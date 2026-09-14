import hashlib
import unittest

import nacl.bindings as sodium

import gen_vectors as g

RECIPIENT_SK = hashlib.sha256(b"test-recipient").digest()
RECIPIENT_PK = sodium.crypto_scalarmult_base(RECIPIENT_SK)
OTHER_SK = hashlib.sha256(b"test-other-recipient").digest()
EPH_SK = hashlib.sha256(b"test-ephemeral").digest()
PREFIX = bytes(range(16))


def seal(plaintext, chunk_size=16, eph_sk=EPH_SK):
    return g.seal(plaintext, RECIPIENT_PK, eph_sk, PREFIX, chunk_size)


def body_chunks(sealed, chunk_size):
    body = sealed[g.HEADER_SIZE :]
    full = chunk_size + g.TAG_SIZE
    count = len(body) // full + 1
    return [body[i * full : (i + 1) * full] if i < count - 1 else body[i * full :] for i in range(count)]


class HeaderTest(unittest.TestCase):
    def test_layout(self):
        sealed = seal(b"", chunk_size=65536)
        header = sealed[:72]
        self.assertEqual(b"D2VSEAL1", header[0:8])
        self.assertEqual(hashlib.blake2b(RECIPIENT_PK, digest_size=32).digest()[:8], header[8:16])
        self.assertEqual(sodium.crypto_scalarmult_base(EPH_SK), header[16:48])
        self.assertEqual(PREFIX, header[48:64])
        self.assertEqual(bytes([0x00, 0x00, 0x01, 0x00]), header[64:68])
        self.assertEqual(bytes(4), header[68:72])
        self.assertEqual(g.HEADER_SIZE + g.TAG_SIZE, len(sealed))

    def test_key_and_chunks_rederived_independently(self):
        # BLAKE2b from hashlib (not libsodium), nonce and AD built by hand.
        plaintext = b"0123456789abcdefXYZ"  # chunk_size 16: one full chunk, then 3 bytes
        sealed = seal(plaintext)
        header = sealed[:72]
        shared = sodium.crypto_scalarmult(RECIPIENT_SK, header[16:48])
        key = hashlib.blake2b(b"D2VSEAL1" + shared + header[16:48] + RECIPIENT_PK, digest_size=32).digest()
        chunks = body_chunks(sealed, 16)
        self.assertEqual([32, 19], [len(chunk) for chunk in chunks])
        first = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            chunks[0], header + b"\x00", PREFIX + (0).to_bytes(8, "little"), key)
        last = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            chunks[1], header + b"\x01", PREFIX + (1).to_bytes(8, "little"), key)
        self.assertEqual(plaintext, first + last)


class ChunkingTest(unittest.TestCase):
    def test_sizes_and_chunk_counts(self):
        for size, chunks in ((0, 1), (1, 1), (15, 1), (16, 2), (17, 2), (32, 3), (33, 3), (40, 3)):
            with self.subTest(size=size):
                sealed = seal(bytes(size))
                self.assertEqual(g.sealed_size(size, 16), len(sealed))
                self.assertEqual(72 + size + 16 * chunks, len(sealed))
                self.assertEqual(chunks, len(body_chunks(sealed, 16)))

    def test_exact_multiple_ends_with_an_empty_last_chunk(self):
        sealed = seal(bytes(32))
        self.assertEqual([32, 32, 16], [len(chunk) for chunk in body_chunks(sealed, 16)])

    def test_round_trip(self):
        for size, chunk_size in ((0, 65536), (1, 65536), (16, 16), (17, 16), (40, 16), (3, 1),
                                 (70000, 65536)):
            with self.subTest(size=size, chunk_size=chunk_size):
                plaintext = g.pattern(size)
                self.assertEqual(plaintext, g.open_sealed(seal(plaintext, chunk_size), RECIPIENT_SK))

    def test_sealing_is_deterministic_given_the_ephemeral_key_and_prefix(self):
        self.assertEqual(seal(b"abc"), seal(b"abc"))
        self.assertNotEqual(seal(b"abc"), seal(b"abc", eph_sk=hashlib.sha256(b"other").digest()))

    def test_bad_parameters_are_refused_when_sealing(self):
        for chunk_size in (0, g.MAX_CHUNK_SIZE + 1):
            with self.subTest(chunk_size=chunk_size):
                with self.assertRaises(ValueError):
                    seal(b"x", chunk_size=chunk_size)
        with self.assertRaises(ValueError):
            g.seal(b"x", RECIPIENT_PK, EPH_SK, PREFIX[:15], 16)


class OpenErrorsTest(unittest.TestCase):
    def assertOpenFails(self, sealed, expected, sk=RECIPIENT_SK):
        with self.assertRaises(g.OpenError) as caught:
            g.open_sealed(sealed, sk)
        self.assertEqual(expected, caught.exception.kind)

    def test_truncated(self):
        self.assertOpenFails(seal(b"x")[:40], "truncated")
        self.assertOpenFails(seal(b"x")[:72], "truncated")
        self.assertOpenFails(seal(bytes(16))[:-16], "truncated")  # empty last chunk removed
        self.assertOpenFails(seal(bytes(17))[:-17], "truncated")  # last chunk removed
        self.assertOpenFails(seal(bytes(16))[:-1], "truncated")  # 15 bytes left of the last chunk

    def test_a_cut_leaving_16_bytes_or_more_of_the_last_chunk_is_tampered(self):
        self.assertOpenFails(seal(bytes(40))[:-1], "tampered")

    def test_malformed(self):
        sealed = bytearray(seal(b"x"))
        cases = {
            "magic": lambda b: b.__setitem__(7, ord("2")),
            "reserved": lambda b: b.__setitem__(71, 1),
            "chunk size zero": lambda b: b.__setitem__(slice(64, 68), (0).to_bytes(4, "little")),
            "chunk size too large": lambda b: b.__setitem__(slice(64, 68), (g.MAX_CHUNK_SIZE + 1).to_bytes(4, "little")),
            "low order ephemeral key": lambda b: b.__setitem__(slice(16, 48), bytes(32)),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                copy = bytearray(sealed)
                mutate(copy)
                self.assertOpenFails(bytes(copy), "malformed")

    def test_wrong_key(self):
        self.assertOpenFails(seal(b"x"), "wrong_key", sk=OTHER_SK)

    def test_header_problems_take_precedence(self):
        copy = bytearray(seal(b"x"))
        copy[0] = ord("X")
        self.assertOpenFails(bytes(copy), "malformed", sk=OTHER_SK)
        self.assertOpenFails(seal(bytes(16))[:-16], "wrong_key", sk=OTHER_SK)

    def test_tampered(self):
        sealed = seal(bytes(40))
        full = 32
        cases = {
            "ciphertext bit": lambda b: b.__setitem__(72, b[72] ^ 1),
            "last tag byte": lambda b: b.__setitem__(len(b) - 1, b[-1] ^ 0x80),
            "nonce prefix": lambda b: b.__setitem__(48, b[48] ^ 1),
            "ephemeral key": lambda b: b.__setitem__(20, b[20] ^ 1),
            "chunks swapped": lambda b: b.__setitem__(slice(72, 72 + 2 * full),
                                                      bytes(b[72 + full:72 + 2 * full]) + bytes(b[72:72 + full])),
            "extra byte": lambda b: b.append(0),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                copy = bytearray(sealed)
                mutate(copy)
                self.assertOpenFails(bytes(copy), "tampered")

    def test_writer_bugs_are_rejected(self):
        # A writer that omits the empty last chunk of an exact multiple.
        no_empty_last = g.seal_with_flags(bytes(16), RECIPIENT_PK, EPH_SK, PREFIX, 16, chunk_lengths=[16],
                                          last_flags=[1])
        self.assertOpenFails(no_empty_last, "truncated")
        # A writer that never sets the last flag.
        never_last = g.seal_with_flags(bytes(17), RECIPIENT_PK, EPH_SK, PREFIX, 16, chunk_lengths=[16, 1],
                                       last_flags=[0, 0])
        self.assertOpenFails(never_last, "tampered")
        # The same helper with the normal flags produces the normal output.
        self.assertEqual(seal(bytes(17)),
                         g.seal_with_flags(bytes(17), RECIPIENT_PK, EPH_SK, PREFIX, 16, chunk_lengths=[16, 1],
                                           last_flags=[0, 1]))
