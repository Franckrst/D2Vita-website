# D2VSEAL1 sealed format

Frozen with contract v1.

Crash report artifacts (dump, logs) travel over plain HTTP and are stored by
the API as opaque bytes. The console seals each artifact for the
maintainer's X25519 public key, embedded in the eboot; only the private key,
which never leaves the maintainer's PC, opens it (design, sections 4.7 and 8).

- Reference implementation: `tools/gen_vectors.py` (`seal`, `open_sealed`,
  PyNaCl). Byte compatibility with Monocypher 4.0.2 is checked by
  `tools/c_check` (`make -C contract/tools/c_check check`).
- Test vectors: `vectors/sealed.v1.json`.

## 1. Primitives

| Primitive | Definition | Monocypher 4 (console) | PyNaCl 1.5 (admin) |
|---|---|---|---|
| X25519 | RFC 7748, scalars clamped by the implementation | `crypto_x25519`, `crypto_x25519_public_key` | `nacl.bindings.crypto_scalarmult`, `crypto_scalarmult_base` |
| BLAKE2b-256 | RFC 7693, unkeyed, 32-byte digest | `crypto_blake2b(hash, 32, msg, len)` | `nacl.hash.blake2b(msg, digest_size=32)` |
| XChaCha20-Poly1305 | IETF construction (`draft-irtf-cfrg-xchacha`), 24-byte nonce, 16-byte tag | `crypto_aead_lock` / `crypto_aead_unlock` (the tag is a separate buffer) | `crypto_aead_xchacha20poly1305_ietf_encrypt` / `_decrypt` (output is ciphertext followed by tag) |

Monocypher writes the tag into its own `mac` buffer: a sealed chunk is the
ciphertext **followed by** that tag, which is exactly what libsodium returns.

## 2. Layout

All integers are little-endian.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 8 | `magic` | ASCII `D2VSEAL1` |
| 8 | 8 | `key_id` | first 8 bytes of BLAKE2b-256(`recipient_pk`) |
| 16 | 32 | `eph_pk` | ephemeral X25519 public key |
| 48 | 16 | `nonce_prefix` | random |
| 64 | 4 | `chunk_size` | u32, 65536 when written by the console; readers accept 1 to 1048576 |
| 68 | 4 | `reserved` | zero |
| 72 | ... | chunks | see section 4 |

The 72 bytes from offset 0 are the **header**.

## 3. Key

```
shared = X25519(eph_sk, recipient_pk)            = X25519(recipient_sk, eph_pk)
key    = BLAKE2b-256("D2VSEAL1" || shared || eph_pk || recipient_pk)
```

The BLAKE2b input is 104 bytes: the 8 ASCII bytes of the magic, then the
three 32-byte values.

## 4. Chunks

With `n` plaintext bytes and `C = chunk_size`:

- the plaintext is cut into `k = floor(n / C) + 1` chunks: `k - 1` full chunks
  of `C` bytes, then a last chunk of `n mod C` bytes. The last chunk is
  **empty** when `n` is a multiple of `C`, including `n = 0`;
- chunk `i` (from 0) is sealed with XChaCha20-Poly1305 IETF using
  - nonce = `nonce_prefix || u64(i)` (24 bytes),
  - associated data = `header || last` (73 bytes), where `last` is one byte:
    `01` for the last chunk, `00` otherwise,
  - output = ciphertext (same length as the chunk) `||` 16-byte tag;
- the sealed chunks follow the header, in order, without separators.

```
sealed_size = 72 + n + 16 * (floor(n / C) + 1)
```

A sealed chunk of exactly `C + 16` bytes is never the last one, and the last
one is 16 to `C + 15` bytes long: the chunk boundaries follow from the total
size. Because the header is authenticated with every chunk, changing any
header byte makes every chunk fail. Because only the last chunk is sealed
with `last = 01`, dropping chunks from the end is detected.

## 5. Writing (console)

- `chunk_size` is 65536.
- Every object gets a fresh ephemeral key pair and a fresh `nonce_prefix`,
  both from the system CSPRNG. Never reuse either: the vectors fix them only
  so that the bytes can be compared.
- Wipe `eph_sk`, `shared` and `key` after use.
- The sealed size is known before sealing (formula above), so the upload can
  send `Content-Length` and seal while streaming, one chunk in memory.

## 6. Opening (admin)

Checks run in this order; the first failure gives the result.

1. Fewer than 72 bytes: `truncated`.
2. `magic` is not `D2VSEAL1`, `reserved` is not zero, or `chunk_size` is not
   in [1, 1048576]: `malformed`.
3. `key_id` is not BLAKE2b-256(`recipient_pk`)[0:8], where `recipient_pk` is
   derived from the private key used to open: `wrong_key`.
4. `shared` is all zero (low-order `eph_pk`): `malformed`. libsodium refuses
   this case by itself; with Monocypher, compare `shared` with zero.
5. With `L` = size after the header and `F = C + 16`: if `L mod F < 16`, the
   object does not end with a last chunk: `truncated`.
6. Otherwise there are `floor(L / F) + 1` chunks; any chunk that fails to
   authenticate (with its index and its `last` flag): `tampered`.

A cut that leaves 16 bytes or more of the last chunk fails authentication and
is reported as `tampered`, not `truncated`. A streaming reader must treat a
stream that ends right after a full `C + 16` byte chunk as `truncated`
(step 5), never try that chunk as the last one. Each negative vector has a
single defect (or only header defects), so every reader that follows this
order reports the expected result.

## 7. Example

Case `one_byte` of `vectors/sealed.v1.json`: one plaintext byte, one chunk,
89 bytes in total.

<!-- example:begin -->
```text
recipient_sk   f3df7dd99a602e5a1c773087d693b04f32cc3301b6f1e3e48e513477cad2cc62
recipient_pk   8cfb8351b95fa55ac7f1e749144ed4021c721306609d908f4a711a6cf997eb7d
eph_sk         1b912d8bc4b60af713cd01eb421c51f916653dec7fdfb5757bd30c8381f19c5d
nonce_prefix   0ab9c83ca593838ef1411dd805aa117f
chunk_size     65536
plaintext      44 ('D')

eph_pk = X25519_base(eph_sk)
  9f5badd0b85c03f16715383ab56313b2461b25197f0fe1242b86bce5ada6b012
shared = X25519(eph_sk, recipient_pk)
  97ba850f9df3129c3982abe83f0a09099bf9f51aa0d776e16afe7d9810596268
key = BLAKE2b-256("D2VSEAL1" || shared || eph_pk || recipient_pk)
  5b3c104b530f52185542ebd01f345a6eab978ce93a86b7e8cdbb016a0cb1b4d7
nonce 0 = nonce_prefix || u64 little-endian 0
  0ab9c83ca593838ef1411dd805aa117f0000000000000000
AD 0 = header (72 bytes) || 01, because chunk 0 is the last chunk

off   bytes                                            field
0000  44 32 56 53 45 41 4c 31                          magic "D2VSEAL1"
0008  0e d2 01 2a 07 ec 55 d2                          key_id = BLAKE2b-256(recipient_pk)[0:8]
0010  9f 5b ad d0 b8 5c 03 f1 67 15 38 3a b5 63 13 b2  eph_pk
0020  46 1b 25 19 7f 0f e1 24 2b 86 bc e5 ad a6 b0 12
0030  0a b9 c8 3c a5 93 83 8e f1 41 1d d8 05 aa 11 7f  nonce_prefix
0040  00 00 01 00                                      chunk_size = 65536, u32 little-endian
0044  00 00 00 00                                      reserved, zero
0048  2d                                               chunk 0: ciphertext (1 byte)
0049  50 70 1c 01 09 70 d7 35 33 9b ee 74 d7 bb 2f 34  chunk 0: Poly1305 tag (16 bytes)
```
<!-- example:end -->

## 8. Vectors

`vectors/sealed.v1.json` has two lists.

- `cases`: `{name, recipient_sk_hex, recipient_pk_hex, eph_sk_hex,
  nonce_prefix_hex, chunk_size, plaintext_hex, eph_pk_hex, shared_hex,
  key_id_hex, key_hex, sealed_hex}`. An implementation must produce
  `sealed_hex` from the inputs and open it back. The intermediate values
  (`eph_pk_hex` to `key_hex`) locate a disagreement. Some secret keys are not
  clamped on purpose.
- `negative_cases`: `{name, base, recipient_sk_hex, sealed_hex, expect}`.
  Opening must fail with `expect`: `truncated`, `malformed`, `wrong_key` or
  `tampered`. `base` names the case the object was derived from (`null` for
  objects written by a deliberately broken sealer).

Response signatures (`X-D2V-Signature`) are not part of this format; see
`README.md` and `vectors/response-sig.v1.json`.
