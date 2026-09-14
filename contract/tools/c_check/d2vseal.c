#include "d2vseal.h"

#include <string.h>

#include "monocypher.h"

static const uint8_t magic[8] = {'D', '2', 'V', 'S', 'E', 'A', 'L', '1'};

static void store32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static void store64_le(uint8_t *out, uint64_t value)
{
    store32_le(out, (uint32_t)value);
    store32_le(out + 4, (uint32_t)(value >> 32));
}

static uint32_t load32_le(const uint8_t *in)
{
    return (uint32_t)in[0] | (uint32_t)in[1] << 8 | (uint32_t)in[2] << 16 | (uint32_t)in[3] << 24;
}

size_t d2vseal_sealed_size(size_t plaintext_size, uint32_t chunk_size)
{
    return D2VSEAL_HEADER_SIZE + plaintext_size + D2VSEAL_TAG_SIZE * (plaintext_size / chunk_size + 1);
}

void d2vseal_key_id(uint8_t key_id[8], const uint8_t recipient_pk[32])
{
    uint8_t hash[32];
    crypto_blake2b(hash, sizeof hash, recipient_pk, 32);
    memcpy(key_id, hash, 8);
}

void d2vseal_derive_key(uint8_t key[32], const uint8_t shared[32], const uint8_t eph_pk[32],
                        const uint8_t recipient_pk[32])
{
    uint8_t input[8 + 3 * 32];
    memcpy(input, magic, 8);
    memcpy(input + 8, shared, 32);
    memcpy(input + 40, eph_pk, 32);
    memcpy(input + 72, recipient_pk, 32);
    crypto_blake2b(key, 32, input, sizeof input);
    crypto_wipe(input, sizeof input);
}

int d2vseal_seal(uint8_t *sealed, const uint8_t *plaintext, size_t plaintext_size,
                 const uint8_t recipient_pk[32], const uint8_t eph_sk[32],
                 const uint8_t nonce_prefix[16], uint32_t chunk_size)
{
    static const uint8_t nothing[1] = {0};
    uint8_t eph_pk[32], shared[32], key[32], nonce[24], ad[D2VSEAL_HEADER_SIZE + 1];
    uint8_t *write = sealed + D2VSEAL_HEADER_SIZE;
    size_t chunks, index, offset = 0;

    if (chunk_size < 1 || chunk_size > D2VSEAL_MAX_CHUNK_SIZE)
        return -1;
    if (!plaintext)
        plaintext = nothing; /* only valid with plaintext_size == 0 */

    crypto_x25519_public_key(eph_pk, eph_sk);
    crypto_x25519(shared, eph_sk, recipient_pk);
    d2vseal_derive_key(key, shared, eph_pk, recipient_pk);

    memcpy(sealed, magic, 8);
    d2vseal_key_id(sealed + 8, recipient_pk);
    memcpy(sealed + 16, eph_pk, 32);
    memcpy(sealed + 48, nonce_prefix, D2VSEAL_NONCE_PREFIX_SIZE);
    store32_le(sealed + 64, chunk_size);
    memset(sealed + 68, 0, 4);

    memcpy(ad, sealed, D2VSEAL_HEADER_SIZE);
    memcpy(nonce, nonce_prefix, D2VSEAL_NONCE_PREFIX_SIZE);
    chunks = plaintext_size / chunk_size + 1;
    for (index = 0; index < chunks; index++) {
        int last = index + 1 == chunks;
        size_t size = last ? plaintext_size - offset : chunk_size;
        ad[D2VSEAL_HEADER_SIZE] = (uint8_t)last;
        store64_le(nonce + D2VSEAL_NONCE_PREFIX_SIZE, (uint64_t)index);
        /* Monocypher writes the tag separately: store it right after the ciphertext. */
        crypto_aead_lock(write, write + size, key, nonce, ad, sizeof ad, plaintext + offset, size);
        write += size + D2VSEAL_TAG_SIZE;
        offset += size;
    }

    crypto_wipe(shared, sizeof shared);
    crypto_wipe(key, sizeof key);
    return 0;
}

d2vseal_result d2vseal_open(uint8_t *plaintext, size_t *plaintext_size, const uint8_t *sealed,
                            size_t sealed_size, const uint8_t recipient_sk[32])
{
    static const uint8_t zero[32] = {0};
    uint8_t recipient_pk[32], key_id[8], shared[32], key[32], nonce[24], ad[D2VSEAL_HEADER_SIZE + 1];
    const uint8_t *read;
    uint32_t chunk_size;
    size_t body, full, chunks, index, written = 0;
    d2vseal_result result = D2VSEAL_OK;

    *plaintext_size = 0;
    /* 1. */
    if (sealed_size < D2VSEAL_HEADER_SIZE)
        return D2VSEAL_TRUNCATED;
    /* 2. */
    chunk_size = load32_le(sealed + 64);
    if (memcmp(sealed, magic, 8) != 0 || load32_le(sealed + 68) != 0 || chunk_size < 1 ||
        chunk_size > D2VSEAL_MAX_CHUNK_SIZE)
        return D2VSEAL_MALFORMED;
    /* 3. */
    crypto_x25519_public_key(recipient_pk, recipient_sk);
    d2vseal_key_id(key_id, recipient_pk);
    if (memcmp(key_id, sealed + 8, 8) != 0)
        return D2VSEAL_WRONG_KEY;
    /* 4. Monocypher does not refuse an all-zero shared secret by itself. */
    crypto_x25519(shared, recipient_sk, sealed + 16);
    if (crypto_verify32(shared, zero) == 0) {
        crypto_wipe(shared, sizeof shared);
        return D2VSEAL_MALFORMED;
    }
    d2vseal_derive_key(key, shared, sealed + 16, recipient_pk);
    crypto_wipe(shared, sizeof shared);
    /* 5. */
    body = sealed_size - D2VSEAL_HEADER_SIZE;
    full = (size_t)chunk_size + D2VSEAL_TAG_SIZE;
    if (body % full < D2VSEAL_TAG_SIZE) {
        crypto_wipe(key, sizeof key);
        return D2VSEAL_TRUNCATED;
    }
    /* 6. */
    chunks = body / full + 1;
    memcpy(ad, sealed, D2VSEAL_HEADER_SIZE);
    memcpy(nonce, sealed + 48, D2VSEAL_NONCE_PREFIX_SIZE);
    read = sealed + D2VSEAL_HEADER_SIZE;
    for (index = 0; index < chunks; index++) {
        int last = index + 1 == chunks;
        size_t chunk_sealed = last ? body - index * full : full;
        size_t size = chunk_sealed - D2VSEAL_TAG_SIZE;
        ad[D2VSEAL_HEADER_SIZE] = (uint8_t)last;
        store64_le(nonce + D2VSEAL_NONCE_PREFIX_SIZE, (uint64_t)index);
        if (crypto_aead_unlock(plaintext + written, read + size, key, nonce, ad, sizeof ad, read, size) != 0) {
            result = D2VSEAL_TAMPERED;
            break;
        }
        read += chunk_sealed;
        written += size;
    }
    crypto_wipe(key, sizeof key);
    *plaintext_size = result == D2VSEAL_OK ? written : 0;
    return result;
}

const char *d2vseal_result_name(d2vseal_result result)
{
    switch (result) {
    case D2VSEAL_OK: return "ok";
    case D2VSEAL_TRUNCATED: return "truncated";
    case D2VSEAL_MALFORMED: return "malformed";
    case D2VSEAL_WRONG_KEY: return "wrong_key";
    case D2VSEAL_TAMPERED: return "tampered";
    }
    return "unknown";
}
