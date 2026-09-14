/* D2VSEAL1 sealing and opening with Monocypher 4 (contract/sealed-format.md).
 * Whole buffers in memory: this is the byte-compatibility reference used by
 * check_sealed.c, not the console's streaming implementation.
 */
#ifndef D2VSEAL_H
#define D2VSEAL_H

#include <stddef.h>
#include <stdint.h>

#define D2VSEAL_HEADER_SIZE 72
#define D2VSEAL_TAG_SIZE 16
#define D2VSEAL_NONCE_PREFIX_SIZE 16
#define D2VSEAL_CHUNK_SIZE 65536u
#define D2VSEAL_MAX_CHUNK_SIZE 1048576u

typedef enum {
    D2VSEAL_OK = 0,
    D2VSEAL_TRUNCATED,
    D2VSEAL_MALFORMED,
    D2VSEAL_WRONG_KEY,
    D2VSEAL_TAMPERED
} d2vseal_result;

/* 72 + n + 16 * (n / chunk_size + 1); chunk_size must be at least 1. */
size_t d2vseal_sealed_size(size_t plaintext_size, uint32_t chunk_size);

/* BLAKE2b-256(recipient_pk)[0:8] */
void d2vseal_key_id(uint8_t key_id[8], const uint8_t recipient_pk[32]);

/* BLAKE2b-256("D2VSEAL1" || shared || eph_pk || recipient_pk) */
void d2vseal_derive_key(uint8_t key[32], const uint8_t shared[32], const uint8_t eph_pk[32],
                        const uint8_t recipient_pk[32]);

/* Writes d2vseal_sealed_size(plaintext_size, chunk_size) bytes to `sealed`.
 * `plaintext` may be NULL when plaintext_size is 0.
 * Returns 0, or -1 when chunk_size is outside [1, D2VSEAL_MAX_CHUNK_SIZE]. */
int d2vseal_seal(uint8_t *sealed, const uint8_t *plaintext, size_t plaintext_size,
                 const uint8_t recipient_pk[32], const uint8_t eph_sk[32],
                 const uint8_t nonce_prefix[16], uint32_t chunk_size);

/* Opens `sealed` with the recipient secret key. `plaintext` must hold at
 * least sealed_size bytes. Checks run in the order of sealed-format.md. */
d2vseal_result d2vseal_open(uint8_t *plaintext, size_t *plaintext_size, const uint8_t *sealed,
                            size_t sealed_size, const uint8_t recipient_sk[32]);

const char *d2vseal_result_name(d2vseal_result result);

#endif
