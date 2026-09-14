/* check_sealed: Monocypher 4.0.2 against the contract vectors.
 *
 *   make -C contract/tools/c_check check
 *   ./check_sealed <vector directory>
 *
 * sealed.v1.json: for each case, checks every intermediate value, reproduces
 * sealed_hex from the inputs, opens it back, then checks that a flipped byte
 * no longer opens (so the comparison is able to fail). Each negative case
 * must fail with its expected result.
 *
 * response-sig.v1.json: for each case, derives the public key from the seed,
 * reproduces the signature (Ed25519 is deterministic), verifies it with
 * crypto_ed25519_check, then checks that a changed body or signature is
 * rejected. Each negative case must be rejected.
 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2vseal.h"
#include "jsonlite.h"
#include "monocypher-ed25519.h"
#include "monocypher.h"

#define MIN_SEALED_CASES 6
#define MIN_NEGATIVE_CASES 3
#define MIN_SIGNATURE_CASES 3

static int failures;

#define FAIL(...)                              \
    do {                                       \
        failures++;                            \
        fprintf(stderr, "FAIL: ");             \
        fprintf(stderr, __VA_ARGS__);          \
        fputc('\n', stderr);                   \
    } while (0)

/* ------------------------------------------------------------------------ */
/* Files, hex, base64                                                       */
/* ------------------------------------------------------------------------ */

static char *read_file(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    char *data = NULL;
    size_t used = 0, capacity = 0;
    if (!file)
        return NULL;
    for (;;) {
        size_t got;
        if (capacity - used < 65536) {
            size_t grown_capacity = capacity ? capacity * 2 : 262144;
            char *grown = realloc(data, grown_capacity + 1);
            if (!grown) {
                free(data);
                fclose(file);
                return NULL;
            }
            data = grown;
            capacity = grown_capacity;
        }
        got = fread(data + used, 1, capacity - used, file);
        used += got;
        if (got == 0)
            break;
    }
    if (ferror(file)) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    data[used] = '\0';
    *size = used;
    return data;
}

static int hex_digit(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

/* Lowercase hex to a new buffer (never NULL on success, even when empty). */
static uint8_t *hex_decode(const char *hex, size_t hex_size, size_t *size)
{
    uint8_t *out;
    size_t i;
    if (hex_size % 2)
        return NULL;
    out = malloc(hex_size / 2 + 1);
    if (!out)
        return NULL;
    for (i = 0; i < hex_size / 2; i++) {
        int high = hex_digit((unsigned char)hex[2 * i]);
        int low = hex_digit((unsigned char)hex[2 * i + 1]);
        if (high < 0 || low < 0) {
            free(out);
            return NULL;
        }
        out[i] = (uint8_t)(high << 4 | low);
    }
    *size = hex_size / 2;
    return out;
}

static int base64_digit(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* Strict RFC 4648 base64 with padding. Returns the decoded size or -1. */
static long base64_decode(uint8_t *out, size_t capacity, const char *text, size_t size)
{
    size_t i, written = 0;
    if (size % 4)
        return -1;
    for (i = 0; i < size; i += 4) {
        int digits[4], padding = 0, j;
        unsigned long group;
        for (j = 0; j < 4; j++) {
            char c = text[i + j];
            if (c == '=') {
                if (i + 4 != size || j < 2)
                    return -1;
                digits[j] = 0;
                padding++;
            } else {
                if (padding)
                    return -1;
                digits[j] = base64_digit((unsigned char)c);
                if (digits[j] < 0)
                    return -1;
            }
        }
        if ((padding == 1 && (digits[2] & 0x03)) || (padding == 2 && (digits[1] & 0x0f)))
            return -1; /* non-zero bits under the padding */
        if (written + (size_t)(3 - padding) > capacity)
            return -1;
        group = (unsigned long)digits[0] << 18 | (unsigned long)digits[1] << 12 |
                (unsigned long)digits[2] << 6 | (unsigned long)digits[3];
        out[written++] = (uint8_t)(group >> 16);
        if (padding < 2)
            out[written++] = (uint8_t)(group >> 8);
        if (padding < 1)
            out[written++] = (uint8_t)group;
    }
    return (long)written;
}

static size_t first_difference(const uint8_t *a, const uint8_t *b, size_t size)
{
    size_t i;
    for (i = 0; i < size && a[i] == b[i]; i++)
        ;
    return i;
}

/* ------------------------------------------------------------------------ */
/* Vector fields                                                            */
/* ------------------------------------------------------------------------ */

static const json_value *field(const json_value *object, const char *key, json_type type,
                               const char *where)
{
    const json_value *value = json_get(object, key);
    if (!value || value->type != type) {
        FAIL("%s: field %s is missing or has the wrong type", where, key);
        return NULL;
    }
    return value;
}

/* Hex field decoded to a new buffer; expected_size 0 accepts any size. */
static uint8_t *hex_field(const json_value *object, const char *key, size_t expected_size,
                         size_t *size, const char *where)
{
    const json_value *value = field(object, key, JSON_STRING, where);
    uint8_t *bytes;
    if (!value)
        return NULL;
    bytes = hex_decode(value->string, value->length, size);
    if (!bytes) {
        FAIL("%s: field %s is not lowercase hex", where, key);
        return NULL;
    }
    if (expected_size && *size != expected_size) {
        FAIL("%s: field %s has %zu bytes, expected %zu", where, key, *size, expected_size);
        free(bytes);
        return NULL;
    }
    return bytes;
}

static int result_from_name(const char *name, d2vseal_result *result)
{
    static const struct {
        const char *name;
        d2vseal_result result;
    } names[] = {{"truncated", D2VSEAL_TRUNCATED},
                 {"malformed", D2VSEAL_MALFORMED},
                 {"wrong_key", D2VSEAL_WRONG_KEY},
                 {"tampered", D2VSEAL_TAMPERED}};
    size_t i;
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (strcmp(name, names[i].name) == 0) {
            *result = names[i].result;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Sealed vectors                                                           */
/* ------------------------------------------------------------------------ */

static void check_sealed_case(const json_value *vector)
{
    const json_value *name = field(vector, "name", JSON_STRING, "sealed case");
    const char *where = name ? name->string : "sealed case";
    size_t sk_size = 0, pk_size = 0, eph_sk_size = 0, prefix_size = 0, plaintext_size = 0;
    size_t eph_pk_size = 0, shared_size = 0, key_id_size = 0, key_size = 0, sealed_size = 0;
    uint8_t *sk = hex_field(vector, "recipient_sk_hex", 32, &sk_size, where);
    uint8_t *pk = hex_field(vector, "recipient_pk_hex", 32, &pk_size, where);
    uint8_t *eph_sk = hex_field(vector, "eph_sk_hex", 32, &eph_sk_size, where);
    uint8_t *prefix = hex_field(vector, "nonce_prefix_hex", 16, &prefix_size, where);
    uint8_t *plaintext = hex_field(vector, "plaintext_hex", 0, &plaintext_size, where);
    uint8_t *eph_pk = hex_field(vector, "eph_pk_hex", 32, &eph_pk_size, where);
    uint8_t *shared = hex_field(vector, "shared_hex", 32, &shared_size, where);
    uint8_t *key_id = hex_field(vector, "key_id_hex", 8, &key_id_size, where);
    uint8_t *key = hex_field(vector, "key_hex", 32, &key_size, where);
    uint8_t *sealed = hex_field(vector, "sealed_hex", 0, &sealed_size, where);
    const json_value *chunk = field(vector, "chunk_size", JSON_NUMBER, where);
    uint8_t *output = NULL, *opened = NULL;
    uint8_t value[32], id[8];
    uint32_t chunk_size;
    size_t expected_size, opened_size = 0;
    d2vseal_result result;

    if (!sk || !pk || !eph_sk || !prefix || !plaintext || !eph_pk || !shared || !key_id || !key ||
        !sealed || !chunk)
        goto done;
    if (chunk->number != floor(chunk->number) || chunk->number < 1 ||
        chunk->number > D2VSEAL_MAX_CHUNK_SIZE) {
        FAIL("%s: chunk_size out of range", where);
        goto done;
    }
    chunk_size = (uint32_t)chunk->number;

    crypto_x25519_public_key(value, sk);
    if (memcmp(value, pk, 32) != 0)
        FAIL("%s: recipient_pk is not X25519_base(recipient_sk)", where);
    crypto_x25519_public_key(value, eph_sk);
    if (memcmp(value, eph_pk, 32) != 0)
        FAIL("%s: eph_pk is not X25519_base(eph_sk)", where);
    crypto_x25519(value, eph_sk, pk);
    if (memcmp(value, shared, 32) != 0)
        FAIL("%s: X25519(eph_sk, recipient_pk) differs from shared", where);
    crypto_x25519(value, sk, eph_pk);
    if (memcmp(value, shared, 32) != 0)
        FAIL("%s: X25519(recipient_sk, eph_pk) differs from shared", where);
    d2vseal_derive_key(value, shared, eph_pk, pk);
    if (memcmp(value, key, 32) != 0)
        FAIL("%s: derived key differs", where);
    d2vseal_key_id(id, pk);
    if (memcmp(id, key_id, 8) != 0)
        FAIL("%s: key_id differs", where);

    expected_size = d2vseal_sealed_size(plaintext_size, chunk_size);
    if (expected_size != sealed_size)
        FAIL("%s: sealed size formula gives %zu, vector has %zu bytes", where, expected_size, sealed_size);
    output = malloc(expected_size + 1);
    opened = malloc(sealed_size + 1);
    if (!output || !opened) {
        FAIL("%s: out of memory", where);
        goto done;
    }
    if (d2vseal_seal(output, plaintext, plaintext_size, pk, eph_sk, prefix, chunk_size) != 0)
        FAIL("%s: sealing failed", where);
    else if (expected_size == sealed_size && memcmp(output, sealed, sealed_size) != 0)
        FAIL("%s: sealed bytes differ from the vector at offset %zu", where,
             first_difference(output, sealed, sealed_size));

    result = d2vseal_open(opened, &opened_size, sealed, sealed_size, sk);
    if (result != D2VSEAL_OK)
        FAIL("%s: opening the vector gives %s", where, d2vseal_result_name(result));
    else if (opened_size != plaintext_size || memcmp(opened, plaintext, plaintext_size) != 0)
        FAIL("%s: opened plaintext differs", where);

    sealed[sealed_size / 2] ^= 0x01;
    result = d2vseal_open(opened, &opened_size, sealed, sealed_size, sk);
    if (result == D2VSEAL_OK)
        FAIL("%s: still opens after flipping byte %zu", where, sealed_size / 2);

done:
    free(sk);
    free(pk);
    free(eph_sk);
    free(prefix);
    free(plaintext);
    free(eph_pk);
    free(shared);
    free(key_id);
    free(key);
    free(sealed);
    free(output);
    free(opened);
}

static void check_negative_sealed_case(const json_value *vector)
{
    const json_value *name = field(vector, "name", JSON_STRING, "negative sealed case");
    const char *where = name ? name->string : "negative sealed case";
    const json_value *expect = field(vector, "expect", JSON_STRING, where);
    size_t sk_size = 0, sealed_size = 0, opened_size = 0;
    uint8_t *sk = hex_field(vector, "recipient_sk_hex", 32, &sk_size, where);
    uint8_t *sealed = hex_field(vector, "sealed_hex", 0, &sealed_size, where);
    uint8_t *opened = NULL;
    d2vseal_result expected, result;

    if (!expect || !sk || !sealed)
        goto done;
    if (!result_from_name(expect->string, &expected)) {
        FAIL("%s: unknown expected result %s", where, expect->string);
        goto done;
    }
    opened = malloc(sealed_size + 1);
    if (!opened) {
        FAIL("%s: out of memory", where);
        goto done;
    }
    result = d2vseal_open(opened, &opened_size, sealed, sealed_size, sk);
    if (result != expected)
        FAIL("%s: opening gives %s, expected %s", where, d2vseal_result_name(result), expect->string);
done:
    free(sk);
    free(sealed);
    free(opened);
}

/* ------------------------------------------------------------------------ */
/* Response signature vectors                                               */
/* ------------------------------------------------------------------------ */

static int decode_signature(const json_value *vector, uint8_t signature[64], const char *where)
{
    const json_value *text = field(vector, "signature_b64", JSON_STRING, where);
    if (!text)
        return 0;
    if (base64_decode(signature, 64, text->string, text->length) != 64) {
        FAIL("%s: signature_b64 is not the base64 of 64 bytes", where);
        return 0;
    }
    return 1;
}

static void check_signature_case(const json_value *vector)
{
    const json_value *name = field(vector, "name", JSON_STRING, "signature case");
    const char *where = name ? name->string : "signature case";
    const json_value *body = field(vector, "body_utf8", JSON_STRING, where);
    size_t seed_size = 0, pk_size = 0;
    uint8_t *seed = hex_field(vector, "seed_hex", 32, &seed_size, where);
    uint8_t *pk = hex_field(vector, "public_key_hex", 32, &pk_size, where);
    uint8_t signature[64], produced[64], secret[64], derived[32], seed_copy[32];
    const uint8_t *message;

    if (!body || !seed || !pk || !decode_signature(vector, signature, where))
        goto done;
    message = (const uint8_t *)body->string;
    memcpy(seed_copy, seed, 32);
    crypto_ed25519_key_pair(secret, derived, seed_copy); /* wipes seed_copy */
    if (memcmp(derived, pk, 32) != 0)
        FAIL("%s: public key derived from the seed differs", where);
    crypto_ed25519_sign(produced, secret, message, body->length);
    crypto_wipe(secret, sizeof secret);
    if (memcmp(produced, signature, 64) != 0)
        FAIL("%s: crypto_ed25519_sign gives another signature", where);
    if (crypto_ed25519_check(signature, pk, message, body->length) != 0)
        FAIL("%s: crypto_ed25519_check rejects the vector", where);

    if (body->length > 0) {
        body->string[0] ^= 0x01;
        if (crypto_ed25519_check(signature, pk, message, body->length) == 0)
            FAIL("%s: still verifies with a changed body", where);
        body->string[0] ^= 0x01;
    }
    signature[63] ^= 0x01;
    if (crypto_ed25519_check(signature, pk, message, body->length) == 0)
        FAIL("%s: still verifies with a changed signature", where);
done:
    free(seed);
    free(pk);
}

static void check_negative_signature_case(const json_value *vector)
{
    const json_value *name = field(vector, "name", JSON_STRING, "negative signature case");
    const char *where = name ? name->string : "negative signature case";
    const json_value *body = field(vector, "body_utf8", JSON_STRING, where);
    const json_value *expect = field(vector, "expect", JSON_STRING, where);
    size_t pk_size = 0;
    uint8_t *pk = hex_field(vector, "public_key_hex", 32, &pk_size, where);
    uint8_t signature[64];

    if (!body || !expect || !pk || !decode_signature(vector, signature, where))
        goto done;
    if (strcmp(expect->string, "invalid") != 0)
        FAIL("%s: unknown expected result %s", where, expect->string);
    else if (crypto_ed25519_check(signature, pk, (const uint8_t *)body->string, body->length) == 0)
        FAIL("%s: crypto_ed25519_check accepts it", where);
done:
    free(pk);
}

/* ------------------------------------------------------------------------ */
/* Self-tests of the helpers                                                */
/* ------------------------------------------------------------------------ */

static void self_test_json(void)
{
    /* {"a":[1,-2.5e3,true,false,null],"s":"q\"b\\s\/\b\f\n\r\t<e9><1F525><0>z","o":{},"e":[]} */
    static const char good[] =
        "{\"a\":[1,-2.5e3,true,false,null],"
        "\"s\":\"q\\\"b\\\\s\\/\\b\\f\\n\\r\\t\x5cu00e9\x5cud83d\x5cudd25\x5cu0000z\","
        " \"o\" : {} , \"e\":[ ]}\n";
    static const char expected_s[] = "q\"b\\s/\b\f\n\r\t\xc3\xa9\xf0\x9f\x94\xa5" "\0" "z";
    static const char *const bad[] = {
        "", "{", "[1 2]", "{\"a\":1,}", "[1,]", "01", "1.", ".5", "-", "1e", "+1", "\"abc",
        "\"\x5cud83d\"", "\"\x5cudd25\"", "\"\x5cud83d\x5cu0041\"", "\"\x5cx41\"", "\"\x5cu12G4\"",
        "\"a\x01" "b\"", "{\"a\":1,\"a\":2}", "1 x", "[] []", "tru", "nul", "{1:2}", "{\"a\" 1}",
    };
    char error[160], deep[200];
    json_value *root = json_parse(good, sizeof good - 1, error, sizeof error);
    const json_value *a, *s;
    size_t i;

    if (!root) {
        FAIL("jsonlite: valid document rejected: %s", error);
    } else {
        a = json_get(root, "a");
        s = json_get(root, "s");
        if (root->type != JSON_OBJECT || root->length != 4 || !a || a->type != JSON_ARRAY ||
            a->length != 5 || a->items[0].type != JSON_NUMBER || a->items[0].number != 1 ||
            a->items[1].number != -2500 || a->items[2].type != JSON_TRUE ||
            a->items[3].type != JSON_FALSE || a->items[4].type != JSON_NULL)
            FAIL("jsonlite: array or number decoded wrongly");
        if (!s || s->type != JSON_STRING || s->length != sizeof expected_s - 1 ||
            memcmp(s->string, expected_s, s->length) != 0)
            FAIL("jsonlite: string escapes decoded wrongly");
        if (!json_get(root, "o") || json_get(root, "o")->type != JSON_OBJECT ||
            !json_get(root, "e") || json_get(root, "e")->length != 0 || json_get(root, "zz"))
            FAIL("jsonlite: object lookup is wrong");
        json_free(root);
    }
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        root = json_parse(bad[i], strlen(bad[i]), error, sizeof error);
        if (root) {
            FAIL("jsonlite: invalid document %zu accepted", i);
            json_free(root);
        }
    }
    memset(deep, '[', 65);
    memset(deep + 65, ']', 65);
    root = json_parse(deep, 130, error, sizeof error);
    if (root) {
        FAIL("jsonlite: nesting deeper than 64 accepted");
        json_free(root);
    }
    root = json_parse(deep + 1, 128, error, sizeof error);
    if (!root)
        FAIL("jsonlite: nesting of 64 rejected: %s", error);
    json_free(root);
}

static void self_test_encodings(void)
{
    uint8_t out[8];
    size_t size = 0;
    uint8_t *bytes;
    if (base64_decode(out, sizeof out, "TWFu", 4) != 3 || memcmp(out, "Man", 3) != 0 ||
        base64_decode(out, sizeof out, "TWE=", 4) != 2 || base64_decode(out, sizeof out, "TQ==", 4) != 1 ||
        base64_decode(out, sizeof out, "", 0) != 0)
        FAIL("base64: valid input decoded wrongly");
    if (base64_decode(out, sizeof out, "TQ=", 3) != -1 || base64_decode(out, sizeof out, "T===", 4) != -1 ||
        base64_decode(out, sizeof out, "TQ=a", 4) != -1 || base64_decode(out, sizeof out, "TR==", 4) != -1 ||
        base64_decode(out, 2, "TWFu", 4) != -1)
        FAIL("base64: invalid input accepted");
    bytes = hex_decode("00ff10", 6, &size);
    if (!bytes || size != 3 || bytes[0] != 0 || bytes[1] != 0xff || bytes[2] != 0x10)
        FAIL("hex: valid input decoded wrongly");
    free(bytes);
    bytes = hex_decode("0G", 2, &size);
    if (bytes)
        FAIL("hex: invalid input accepted");
    free(bytes);
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

static json_value *load(const char *directory, const char *name)
{
    char path[1024], error[160];
    size_t size = 0;
    char *text;
    json_value *root;
    snprintf(path, sizeof path, "%s/%s", directory, name);
    text = read_file(path, &size);
    if (!text) {
        FAIL("cannot read %s", path);
        return NULL;
    }
    root = json_parse(text, size, error, sizeof error);
    free(text);
    if (!root || root->type != JSON_OBJECT) {
        FAIL("%s: %s", path, root ? "not a JSON object" : error);
        json_free(root);
        return NULL;
    }
    return root;
}

static size_t run_list(const json_value *root, const char *list, const char *file, size_t minimum,
                       void (*check)(const json_value *))
{
    const json_value *cases = root ? json_get(root, list) : NULL;
    size_t i;
    if (!cases || cases->type != JSON_ARRAY) {
        FAIL("%s: no %s array", file, list);
        return 0;
    }
    for (i = 0; i < cases->length; i++)
        check(&cases->items[i]);
    if (cases->length < minimum)
        FAIL("%s: %zu %s, at least %zu expected", file, cases->length, list, minimum);
    return cases->length;
}

int main(int argc, char **argv)
{
    const char *directory = argc > 1 ? argv[1] : "../../vectors";
    json_value *sealed, *signatures;
    size_t sealed_cases = 0, sealed_negative = 0, signature_cases = 0, signature_negative = 0;

    self_test_json();
    self_test_encodings();
    if (failures) {
        fprintf(stderr, "FAILED: helper self-tests (%d problems)\n", failures);
        return 1;
    }

    sealed = load(directory, "sealed.v1.json");
    if (sealed) {
        sealed_cases = run_list(sealed, "cases", "sealed.v1.json", MIN_SEALED_CASES, check_sealed_case);
        sealed_negative = run_list(sealed, "negative_cases", "sealed.v1.json", MIN_NEGATIVE_CASES,
                                   check_negative_sealed_case);
    }
    signatures = load(directory, "response-sig.v1.json");
    if (signatures) {
        signature_cases = run_list(signatures, "cases", "response-sig.v1.json", MIN_SIGNATURE_CASES,
                                   check_signature_case);
        signature_negative = run_list(signatures, "negative_cases", "response-sig.v1.json",
                                      MIN_NEGATIVE_CASES, check_negative_signature_case);
    }
    json_free(sealed);
    json_free(signatures);

    if (failures) {
        fprintf(stderr, "FAILED: %d problems\n", failures);
        return 1;
    }
    printf("OK: %zu sealed cases, %zu negative sealed cases, %zu signature cases, "
           "%zu negative signature cases (Monocypher 4.0.2)\n",
           sealed_cases, sealed_negative, signature_cases, signature_negative);
    return 0;
}
