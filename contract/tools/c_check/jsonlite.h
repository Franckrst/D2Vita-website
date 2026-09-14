/* Minimal strict JSON reader for the contract vector files (RFC 8259).
 * Test support only: whole document in memory, no streaming.
 */
#ifndef JSONLITE_H
#define JSONLITE_H

#include <stddef.h>

typedef enum {
    JSON_NULL,
    JSON_FALSE,
    JSON_TRUE,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct json_value json_value;
struct json_value {
    json_type type;
    double number;      /* JSON_NUMBER */
    char *string;       /* JSON_STRING: decoded UTF-8 bytes, NUL-terminated */
    size_t length;      /* JSON_STRING: byte count; JSON_ARRAY, JSON_OBJECT: element count */
    json_value *items;  /* JSON_ARRAY: elements; JSON_OBJECT: member values */
    char **keys;        /* JSON_OBJECT: member names (decoded, NUL-terminated) */
};

/* Parses `size` bytes. Returns NULL and writes a message into `error` on
 * failure: bad syntax, invalid escape or surrogate, raw control character,
 * duplicate member name, nesting deeper than 64, trailing data. */
json_value *json_parse(const char *text, size_t size, char *error, size_t error_size);
void json_free(json_value *value);

/* Member of an object, or NULL. */
const json_value *json_get(const json_value *object, const char *key);

#endif
