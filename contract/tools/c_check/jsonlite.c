#include "jsonlite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 64

typedef struct {
    const char *start;
    const char *cursor;
    const char *end;
    char *error;
    size_t error_size;
    int depth;
} parser;

static int fail(parser *state, const char *message)
{
    if (state->error && state->error_size && !state->error[0])
        snprintf(state->error, state->error_size, "%s at byte %ld", message,
                 (long)(state->cursor - state->start));
    return 0;
}

static void skip_space(parser *state)
{
    while (state->cursor < state->end &&
           (*state->cursor == ' ' || *state->cursor == '\t' || *state->cursor == '\n' ||
            *state->cursor == '\r'))
        state->cursor++;
}

static int literal(parser *state, const char *word)
{
    size_t size = strlen(word);
    if ((size_t)(state->end - state->cursor) < size || memcmp(state->cursor, word, size) != 0)
        return fail(state, "invalid literal");
    state->cursor += size;
    return 1;
}

static int hex4(const char *text, unsigned *value)
{
    int i;
    *value = 0;
    for (i = 0; i < 4; i++) {
        char c = text[i];
        *value <<= 4;
        if (c >= '0' && c <= '9')
            *value |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            *value |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            *value |= (unsigned)(c - 'A' + 10);
        else
            return 0;
    }
    return 1;
}

static size_t utf8_encode(char *out, unsigned code_point)
{
    if (code_point < 0x80) {
        out[0] = (char)code_point;
        return 1;
    }
    if (code_point < 0x800) {
        out[0] = (char)(0xc0 | code_point >> 6);
        out[1] = (char)(0x80 | (code_point & 0x3f));
        return 2;
    }
    if (code_point < 0x10000) {
        out[0] = (char)(0xe0 | code_point >> 12);
        out[1] = (char)(0x80 | (code_point >> 6 & 0x3f));
        out[2] = (char)(0x80 | (code_point & 0x3f));
        return 3;
    }
    out[0] = (char)(0xf0 | code_point >> 18);
    out[1] = (char)(0x80 | (code_point >> 12 & 0x3f));
    out[2] = (char)(0x80 | (code_point >> 6 & 0x3f));
    out[3] = (char)(0x80 | (code_point & 0x3f));
    return 4;
}

/* The cursor is on the opening quote. Decoded text never grows, so the output
 * buffer is sized from the raw span. */
static int parse_string(parser *state, char **out, size_t *out_size)
{
    const char *scan = state->cursor + 1;
    char *buffer, *write;
    while (scan < state->end && *scan != '"') {
        if ((unsigned char)*scan < 0x20)
            return fail(state, "raw control character in string");
        scan += (*scan == '\\') ? 2 : 1;
    }
    if (scan >= state->end)
        return fail(state, "unterminated string");
    buffer = malloc((size_t)(scan - state->cursor));
    if (!buffer)
        return fail(state, "out of memory");
    write = buffer;
    state->cursor++;
    while (state->cursor < scan) {
        char c = *state->cursor++;
        unsigned code_point, low;
        if (c != '\\') {
            *write++ = c;
            continue;
        }
        c = *state->cursor++;
        switch (c) {
        case '"': *write++ = '"'; break;
        case '\\': *write++ = '\\'; break;
        case '/': *write++ = '/'; break;
        case 'b': *write++ = '\b'; break;
        case 'f': *write++ = '\f'; break;
        case 'n': *write++ = '\n'; break;
        case 'r': *write++ = '\r'; break;
        case 't': *write++ = '\t'; break;
        case 'u':
            if (scan - state->cursor < 4 || !hex4(state->cursor, &code_point)) {
                free(buffer);
                return fail(state, "invalid \\u escape");
            }
            state->cursor += 4;
            if (code_point >= 0xdc00 && code_point <= 0xdfff) {
                free(buffer);
                return fail(state, "unpaired low surrogate");
            }
            if (code_point >= 0xd800 && code_point <= 0xdbff) {
                if (scan - state->cursor < 6 || state->cursor[0] != '\\' || state->cursor[1] != 'u' ||
                    !hex4(state->cursor + 2, &low) || low < 0xdc00 || low > 0xdfff) {
                    free(buffer);
                    return fail(state, "unpaired high surrogate");
                }
                state->cursor += 6;
                code_point = 0x10000 + ((code_point - 0xd800) << 10) + (low - 0xdc00);
            }
            write += utf8_encode(write, code_point);
            break;
        default:
            free(buffer);
            return fail(state, "invalid escape");
        }
    }
    state->cursor = scan + 1;
    *write = '\0';
    *out = buffer;
    *out_size = (size_t)(write - buffer);
    return 1;
}

static int parse_number(parser *state, double *value)
{
    const char *p = state->cursor;
    char digits[64];
    if (p < state->end && *p == '-')
        p++;
    if (p >= state->end || *p < '0' || *p > '9')
        return fail(state, "invalid number");
    if (*p == '0')
        p++;
    else
        while (p < state->end && *p >= '0' && *p <= '9')
            p++;
    if (p < state->end && *p == '.') {
        p++;
        if (p >= state->end || *p < '0' || *p > '9')
            return fail(state, "invalid fraction");
        while (p < state->end && *p >= '0' && *p <= '9')
            p++;
    }
    if (p < state->end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < state->end && (*p == '+' || *p == '-'))
            p++;
        if (p >= state->end || *p < '0' || *p > '9')
            return fail(state, "invalid exponent");
        while (p < state->end && *p >= '0' && *p <= '9')
            p++;
    }
    if ((size_t)(p - state->cursor) >= sizeof digits)
        return fail(state, "number too long");
    memcpy(digits, state->cursor, (size_t)(p - state->cursor));
    digits[p - state->cursor] = '\0';
    *value = strtod(digits, NULL);
    state->cursor = p;
    return 1;
}

static int parse_value(parser *state, json_value *value);

static int append(json_value *container, size_t *capacity, json_value **item, char *key)
{
    if (container->length == *capacity) {
        size_t grown_capacity = *capacity ? *capacity * 2 : 8;
        json_value *items = realloc(container->items, grown_capacity * sizeof *items);
        if (!items)
            return 0;
        container->items = items;
        if (container->type == JSON_OBJECT) {
            char **keys = realloc(container->keys, grown_capacity * sizeof *keys);
            if (!keys)
                return 0;
            container->keys = keys;
        }
        *capacity = grown_capacity;
    }
    *item = &container->items[container->length];
    memset(*item, 0, sizeof **item);
    if (container->type == JSON_OBJECT)
        container->keys[container->length] = key;
    container->length++;
    return 1;
}

static int parse_container(parser *state, json_value *value, char close)
{
    size_t capacity = 0;
    value->type = close == ']' ? JSON_ARRAY : JSON_OBJECT;
    if (++state->depth > MAX_DEPTH)
        return fail(state, "nesting too deep");
    state->cursor++;
    skip_space(state);
    if (state->cursor < state->end && *state->cursor == close) {
        state->cursor++;
        state->depth--;
        return 1;
    }
    for (;;) {
        json_value *item;
        char *key = NULL;
        size_t key_size, i;
        skip_space(state);
        if (value->type == JSON_OBJECT) {
            if (state->cursor >= state->end || *state->cursor != '"')
                return fail(state, "expected a member name");
            if (!parse_string(state, &key, &key_size))
                return 0;
            if (strlen(key) != key_size) {
                free(key);
                return fail(state, "NUL in member name");
            }
            for (i = 0; i < value->length; i++) {
                if (strcmp(value->keys[i], key) == 0) {
                    free(key);
                    return fail(state, "duplicate member name");
                }
            }
            skip_space(state);
            if (state->cursor >= state->end || *state->cursor != ':') {
                free(key);
                return fail(state, "expected ':'");
            }
            state->cursor++;
        }
        if (!append(value, &capacity, &item, key)) {
            free(key);
            return fail(state, "out of memory");
        }
        skip_space(state);
        if (!parse_value(state, item))
            return 0;
        skip_space(state);
        if (state->cursor < state->end && *state->cursor == ',') {
            state->cursor++;
            continue;
        }
        if (state->cursor < state->end && *state->cursor == close) {
            state->cursor++;
            state->depth--;
            return 1;
        }
        return fail(state, "expected ',' or the end of the container");
    }
}

static int parse_value(parser *state, json_value *value)
{
    if (state->cursor >= state->end)
        return fail(state, "unexpected end of input");
    switch (*state->cursor) {
    case '{':
        return parse_container(state, value, '}');
    case '[':
        return parse_container(state, value, ']');
    case '"':
        value->type = JSON_STRING;
        return parse_string(state, &value->string, &value->length);
    case 't':
        value->type = JSON_TRUE;
        return literal(state, "true");
    case 'f':
        value->type = JSON_FALSE;
        return literal(state, "false");
    case 'n':
        value->type = JSON_NULL;
        return literal(state, "null");
    default:
        value->type = JSON_NUMBER;
        return parse_number(state, &value->number);
    }
}

static void release(json_value *value)
{
    size_t i;
    if (value->type == JSON_ARRAY || value->type == JSON_OBJECT) {
        for (i = 0; i < value->length; i++) {
            release(&value->items[i]);
            if (value->keys)
                free(value->keys[i]);
        }
        free(value->items);
        free(value->keys);
    }
    free(value->string);
}

json_value *json_parse(const char *text, size_t size, char *error, size_t error_size)
{
    parser state;
    json_value *root = calloc(1, sizeof *root);
    if (error && error_size)
        error[0] = '\0';
    state.start = state.cursor = text;
    state.end = text + size;
    state.error = error;
    state.error_size = error_size;
    state.depth = 0;
    if (!root) {
        if (error && error_size)
            snprintf(error, error_size, "out of memory");
        return NULL;
    }
    skip_space(&state);
    if (parse_value(&state, root)) {
        skip_space(&state);
        if (state.cursor == state.end)
            return root;
        fail(&state, "trailing data");
    }
    json_free(root);
    return NULL;
}

void json_free(json_value *value)
{
    if (!value)
        return;
    release(value);
    free(value);
}

const json_value *json_get(const json_value *object, const char *key)
{
    size_t i;
    if (!object || object->type != JSON_OBJECT)
        return NULL;
    for (i = 0; i < object->length; i++)
        if (strcmp(object->keys[i], key) == 0)
            return &object->items[i];
    return NULL;
}
