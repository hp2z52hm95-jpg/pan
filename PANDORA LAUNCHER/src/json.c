/*
 * json.c - minimal JSON parser for the launcher's server responses.
 * Portable C99. Parses RFC 8259 objects/arrays/strings/numbers/bools/null,
 * decodes \uXXXX escapes to UTF-8, ignores extra whitespace.
 * On error json_parse() returns NULL (the launcher then reports
 * "Invalid server response" instead of guessing).
 */
#include "pandora.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *p;
    const char *end;
    int         depth;
} jparse;

static json *parse_value(jparse *s);

static json *jnew(jtype t)
{
    json *v = (json *)p_malloc(sizeof(json));
    memset(v, 0, sizeof(*v));
    v->t = t;
    return v;
}

void json_free(json *v)
{
    size_t i;
    if (!v)
        return;
    switch (v->t) {
    case JSON_ARR:
        for (i = 0; i < v->nitems; i++)
            json_free(v->items[i]);
        free(v->items);
        break;
    case JSON_OBJ:
        for (i = 0; i < v->nkeys; i++) {
            free(v->keys[i]);
            json_free(v->vals[i]);
        }
        free(v->keys);
        free(v->vals);
        break;
    default:
        break;
    }
    free(v->raw);
    free(v);
}

static void skip_ws(jparse *s)
{
    while (s->p < s->end) {
        char c = *s->p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            s->p++;
        else
            break;
    }
}

static int peek(jparse *s)
{
    return s->p < s->end ? (unsigned char)*s->p : -1;
}

/* appends UTF-8 encoding of a code point */
static void utf8_add(sbuf *b, unsigned long cp)
{
    if (cp < 0x80) {
        sb_addc(b, (char)cp);
    } else if (cp < 0x800) {
        sb_addc(b, (char)(0xc0 | (cp >> 6)));
        sb_addc(b, (char)(0x80 | (cp & 0x3f)));
    } else if (cp < 0x10000) {
        sb_addc(b, (char)(0xe0 | (cp >> 12)));
        sb_addc(b, (char)(0x80 | ((cp >> 6) & 0x3f)));
        sb_addc(b, (char)(0x80 | (cp & 0x3f)));
    } else {
        sb_addc(b, (char)(0xf0 | (cp >> 18)));
        sb_addc(b, (char)(0x80 | ((cp >> 12) & 0x3f)));
        sb_addc(b, (char)(0x80 | ((cp >> 6) & 0x3f)));
        sb_addc(b, (char)(0x80 | (cp & 0x3f)));
    }
}

static int hex4(const char *p, unsigned long *out)
{
    unsigned long v = 0;
    int i;
    for (i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned long)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned long)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned long)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

/* parses a string body (after the opening quote); returns malloc'd UTF-8 */
static char *parse_string_body(jparse *s)
{
    sbuf b;
    char *out;

    sb_init(&b);
    for (;;) {
        unsigned char c;
        if (s->p >= s->end) {
            sb_free(&b);
            return NULL;
        }
        c = (unsigned char)*s->p++;
        if (c == '"') {
            out = sb_take(&b);
            return out;
        }
        if (c != '\\') {
            sb_addc(&b, (char)c);
            continue;
        }
        if (s->p >= s->end) {
            sb_free(&b);
            return NULL;
        }
        c = (unsigned char)*s->p++;
        switch (c) {
        case '"':  sb_addc(&b, '"');  break;
        case '\\': sb_addc(&b, '\\'); break;
        case '/':  sb_addc(&b, '/');  break;
        case 'b':  sb_addc(&b, '\b'); break;
        case 'f':  sb_addc(&b, '\f'); break;
        case 'n':  sb_addc(&b, '\n'); break;
        case 'r':  sb_addc(&b, '\r'); break;
        case 't':  sb_addc(&b, '\t'); break;
        case 'u': {
            unsigned long cp;
            if (s->p + 4 > s->end || hex4(s->p, &cp) != 0) {
                sb_free(&b);
                return NULL;
            }
            s->p += 4;
            if (cp >= 0xd800 && cp <= 0xdbff && s->p + 6 <= s->end &&
                s->p[0] == '\\' && s->p[1] == 'u') {
                unsigned long lo;
                if (hex4(s->p + 2, &lo) == 0 && lo >= 0xdc00 && lo <= 0xdfff) {
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                    s->p += 6;
                }
            }
            utf8_add(&b, cp);
            break;
        }
        default:
            sb_free(&b);
            return NULL;
        }
    }
}

static json *parse_string(jparse *s)
{
    json *v;
    char *str;

    if (peek(s) != '"')
        return NULL;
    s->p++;
    str = parse_string_body(s);
    if (!str)
        return NULL;
    v = jnew(JSON_STR);
    v->raw = str;
    v->rawlen = strlen(str);
    return v;
}

static json *parse_number(jparse *s)
{
    const char *start = s->p;
    json *v;

    if (peek(s) == '-')
        s->p++;
    while (s->p < s->end && (*s->p >= '0' && *s->p <= '9'))
        s->p++;
    if (peek(s) == '.') {
        s->p++;
        while (s->p < s->end && (*s->p >= '0' && *s->p <= '9'))
            s->p++;
    }
    if (peek(s) == 'e' || peek(s) == 'E') {
        s->p++;
        if (peek(s) == '+' || peek(s) == '-')
            s->p++;
        while (s->p < s->end && (*s->p >= '0' && *s->p <= '9'))
            s->p++;
    }
    if (s->p == start)
        return NULL;
    v = jnew(JSON_NUM);
    v->raw = p_strndup(start, (size_t)(s->p - start));
    v->rawlen = strlen(v->raw);
    v->num = strtod(v->raw, NULL);
    return v;
}

static int lit(jparse *s, const char *word)
{
    size_t n = strlen(word);
    if ((size_t)(s->end - s->p) < n || memcmp(s->p, word, n) != 0)
        return 0;
    s->p += n;
    return 1;
}

static json *parse_object(jparse *s)
{
    json *v;
    size_t cap = 0;

    s->p++; /* '{' */
    v = jnew(JSON_OBJ);
    skip_ws(s);
    if (peek(s) == '}') {
        s->p++;
        return v;
    }
    for (;;) {
        char *key;
        json *val;

        skip_ws(s);
        if (peek(s) != '"')
            goto fail;
        s->p++;
        key = parse_string_body(s);
        if (!key)
            goto fail;
        skip_ws(s);
        if (peek(s) != ':') {
            free(key);
            goto fail;
        }
        s->p++;
        skip_ws(s);
        val = parse_value(s);
        if (!val) {
            free(key);
            goto fail;
        }
        if (v->nkeys == cap) {
            cap = cap ? cap * 2 : 8;
            v->keys = (char **)p_realloc(v->keys, cap * sizeof(char *));
            v->vals = (json **)p_realloc(v->vals, cap * sizeof(json *));
        }
        v->keys[v->nkeys] = key;
        v->vals[v->nkeys] = val;
        v->nkeys++;
        skip_ws(s);
        if (peek(s) == ',') {
            s->p++;
            continue;
        }
        if (peek(s) == '}') {
            s->p++;
            return v;
        }
        goto fail;
    }
fail:
    json_free(v);
    return NULL;
}

static json *parse_array(jparse *s)
{
    json *v;
    size_t cap = 0;

    s->p++; /* '[' */
    v = jnew(JSON_ARR);
    skip_ws(s);
    if (peek(s) == ']') {
        s->p++;
        return v;
    }
    for (;;) {
        json *item;
        skip_ws(s);
        item = parse_value(s);
        if (!item)
            goto fail;
        if (v->nitems == cap) {
            cap = cap ? cap * 2 : 8;
            v->items = (json **)p_realloc(v->items, cap * sizeof(json *));
        }
        v->items[v->nitems++] = item;
        skip_ws(s);
        if (peek(s) == ',') {
            s->p++;
            continue;
        }
        if (peek(s) == ']') {
            s->p++;
            return v;
        }
        goto fail;
    }
fail:
    json_free(v);
    return NULL;
}

static json *parse_value(jparse *s)
{
    if (s->depth > 64)
        return NULL;
    s->depth++;
    switch (peek(s)) {
    case '{': { json *v = parse_object(s); s->depth--; return v; }
    case '[': { json *v = parse_array(s);  s->depth--; return v; }
    case '"': { json *v = parse_string(s); s->depth--; return v; }
    case 't': case 'f': {
        json *v;
        if (lit(s, "true")) {
            v = jnew(JSON_BOOL); v->b = 1; s->depth--; return v;
        }
        if (lit(s, "false")) {
            v = jnew(JSON_BOOL); v->b = 0; s->depth--; return v;
        }
        s->depth--;
        return NULL;
    }
    case 'n':
        if (lit(s, "null")) {
            json *v = jnew(JSON_NULL);
            s->depth--;
            return v;
        }
        s->depth--;
        return NULL;
    default: {
        json *v = parse_number(s);
        s->depth--;
        return v;
    }
    }
}

json *json_parse(const char *s, size_t n)
{
    jparse st;
    json *v;

    if (!s)
        return NULL;
    st.p = s;
    st.end = s + n;
    st.depth = 0;
    skip_ws(&st);
    v = parse_value(&st);
    if (!v)
        return NULL;
    skip_ws(&st);
    if (st.p != st.end) {
        json_free(v);
        return NULL;
    }
    return v;
}

const json *json_get(const json *obj, const char *key)
{
    size_t i;
    if (!obj || obj->t != JSON_OBJ)
        return NULL;
    for (i = 0; i < obj->nkeys; i++)
        if (strcmp(obj->keys[i], key) == 0)
            return obj->vals[i];
    return NULL;
}

const char *json_str(const json *obj, const char *key, const char *def)
{
    const json *v = json_get(obj, key);
    if (!v)
        return def;
    if (v->t == JSON_STR)
        return v->raw ? v->raw : "";
    if (v->t == JSON_NULL)
        return def;
    if (v->t == JSON_NUM)
        return v->raw ? v->raw : def;
    return def;
}

int json_bool(const json *obj, const char *key, int def)
{
    const json *v = json_get(obj, key);
    if (!v)
        return def;
    if (v->t == JSON_BOOL)
        return v->b;
    if (v->t == JSON_NUM)
        return v->num != 0;
    if (v->t == JSON_STR)
        return ascii_icmp(v->raw, "true") == 0;
    return def;
}

double json_num(const json *obj, const char *key, double def)
{
    const json *v = json_get(obj, key);
    if (!v)
        return def;
    if (v->t == JSON_NUM)
        return v->num;
    if (v->t == JSON_STR && v->raw)
        return strtod(v->raw, NULL);
    return def;
}

size_t json_len(const json *arr)
{
    if (!arr)
        return 0;
    if (arr->t == JSON_ARR)
        return arr->nitems;
    return 0;
}

const json *json_at(const json *arr, size_t i)
{
    if (!arr || arr->t != JSON_ARR || i >= arr->nitems)
        return NULL;
    return arr->items[i];
}
