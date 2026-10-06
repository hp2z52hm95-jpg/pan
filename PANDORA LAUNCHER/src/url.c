/*
 * url.c - base-URL parsing and percent encoding. Portable C99.
 * Only what the launcher needs: http(s)://host[:port][/prefix].
 */
#include "pandora.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

int url_parse(const char *url, url_base *out, char *err, size_t errlen)
{
    const char *p = url;
    const char *host_start;
    const char *path_start;
    size_t host_len;

    memset(out, 0, sizeof(*out));
    if (!url || !*url) {
        if (err) snprintf(err, errlen, "empty server URL");
        return -1;
    }
    if (strncmp(p, "https://", 8) == 0) {
        out->tls = 1;
        out->default_port = 443;
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        out->tls = 0;
        out->default_port = 80;
        p += 7;
    } else {
        if (err) snprintf(err, errlen,
                          "server URL must start with http:// or https://");
        return -1;
    }

    host_start = p;
    while (*p && *p != '/' && *p != ':')
        p++;
    host_len = (size_t)(p - host_start);
    if (host_len == 0) {
        if (err) snprintf(err, errlen, "server URL has no host");
        return -1;
    }
    out->host = p_strndup(host_start, host_len);

    out->port = out->default_port;
    if (*p == ':') {
        long port = 0;
        p++;
        while (isdigit((unsigned char)*p))
            port = port * 10 + (*p++ - '0');
        if (port <= 0 || port > 65535) {
            if (err) snprintf(err, errlen, "server URL has an invalid port");
            url_free(out);
            return -1;
        }
        out->port = (int)port;
    }

    path_start = p;
    /* strip a trailing slash, keep the prefix ("/updates" etc.) */
    {
        size_t n = strlen(path_start);
        while (n > 0 && path_start[n - 1] == '/')
            n--;
        out->prefix = p_strndup(path_start, n);
    }
    return 0;
}

void url_free(url_base *u)
{
    free(u->host);
    free(u->prefix);
    u->host = u->prefix = NULL;
}

char *url_join(const url_base *u, const char *path)
{
    sbuf b;
    char *out;

    sb_init(&b);
    sb_addf(&b, "%s://%s", u->tls ? "https" : "http", u->host);
    if (u->port != u->default_port)
        sb_addf(&b, ":%d", u->port);
    if (u->prefix && u->prefix[0])
        sb_adds(&b, u->prefix);
    if (!path)
        path = "";
    if (path[0] != '/')
        sb_addc(&b, '/');
    sb_adds(&b, path);
    out = sb_take(&b);
    return out;
}
char *url_encode_query(const char *s)
{
    static const char *hex = "0123456789ABCDEF";
    sbuf b;
    size_t i, n = strlen(s);
    char *out;

    sb_init(&b);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            sb_addc(&b, (char)c);
        } else {
            char enc[3];
            enc[0] = '%';
            enc[1] = hex[c >> 4];
            enc[2] = hex[c & 15];
            sb_add(&b, enc, 3);
        }
    }
    out = sb_take(&b);
    return out;
}
