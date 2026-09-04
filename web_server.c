// Minimal HTTP/1.1 server over lwIP's raw (callback) TCP API, for the usbnet
// web service. It is intentionally small and single-threaded (lwIP NO_SYS):
// everything is driven by the caller's existing usb_network_update() loop,
// which calls tud_task() and sys_check_timeouts().
//
// Routes (see web_server.h):
//   POST /write  -> persist JSON form fields to flash (<= 2 KiB)
//   GET  /print  -> return the stored data
//   GET  /clear  -> erase the stored data
//
// Only a very small subset of HTTP is supported (GET/POST, Content-Length for
// the POST body); a compliant client (curl, a browser, Postman) is sufficient.
// Each response uses "Connection: close".

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

#include "storage.h"
#include "web_server.h"

#define WEB_PORT 80
#define WEB_MAX_CONNS 2

// Bound the buffered request: enough for the request line + headers plus a
// 2 KiB body, plus slack.
#define WEB_HEADER_LIMIT 1024
#define WEB_BUF_SIZE (WEB_HEADER_LIMIT + STORAGE_MAX_PAYLOAD + 64)

// JSON form field names that /write extracts and /print returns.
static const char *const WRITE_FIELDS[] = {"name", "value"};
#define WRITE_FIELDS_COUNT (sizeof(WRITE_FIELDS) / sizeof(WRITE_FIELDS[0]))

typedef struct {
    struct tcp_pcb *pcb;
    bool active;
    bool responded;              // stop processing further data
    bool close_after_send;
    bool headers_done;
    bool have_content_length;
    uint16_t content_length;
    uint16_t len;                // bytes currently buffered in buf[]
    uint16_t out_len;            // response length being sent
    uint16_t acked;              // response bytes acknowledged so far
    uint8_t idle;                // poll ticks since last activity
    size_t body_start;           // offset of the POST body in buf[]
    char method[8];
    char path[96];
    uint8_t buf[WEB_BUF_SIZE];
} http_conn_t;

static http_conn_t http_conns[WEB_MAX_CONNS];

// Response staging buffer (single-threaded, so one shared buffer is fine).
static uint8_t resp_buf[WEB_BUF_SIZE];

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

static int ci_strncasecmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
        if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb) return (int)ca - (int)cb;
    }
    return 0;
}

// Returns pointer to the first "\r\n\r\n" in buf, or NULL.
static const uint8_t *find_head_end(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i + 3 < len; ++i) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return &buf[i];
        }
    }
    return NULL;
}

// Result of extracting one JSON string field.
typedef enum {
    JSON_FIELD_ABSENT = 0, // field/key not present (or not followed by a string)
    JSON_FIELD_FOUND,      // field present, decoded value copied into out
    JSON_FIELD_INVALID     // document malformed / uses unsupported escapes
} json_field_result_t;

// Extracts a JSON string-valued field by name and copies its decoded value
// into out (NUL-terminated). Only the common JSON escapes are decoded
// (\" \\ \/ \b \f \n \r \t); \uXXXX and any other escape, a dangling
// backslash or a raw control byte makes the document INVALID instead of being
// silently mangled (an unknown escape used to be stored without its
// backslash, corrupting the value).
static json_field_result_t json_get_string(const char *json, size_t jlen, const char *key, char *out, size_t outcap) {
    if (!json || !key || !out || outcap == 0) return JSON_FIELD_INVALID;
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen + 1 < jlen; ++i) {
        if (json[i] != '"') continue;
        if (memcmp(json + i + 1, key, klen) != 0) continue;
        if (json[i + 1 + klen] != '"') continue;
        size_t j = i + 2 + klen;
        while (j < jlen && (json[j] == ' ' || json[j] == '\t' || json[j] == '\r' || json[j] == '\n')) ++j;
        if (j >= jlen || json[j] != ':') continue;
        ++j;
        while (j < jlen && (json[j] == ' ' || json[j] == '\t' || json[j] == '\r' || json[j] == '\n')) ++j;
        if (j >= jlen || json[j] != '"') return JSON_FIELD_INVALID;
        ++j;

        size_t o = 0;
        while (j < jlen) {
            char ch = json[j];
            if (ch == '"') { // end of the string value
                out[o] = 0;
                return JSON_FIELD_FOUND;
            }
            if (ch == '\\') {
                if (j + 1 >= jlen) return JSON_FIELD_INVALID; // dangling backslash
                char dec;
                switch (json[j + 1]) {
                    case '"': dec = '"'; break;
                    case '\\': dec = '\\'; break;
                    case '/': dec = '/'; break;
                    case 'b': dec = '\b'; break;
                    case 'f': dec = '\f'; break;
                    case 'n': dec = '\n'; break;
                    case 'r': dec = '\r'; break;
                    case 't': dec = '\t'; break;
                    default: return JSON_FIELD_INVALID; // incl. \uXXXX: unsupported
                }
                if (o + 1 < outcap) out[o++] = dec; // an overlong value is truncated
                j += 2;                             // here and rejected as 413 later
            } else {
                if ((unsigned char)ch < 0x20) return JSON_FIELD_INVALID; // raw control char
                if (o + 1 < outcap) out[o++] = ch;
                ++j;
            }
        }
        return JSON_FIELD_INVALID; // unterminated string
    }
    return JSON_FIELD_ABSENT;
}

// Appends the JSON-escaped representation of src into dst (capped at cap
// bytes), returning the new offset. Control characters are escaped instead of
// being dropped, so /print round-trips every byte of a stored value. A
// character is only written when its whole escape sequence fits; the caller
// detects the resulting truncation and answers 413.
static size_t json_append_escaped(char *dst, size_t cap, const char *src) {
    static const char hex[] = "0123456789abcdef";
    size_t n = 0;
    for (const char *s = src; *s; ++s) {
        unsigned char ch = (unsigned char)*s;
        const char *esc = NULL;
        size_t need = 1;
        char buf[6];
        switch (ch) {
            case '"': esc = "\\\""; need = 2; break;
            case '\\': esc = "\\\\"; need = 2; break;
            case '\b': esc = "\\b"; need = 2; break;
            case '\f': esc = "\\f"; need = 2; break;
            case '\n': esc = "\\n"; need = 2; break;
            case '\r': esc = "\\r"; need = 2; break;
            case '\t': esc = "\\t"; need = 2; break;
            default:
                if (ch >= 0x20) break; // printable (incl. UTF-8 >= 0x80): raw
                buf[0] = '\\'; buf[1] = 'u'; buf[2] = '0'; buf[3] = '0';
                buf[4] = hex[(ch >> 4) & 0xf]; buf[5] = hex[ch & 0xf];
                esc = buf;
                need = 6;
                break;
        }
        if (n + need > cap) break; // never emit a partial escape
        if (esc != NULL) {
            memcpy(dst + n, esc, need);
        } else {
            dst[n] = (char)ch;
        }
        n += need;
    }
    return n;
}

// ---------------------------------------------------------------------------
// connection pool
// ---------------------------------------------------------------------------

static http_conn_t *get_free_conn(void) {
    for (int i = 0; i < WEB_MAX_CONNS; ++i) {
        if (!http_conns[i].active) {
            http_conn_t *c = &http_conns[i];
            memset(c, 0, sizeof(*c));
            return c;
        }
    }
    return NULL;
}

static void release_conn(http_conn_t *c) {
    if (c) {
        c->active = false;
        c->pcb = NULL;
    }
}

// ---------------------------------------------------------------------------
// response / routing
// ---------------------------------------------------------------------------

static void respond(http_conn_t *c, struct tcp_pcb *pcb, const char *status, const char *body, size_t body_len) {
    char head[160];
    int hn = snprintf(head, sizeof(head),
                      "HTTP/1.1 %s\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: %u\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      status, (unsigned)body_len);
    if (hn < 0 || (size_t)hn + body_len > sizeof(resp_buf)) {
        tcp_arg(pcb, NULL);
        tcp_abort(pcb);
        release_conn(c);
        return;
    }
    memcpy(resp_buf, head, (size_t)hn);
    if (body_len) memcpy(resp_buf + hn, body, body_len);

    err_t err = tcp_write(pcb, resp_buf, (u16_t)(hn + body_len), TCP_WRITE_FLAG_COPY);
    c->responded = true;
    c->close_after_send = true;
    c->out_len = (uint16_t)(hn + body_len);
    c->acked = 0;
    if (err == ERR_OK) {
        tcp_output(pcb);
    } else {
        // Failed to queue the response (e.g. ERR_MEM while the lwIP heap is
        // busy). Clear the callback arg before aborting so the error callback
        // cannot touch a connection slot that may be reused later.
        tcp_arg(pcb, NULL);
        tcp_abort(pcb);
        release_conn(c);
    }
}

// Convenience wrapper for respond() with fixed string bodies: the length is
// computed here, so the body and the Content-Length header can never drift
// apart (they used to be hand-counted magic numbers, several of which were
// wrong and made memcpy() read past the end of the string literal).
static void respond_err(http_conn_t *c, struct tcp_pcb *pcb, const char *status, const char *body) {
    respond(c, pcb, status, body, strlen(body));
}

static void handle_write(http_conn_t *c, struct tcp_pcb *pcb) {
    const char *json = (const char *)c->buf + c->body_start;
    size_t jlen = c->content_length;
    if (jlen == 0) {
        respond_err(c, pcb, "400 Bad Request", "{\"status\":\"error\",\"error\":\"bad or empty body\"}");
        return;
    }
    if (jlen > STORAGE_MAX_PAYLOAD + 256) {
        // Far beyond anything that could ever be stored: reject up front (the
        // exact 2 KiB stored-JSON check below still applies near the limit).
        respond_err(c, pcb, "413 Payload Too Large", "{\"status\":\"error\",\"error\":\"payload too large\"}");
        return;
    }

    // Extract the configured fields.
    static char field_vals[WRITE_FIELDS_COUNT][STORAGE_MAX_PAYLOAD + 2];
    bool has[WRITE_FIELDS_COUNT];
    for (size_t i = 0; i < WRITE_FIELDS_COUNT; ++i) {
        json_field_result_t r = json_get_string(json, jlen, WRITE_FIELDS[i], field_vals[i], sizeof(field_vals[i]));
        if (r == JSON_FIELD_INVALID) {
            respond_err(c, pcb, "400 Bad Request", "{\"status\":\"error\",\"error\":\"malformed json body\"}");
            return;
        }
        has[i] = (r == JSON_FIELD_FOUND);
    }
    bool any = false;
    for (size_t i = 0; i < WRITE_FIELDS_COUNT; ++i) any = any || has[i];
    if (!any) {
        respond_err(c, pcb, "400 Bad Request", "{\"status\":\"error\",\"error\":\"no known form fields\"}");
        return;
    }

    // Re-serialise the extracted fields as a compact JSON object. Writes are
    // bounds-checked so a pathological (huge) field value can never overrun the
    // static buffer; any overflow is reported as 413 below.
    static char stored[STORAGE_MAX_PAYLOAD + 4];
    const size_t stored_size = sizeof(stored);
    size_t o = 0;
    bool overflow = false;
    stored[o++] = '{';
    bool first = true;
    for (size_t i = 0; i < WRITE_FIELDS_COUNT; ++i) {
        if (!has[i]) continue;
        if (o + 2 >= stored_size) { overflow = true; break; }
        if (!first) stored[o++] = ',';
        first = false;
        // "field":"
        stored[o++] = '"';
        size_t klen = strlen(WRITE_FIELDS[i]);
        if (o + klen + 3 >= stored_size) { overflow = true; break; }
        memcpy(stored + o, WRITE_FIELDS[i], klen);
        o += klen;
        stored[o++] = '"';
        stored[o++] = ':';
        stored[o++] = '"';
        o += json_append_escaped(stored + o, stored_size - o, field_vals[i]);
        if (o + 1 >= stored_size) { overflow = true; break; }
        stored[o++] = '"';
    }
    if (!overflow && o + 1 < stored_size) {
        stored[o++] = '}';
    }

    if (overflow || o > STORAGE_MAX_PAYLOAD) {
        respond_err(c, pcb, "413 Payload Too Large", "{\"status\":\"error\",\"error\":\"payload too large\"}");
        return;
    }
    if (!storage_write((const uint8_t *)stored, o)) {
        respond_err(c, pcb, "500 Internal Server Error", "{\"status\":\"error\",\"error\":\"flash write failed\"}");
        return;
    }
    char ok[64];
    int n = snprintf(ok, sizeof(ok), "{\"status\":\"ok\",\"bytes\":%u}", (unsigned)o);
    respond(c, pcb, "200 OK", ok, n > 0 ? (size_t)n : 0);
}

static void handle_print(http_conn_t *c, struct tcp_pcb *pcb) {
    static uint8_t data[STORAGE_MAX_PAYLOAD];
    size_t n = storage_read(data, sizeof(data));
    if (n > 0) {
        respond(c, pcb, "200 OK", (const char *)data, n);
    } else {
        respond_err(c, pcb, "200 OK", "{\"status\":\"empty\"}");
    }
}

static void handle_clear(http_conn_t *c, struct tcp_pcb *pcb) {
    bool ok = storage_clear();
    respond_err(c, pcb, "200 OK", ok ? "{\"status\":\"ok\"}" : "{\"status\":\"error\"}");
}

static void handle_request(http_conn_t *c, struct tcp_pcb *pcb) {
    if (strcmp(c->method, "POST") == 0 && strcmp(c->path, "/write") == 0) {
        handle_write(c, pcb);
    } else if (strcmp(c->method, "GET") == 0 && strcmp(c->path, "/print") == 0) {
        handle_print(c, pcb);
    } else if (strcmp(c->method, "GET") == 0 && strcmp(c->path, "/clear") == 0) {
        handle_clear(c, pcb);
    } else {
        respond_err(c, pcb, "404 Not Found", "{\"status\":\"error\",\"error\":\"not found\"}");
    }
}

// ---------------------------------------------------------------------------
// request parsing
// ---------------------------------------------------------------------------

static void parse_request(http_conn_t *c) {
    const uint8_t *he = find_head_end(c->buf, c->len);
    if (!he) {
        if (c->len >= WEB_HEADER_LIMIT) {
            respond_err(c, c->pcb, "400 Bad Request", "{\"status\":\"error\",\"error\":\"headers too large\"}");
        }
        return; // wait for more data
    }
    size_t he_off = (size_t)(he - c->buf);

    // Request line: first CRLF.
    const char *line = (const char *)c->buf;
    const char *line_end = (const char *)memchr(line, '\r', he_off);
    size_t line_len = line_end ? (size_t)(line_end - line) : he_off;
    char reqline[128];
    if (line_len >= sizeof(reqline)) line_len = sizeof(reqline) - 1;
    memcpy(reqline, line, line_len);
    reqline[line_len] = 0;
    reqline[sizeof(reqline) - 1] = 0;

    char *sp = strchr(reqline, ' ');
    if (sp) {
        *sp = 0;
        strncpy(c->method, reqline, sizeof(c->method) - 1);
        c->method[sizeof(c->method) - 1] = 0;
        char *sp2 = strchr(sp + 1, ' ');
        if (sp2) {
            *sp2 = 0;
            strncpy(c->path, sp + 1, sizeof(c->path) - 1);
            c->path[sizeof(c->path) - 1] = 0;
        }
    }

    // Headers: walk each "Key: Value" line, look for Content-Length.
    // Note: the last header line's terminating '\r' sits exactly at he_off
    // (he_off is the start of the "\r\n\r\n" sequence), so the search window
    // must include he_off; otherwise the final header (typically
    // Content-Length) is skipped and the POST body appears empty.
    c->have_content_length = false;
    c->content_length = 0;
    size_t pos = line_len + 2;
    while (pos <= he_off) {
        const char *hdr = (const char *)c->buf + pos;
        const char *hdr_end = (const char *)memchr(hdr, '\r', he_off + 1 - pos);
        if (hdr_end == NULL) break;
        size_t hlen = (size_t)(hdr_end - hdr);
        if (hlen > 0) {
            const char *colon = (const char *)memchr(hdr, ':', hlen);
            if (colon) {
                size_t klen = (size_t)(colon - hdr);
                if (klen == 14 && ci_strncasecmp(hdr, "Content-Length", 14) == 0) {
                    const char *v = colon + 1;
                    while (*v == ' ' || *v == '\t') ++v;
                    char *endp = NULL;
                    unsigned long cl = strtoul(v, &endp, 10);
                    // Accept trailing spaces/tabs only; an empty value, junk
                    // digits or overflow is a malformed request.
                    while (endp != NULL && (*endp == ' ' || *endp == '\t')) ++endp;
                    if (endp == v || (endp != NULL && *endp != '\0' && *endp != '\r')) {
                        respond_err(c, c->pcb, "400 Bad Request", "{\"status\":\"error\",\"error\":\"bad Content-Length\"}");
                        return;
                    }
                    // The whole body must fit into the receive buffer, or the
                    // request could never be processed and the connection
                    // would sit there until the poll timeout aborts it.
                    // body_start is he_off + 4, see below.
                    size_t body_cap = WEB_BUF_SIZE - (he_off + 4);
                    if (cl > body_cap) {
                        respond_err(c, c->pcb, "413 Payload Too Large", "{\"status\":\"error\",\"error\":\"request too large\"}");
                        return;
                    }
                    c->content_length = (uint16_t)cl; // <= body_cap: cannot truncate
                    c->have_content_length = true;
                }
            }
        }
        pos = pos + hlen + 2;
    }

    c->body_start = he_off + 4;
    c->headers_done = true;
}

static void maybe_handle(http_conn_t *c) {
    if (!c->headers_done) {
        parse_request(c);
    }
    if (!c->headers_done) return; // still waiting for header terminator

    size_t required = c->body_start + (c->have_content_length ? c->content_length : 0);
    if (c->len >= required) {
        handle_request(c, c->pcb);
    }
}

// ---------------------------------------------------------------------------
// lwIP callbacks
// ---------------------------------------------------------------------------

// Detach a connection from its slot and close the pcb. The callback arg is
// cleared first, so a late poll/recv/err callback for this pcb can never
// touch a slot that a newer connection may already reuse (ABA). tcp_close()
// can fail (ERR_MEM): fall back to an abort in that case.
static void conn_shutdown(http_conn_t *c, struct tcp_pcb *pcb) {
    if (c && c->pcb == pcb) {
        release_conn(c);
    }
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_sent(pcb, NULL);
    tcp_poll(pcb, NULL, 0);
    if (tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
    }
}

static err_t web_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    http_conn_t *c = (http_conn_t *)arg;

    if (p == NULL) {
        if (err == ERR_OK && c && c->pcb == pcb && c->responded && c->acked < c->out_len) {
            // Peer half-closed its side while our response is still being
            // transmitted: keep the connection until web_sent_cb() finishes.
            return ERR_OK;
        }
        // Peer closed / connection error: close our side too so the pcb is freed.
        conn_shutdown(c, pcb);
        return ERR_OK;
    }

    if (!c || c->pcb != pcb) {
        // Stale callback for an already released slot: just drop the data.
        pbuf_free(p);
        return ERR_OK;
    }

    c->idle = 0;
    u16_t take = p->tot_len;

    if (c->responded || c->len + take > WEB_BUF_SIZE) {
        // Already answered, or request too large: consume and drop.
        tcp_recved(pcb, take);
        pbuf_free(p);
        if (!c->responded) {
            respond_err(c, pcb, "413 Payload Too Large", "{\"status\":\"error\",\"error\":\"request too large\"}");
        }
        return ERR_OK;
    }

    pbuf_copy_partial(p, c->buf + c->len, take, 0);
    c->len = (uint16_t)(c->len + take);
    tcp_recved(pcb, take);
    pbuf_free(p);

    if (!c->responded) {
        maybe_handle(c);
    }
    return ERR_OK;
}

static err_t web_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
    http_conn_t *c = (http_conn_t *)arg;
    if (!c || c->pcb != pcb) {
        return ERR_OK; // stale callback for a released slot
    }
    c->acked = (uint16_t)(c->acked + len);
    c->idle = 0;
    if (c->close_after_send && c->acked >= c->out_len) {
        conn_shutdown(c, pcb);
    }
    return ERR_OK;
}

static void web_err_cb(void *arg, err_t err) {
    (void)err;
    if (arg) {
        // The pcb is already gone; only free the connection slot. Our own
        // shutdown paths clear the arg first, so arg is never a reused slot.
        release_conn((http_conn_t *)arg);
    }
}

static err_t web_poll_cb(void *arg, struct tcp_pcb *pcb) {
    http_conn_t *c = (http_conn_t *)arg;
    if (c && c->pcb == pcb) {
        if (++c->idle > 60) { // 60 polls x ~1 s per poll = ~60 s of inactivity
            tcp_arg(pcb, NULL);
            tcp_abort(pcb);
            release_conn(c);
            return ERR_ABRT;
        }
    }
    return ERR_OK;
}

static err_t web_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    (void)err;
    http_conn_t *c = get_free_conn();
    if (!c) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }
    c->active = true;
    c->pcb = newpcb;

    tcp_arg(newpcb, c);
    tcp_recv(newpcb, web_recv_cb);
    tcp_sent(newpcb, web_sent_cb);
    tcp_err(newpcb, web_err_cb);
    tcp_poll(newpcb, web_poll_cb, 2); // poll every ~1 s
    return ERR_OK;
}

bool web_server_init(void) {
    struct tcp_pcb *pcb = tcp_new();
    if (pcb == NULL) return false;

    err_t err = tcp_bind(pcb, IP_ADDR_ANY, WEB_PORT);
    if (err != ERR_OK) {
        tcp_close(pcb);
        return false;
    }
    pcb = tcp_listen(pcb);
    if (pcb == NULL) return false;

    tcp_accept(pcb, web_accept_cb);
    return true;
}
