/* SPDX-License-Identifier: MIT */
#include "credentials.h"
#include <stddef.h>
#include <string.h>

static int hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static bool decode(const char *src, uint8_t *dst, size_t capacity, size_t *out_len)
{
    size_t n = 0;
    while (*src) {
        unsigned char c = *src++;
        if (c == '+') c = ' ';
        else if (c == '%') {
            if (!src[0] || !src[1]) return false;
            int a = hex(src[0]), b = hex(src[1]);
            if (a < 0 || b < 0) return false;
            c = (unsigned char)((a << 4) | b);
            src += 2;
        }
        if (!c || n >= capacity) return false;
        dst[n++] = c;
    }
    *out_len = n;
    return true;
}

bool credentials_decode(const char *ssid, const char *password,
                        uint8_t ssid_out[32], uint8_t password_out[64])
{
    if (!ssid || !password || !ssid_out || !password_out) return false;
    uint8_t ssid_buf[32] = {0}, password_buf[64] = {0};
    size_t ssid_len = 0, password_len = 0;
    bool ok = decode(ssid, ssid_buf, sizeof(ssid_buf), &ssid_len) && ssid_len > 0 &&
              decode(password, password_buf, sizeof(password_buf), &password_len);
    if (ok && password_len != 0 && (password_len < 8 || password_len > 64)) ok = false;
    if (ok && password_len == 64) {
        for (size_t i = 0; i < password_len; ++i) {
            if (hex((char)password_buf[i]) < 0) { ok = false; break; }
        }
    }
    if (ok) {
        memcpy(ssid_out, ssid_buf, sizeof(ssid_buf));
        memcpy(password_out, password_buf, sizeof(password_buf));
    }
    /* Avoid leaving an additional credential copy in the stack. */
    volatile uint8_t *p = password_buf;
    for (size_t i = 0; i < sizeof(password_buf); ++i) p[i] = 0;
    return ok;
}
