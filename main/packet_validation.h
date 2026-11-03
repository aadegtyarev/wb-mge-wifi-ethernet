/* SPDX-License-Identifier: MIT */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Ethernet frame must contain a complete, unfragmented IPv4/UDP DHCP header.
 * This intentionally rejects IPv4 options; the forwarding code assumes IHL=5. */
static inline bool valid_dhcp_ipv4(const uint8_t *ip, size_t frame_len)
{
    if (frame_len < 285 || ip[0] != 0x45 || ip[9] != 17 ||
        (ip[6] & 0x3f) || ip[7]) return false;
    unsigned ip_len = ((unsigned)ip[2] << 8) | ip[3];
    unsigned udp_len = ((unsigned)ip[24] << 8) | ip[25];
    return ip_len >= 20 + 8 + 243 && ip_len <= frame_len - 14 && udp_len == ip_len - 20;
}

/* Return NULL for absent or malformed options. The four-byte DHCP cookie is
 * required; option 0 is padding and 255 terminates the option list. */
static inline uint8_t *dhcp_find_option(uint8_t *cookie, uint8_t *end, uint8_t code, size_t expected_len)
{
    static const uint8_t magic[4] = {0x63, 0x82, 0x53, 0x63};
    if (cookie > end || (size_t)(end - cookie) < sizeof(magic) ||
        memcmp(cookie, magic, sizeof(magic)) != 0) return NULL;
    uint8_t *p = cookie + sizeof(magic);
    while (p < end) {
        uint8_t id = *p++;
        if (id == 255) return NULL;
        if (id == 0) continue;
        if (p == end) return NULL;
        size_t len = *p++;
        if (len > (size_t)(end - p)) return NULL;
        if (id == code && len == expected_len) return p;
        p += len;
    }
    return NULL;
}
