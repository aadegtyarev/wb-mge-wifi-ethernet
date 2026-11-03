/* Based on ESP-IDF sta2eth, Copyright 2023-2024 Espressif Systems.
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include "frame_bridge.h"
#include "packet_validation.h"
#include <string.h>

static uint16_t be16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }

static bool client_source_valid(const uint8_t mac[6], const uint8_t wifi_mac[6])
{
    static const uint8_t zero[6] = {0};
    return !(mac[0] & 1) && memcmp(mac, zero, 6) && memcmp(mac, wifi_mac, 6);
}

/* Recalculate the UDP checksum, including the IPv4 pseudo-header. */
static void udp_checksum(uint8_t *ip, uint8_t *udp)
{
    size_t len = be16(udp + 4);
    uint32_t sum = 17 + len;
    udp[6] = udp[7] = 0;
    for (size_t i = 12; i < 20; i += 2) sum += be16(ip + i);
    for (size_t i = 0; i + 1 < len; i += 2) sum += be16(udp + i);
    if (len & 1) sum += (uint16_t)udp[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t result = (uint16_t)~sum;
    if (!result) result = 0xffff; /* zero denotes no checksum in IPv4 UDP */
    udp[6] = result >> 8;
    udp[7] = result & 0xff;
}

static void rewrite_dhcp(frame_bridge_t *s, bridge_direction_t direction,
                         uint8_t *frame, size_t len, const uint8_t wifi_mac[6])
{
    uint8_t *ip = frame + 14;
    if (!valid_dhcp_ipv4(ip, len)) return;
    uint8_t *udp = ip + 20;
    uint16_t src = be16(udp), dst = be16(udp + 2);
    if ((direction == BRIDGE_FROM_ETHERNET && (src != 68 || dst != 67)) ||
        (direction == BRIDGE_TO_ETHERNET && (src != 67 || dst != 68))) return;

    uint8_t *bootp = udp + 8;
    uint8_t *end = ip + be16(ip + 2);
    uint8_t *cookie = bootp + 236;
    uint8_t *type = dhcp_find_option(cookie, end, 53, 1);
    if (!type || bootp[1] != 1 || bootp[2] != 6) return;
    uint8_t *chaddr = bootp + 28;
    bool changed = false;
    if (direction == BRIDGE_FROM_ETHERNET && bootp[0] == 1) {
        /* A new Discover replaces the client; Request also learns an unknown
         * client after the bridge restarts while its DHCP lease is still valid. */
        if ((*type == 1 || (*type == 3 && !s->client_known)) &&
            client_source_valid(frame + 6, wifi_mac) && !memcmp(chaddr, frame + 6, 6)) {
            memcpy(s->client_mac, frame + 6, 6);
            s->client_known = true;
        }
        if (!s->client_known || memcmp(frame + 6, s->client_mac, 6)) return;
        if (!memcmp(chaddr, s->client_mac, 6)) {
            memcpy(chaddr, wifi_mac, 6);
            changed = true;
        }
        uint8_t *id = dhcp_find_option(cookie, end, 61, 7);
        if (id && id[0] == 1 && !memcmp(id + 1, s->client_mac, 6)) {
            memcpy(id + 1, wifi_mac, 6);
            changed = true;
        }
    } else if (direction == BRIDGE_TO_ETHERNET && bootp[0] == 2 && s->client_known &&
               !memcmp(chaddr, wifi_mac, 6)) {
        memcpy(chaddr, s->client_mac, 6);
        uint8_t *id = dhcp_find_option(cookie, end, 61, 7);
        if (id && id[0] == 1 && !memcmp(id + 1, wifi_mac, 6))
            memcpy(id + 1, s->client_mac, 6);
        changed = true;
    }
    if (changed) udp_checksum(ip, udp);
}

void frame_bridge_rewrite(frame_bridge_t *s, bridge_direction_t direction,
                          uint8_t *frame, size_t len, const uint8_t wifi_mac[6])
{
    if (!s || !frame || !wifi_mac || len < 14) return;
    uint16_t type = be16(frame + 12);
    if (type == 0x0800) rewrite_dhcp(s, direction, frame, len, wifi_mac);
    else if (type == 0x0806 && len >= 42) {
        static const uint8_t arp_header[] = {0, 1, 8, 0, 6, 4};
        uint8_t *arp = frame + 14;
        if (!memcmp(arp, arp_header, sizeof(arp_header))) {
            if (!s->client_known && direction == BRIDGE_FROM_ETHERNET && client_source_valid(frame + 6, wifi_mac) &&
                !memcmp(arp + 8, frame + 6, 6)) {
                memcpy(s->client_mac, frame + 6, 6);
                s->client_known = true;
            }
            if (s->client_known && direction == BRIDGE_FROM_ETHERNET && !memcmp(arp + 8, s->client_mac, 6))
                memcpy(arp + 8, wifi_mac, 6);
            else if (s->client_known && direction == BRIDGE_TO_ETHERNET && !memcmp(arp + 18, wifi_mac, 6))
                memcpy(arp + 18, s->client_mac, 6);
        }
    }
    if (type != 0x0800 && type != 0x0806) return;
    if (s->client_known && direction == BRIDGE_FROM_ETHERNET && !memcmp(frame + 6, s->client_mac, 6))
        memcpy(frame + 6, wifi_mac, 6);
    else if (s->client_known && direction == BRIDGE_TO_ETHERNET && !memcmp(frame, wifi_mac, 6))
        memcpy(frame, s->client_mac, 6);
}
