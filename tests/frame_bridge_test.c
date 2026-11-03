/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "frame_bridge.h"

static const uint8_t client[] = {0x02, 1, 2, 3, 4, 5};
static const uint8_t station[] = {0x02, 7, 8, 9, 10, 11};
static uint16_t be16(const uint8_t *p) { return (p[0] << 8) | p[1]; }

static uint16_t checksum_sum(const uint8_t *ip)
{
    const uint8_t *udp = ip + 20;
    size_t len = be16(udp + 4);
    uint32_t sum = 17 + len;
    for (int i = 12; i < 20; i += 2) sum += be16(ip + i);
    for (size_t i = 0; i + 1 < len; i += 2) sum += be16(udp + i);
    if (len & 1) sum += udp[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return sum;
}

static void dhcp(uint8_t *f, int reply)
{
    memset(f, 0, 320);
    memcpy(reply ? f : f + 6, reply ? station : client, 6);
    f[12] = 8; f[13] = 0;
    uint8_t *ip = f + 14;
    ip[0] = 0x45; ip[2] = 1; ip[3] = 30; ip[9] = 17; /* IP length 286 */
    uint8_t *udp = ip + 20;
    udp[1] = reply ? 67 : 68; udp[3] = reply ? 68 : 67;
    udp[4] = 1; udp[5] = 10; /* UDP length 266 */
    uint8_t *bootp = udp + 8;
    bootp[0] = reply ? 2 : 1; bootp[1] = 1; bootp[2] = 6;
    memcpy(bootp + 28, reply ? station : client, 6);
    uint8_t opts[] = {0x63, 0x82, 0x53, 0x63, 0, 12, 1, 'x', 53, 1,
                      reply ? 5 : 1, 61, 7, 1, 2, 1, 2, 3, 4, 5, 255};
    memcpy(bootp + 236, opts, sizeof(opts));
    if (reply) memcpy(bootp + 236 + 14, station, 6);
}

int main(void)
{
    uint8_t f[320];
    frame_bridge_t state = {0};
    /* Renew after bridge reboot: DHCP Request can identify the client. */
    dhcp(f, 0);
    f[14 + 20 + 8 + 236 + 10] = 3;
    frame_bridge_rewrite(&state, BRIDGE_FROM_ETHERNET, f, sizeof(f), station);
    assert(state.client_known && !memcmp(state.client_mac, client, 6));
    state = (frame_bridge_t){0};
    dhcp(f, 0);
    frame_bridge_rewrite(&state, BRIDGE_FROM_ETHERNET, f, sizeof(f), station);
    assert(state.client_known && !memcmp(state.client_mac, client, 6));
    assert(!memcmp(f + 6, station, 6));
    assert(!memcmp(f + 14 + 20 + 8 + 28, station, 6));
    assert(!memcmp(f + 14 + 20 + 8 + 236 + 14, station, 6));
    assert(checksum_sum(f + 14) == 0xffff);

    dhcp(f, 1);
    frame_bridge_rewrite(&state, BRIDGE_TO_ETHERNET, f, sizeof(f), station);
    assert(!memcmp(f, client, 6));
    assert(!memcmp(f + 14 + 20 + 8 + 28, client, 6));
    assert(!memcmp(f + 14 + 20 + 8 + 236 + 14, client, 6));
    assert(checksum_sum(f + 14) == 0xffff);

    /* Do not learn a client from a discovery with a mismatched BOOTP address. */
    dhcp(f, 0);
    f[11] = 42;
    frame_bridge_rewrite(&state, BRIDGE_FROM_ETHERNET, f, sizeof(f), station);
    assert(!memcmp(state.client_mac, client, 6));

    /* A later DHCP discovery on the same link learns a replacement client. */
    dhcp(f, 0);
    f[11] = 42;
    f[14 + 20 + 8 + 28 + 5] = 42;
    frame_bridge_rewrite(&state, BRIDGE_FROM_ETHERNET, f, sizeof(f), station);
    assert(state.client_mac[5] == 42 && !memcmp(f + 6, station, 6));
    state.client_mac[5] = 5;

    memset(f, 0, sizeof(f));
    memcpy(f + 6, client, 6); f[12] = 8; f[13] = 6;
    uint8_t arp[] = {0, 1, 8, 0, 6, 4, 0, 1};
    memcpy(f + 14, arp, sizeof(arp)); memcpy(f + 22, client, 6);
    state = (frame_bridge_t){0};
    frame_bridge_rewrite(&state, BRIDGE_FROM_ETHERNET, f, 42, station);
    assert(state.client_known && !memcmp(state.client_mac, client, 6));
    assert(!memcmp(f + 22, station, 6));
    memcpy(f, station, 6);
    memcpy(f + 14 + 18, station, 6);
    frame_bridge_rewrite(&state, BRIDGE_TO_ETHERNET, f, 42, station);
    assert(!memcmp(f, client, 6));
    assert(!memcmp(f + 14 + 18, client, 6));

    /* A valid packet truncated at every byte boundary must be safe. Allocate
     * exactly n + 1 bytes so the misaligned frame ends at an ASan red zone. */
    uint8_t complete[320];
    dhcp(complete, 0);
    for (size_t n = 0; n <= sizeof(complete); ++n) {
        uint8_t *data = malloc(n + 1);
        assert(data);
        memcpy(data + 1, complete, n);
        frame_bridge_t local = {0};
        frame_bridge_rewrite(&local, BRIDGE_FROM_ETHERNET, data + 1, n, station);
        free(data);
    }

    /* Exercise exact-size, deliberately misaligned allocations with arbitrary
     * packet contents. ASan detects access before or after the declared frame. */
    uint32_t rng = 42;
    for (size_t n = 0; n < 512; ++n) {
        uint8_t *data = malloc(n + 1);
        assert(data);
        for (size_t i = 0; i < n + 1; ++i) {
            rng = rng * 1664525u + 1013904223u;
            data[i] = rng >> 24;
        }
        if (n >= 14) { data[13] = 8; data[14] = (n & 1) ? 0 : 6; }
        frame_bridge_rewrite(&state, BRIDGE_FROM_ETHERNET, data + 1, n, station);
        frame_bridge_rewrite(&state, BRIDGE_TO_ETHERNET, data + 1, n, station);
        free(data);
    }
    return 0;
}
