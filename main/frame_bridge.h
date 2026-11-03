/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t client_mac[6];
    bool client_known;
} frame_bridge_t;

typedef enum { BRIDGE_FROM_ETHERNET, BRIDGE_TO_ETHERNET } bridge_direction_t;

/* Callers must serialize access to the state. Frames shorter than an Ethernet
 * header are ignored. Only untagged IPv4 and Ethernet/IPv4 ARP are rewritten. */
void frame_bridge_rewrite(frame_bridge_t *state, bridge_direction_t direction,
                          uint8_t *frame, size_t len, const uint8_t wifi_mac[6]);
