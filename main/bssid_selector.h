/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t reference[6], first[6], next[6];
    bool has_reference, has_first, has_next;
} bssid_selector_t;

/* Enumerate matching APs in any order. Select the lexicographically next BSSID,
 * wrapping to the lowest. A missing reference selects the lowest candidate. */
void bssid_selector_init(bssid_selector_t *s, const uint8_t *reference);
void bssid_selector_add(bssid_selector_t *s, const uint8_t candidate[6]);
bool bssid_selector_result(const bssid_selector_t *s, uint8_t result[6]);
