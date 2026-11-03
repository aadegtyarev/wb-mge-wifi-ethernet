/* SPDX-License-Identifier: MIT */
#include "bssid_selector.h"
#include <string.h>

void bssid_selector_init(bssid_selector_t *s, const uint8_t *reference)
{
    memset(s, 0, sizeof(*s));
    if (reference) {
        memcpy(s->reference, reference, 6);
        s->has_reference = true;
    }
}

void bssid_selector_add(bssid_selector_t *s, const uint8_t candidate[6])
{
    if (!s->has_first || memcmp(candidate, s->first, 6) < 0) {
        memcpy(s->first, candidate, 6);
        s->has_first = true;
    }
    if (s->has_reference && memcmp(candidate, s->reference, 6) > 0 &&
        (!s->has_next || memcmp(candidate, s->next, 6) < 0)) {
        memcpy(s->next, candidate, 6);
        s->has_next = true;
    }
}

bool bssid_selector_result(const bssid_selector_t *s, uint8_t result[6])
{
    if (!s->has_first) return false;
    const uint8_t *selected = s->has_next ? s->next : s->first;
    if (s->has_reference && !memcmp(selected, s->reference, 6)) return false;
    memcpy(result, selected, 6);
    return true;
}
