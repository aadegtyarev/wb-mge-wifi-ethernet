/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <string.h>
#include "bssid_selector.h"

static const uint8_t a[6] = {2, 0, 0, 0, 0, 1};
static const uint8_t b[6] = {2, 0, 0, 0, 0, 2};
static const uint8_t c[6] = {2, 0, 0, 0, 0, 3};

int main(void)
{
    bssid_selector_t s;
    uint8_t selected[6];
    bssid_selector_init(&s, NULL);
    assert(!bssid_selector_result(&s, selected));
    bssid_selector_add(&s, c); bssid_selector_add(&s, a); bssid_selector_add(&s, b);
    assert(bssid_selector_result(&s, selected) && !memcmp(selected, a, 6));

    bssid_selector_init(&s, a);
    bssid_selector_add(&s, c); bssid_selector_add(&s, b); bssid_selector_add(&s, b);
    assert(bssid_selector_result(&s, selected) && !memcmp(selected, b, 6));
    bssid_selector_init(&s, c);
    bssid_selector_add(&s, c); bssid_selector_add(&s, a); bssid_selector_add(&s, b);
    assert(bssid_selector_result(&s, selected) && !memcmp(selected, a, 6));
    bssid_selector_init(&s, a);
    bssid_selector_add(&s, a); bssid_selector_add(&s, a);
    assert(!bssid_selector_result(&s, selected));
    bssid_selector_init(&s, b); /* reference not present in scan */
    bssid_selector_add(&s, c); bssid_selector_add(&s, a);
    assert(bssid_selector_result(&s, selected) && !memcmp(selected, c, 6));
    return 0;
}
