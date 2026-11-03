/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Decode form-encoded UTF-8 bytes into the fixed-size ESP-IDF fields.
 * A 32-byte SSID or 64-byte hexadecimal PSK fills its field without NUL. */
bool credentials_decode(const char *ssid, const char *password,
                        uint8_t ssid_out[32], uint8_t password_out[64]);
