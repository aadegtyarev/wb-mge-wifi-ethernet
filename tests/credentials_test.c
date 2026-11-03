/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "credentials.h"

int main(void)
{
    uint8_t ssid[32], pass[64];
    assert(credentials_decode("My+Wi%2DFi", "test%2Bpassword", ssid, pass));
    assert(!strcmp((char *)ssid, "My Wi-Fi"));
    assert(!strcmp((char *)pass, "test+password"));
    assert(credentials_decode("open", "", ssid, pass) && !pass[0]);
    assert(!credentials_decode("", "password", ssid, pass));
    assert(!credentials_decode("net%00x", "password", ssid, pass));
    assert(!credentials_decode("net%", "password", ssid, pass));
    assert(!credentials_decode("net%Q0", "password", ssid, pass));
    assert(!credentials_decode("net", "1234567", ssid, pass));
    assert(credentials_decode("12345678901234567890123456789012", "password", ssid, pass));
    assert(!memcmp(ssid, "12345678901234567890123456789012", 32));
    assert(!credentials_decode("123456789012345678901234567890123", "password", ssid, pass));
    assert(credentials_decode("net", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ssid, pass));
    assert(!credentials_decode("net", "z123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ssid, pass));
    assert(!credentials_decode("net", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", ssid, pass));
    assert(!credentials_decode(NULL, "password", ssid, pass));
    return 0;
}
