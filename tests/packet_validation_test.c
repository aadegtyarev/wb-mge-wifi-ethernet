#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "packet_validation.h"

int main(void)
{
    uint8_t frame[320] = {0};
    uint8_t *ip = frame + 14;
    ip[0] = 0x45;
    ip[2] = 1; ip[3] = 15; /* 271: IP + UDP + 243 bytes DHCP */
    ip[9] = 17;
    ip[24] = 0; ip[25] = 251;
    assert(valid_dhcp_ipv4(ip, sizeof(frame)));
    assert(valid_dhcp_ipv4(ip, 285));
    assert(!valid_dhcp_ipv4(ip, 284));
    ip[0] = 0x46; assert(!valid_dhcp_ipv4(ip, sizeof(frame))); ip[0] = 0x45;
    ip[6] = 0x20; assert(!valid_dhcp_ipv4(ip, sizeof(frame))); ip[6] = 0;
    ip[7] = 1; assert(!valid_dhcp_ipv4(ip, sizeof(frame))); ip[7] = 0;
    ip[9] = 6; assert(!valid_dhcp_ipv4(ip, sizeof(frame))); ip[9] = 17;
    ip[3] = 255; assert(!valid_dhcp_ipv4(ip, sizeof(frame))); ip[3] = 15;
    ip[25] = 250; assert(!valid_dhcp_ipv4(ip, sizeof(frame)));

    uint8_t options[] = {0x63, 0x82, 0x53, 0x63, 0, 12, 2, 'p', 'c', 53, 1, 1, 61, 7, 1, 2, 3, 4, 5, 6, 7, 255};
    uint8_t *end = options + sizeof(options);
    assert(dhcp_find_option(options, end, 53, 1) == options + 11);
    assert(dhcp_find_option(options, end, 61, 7) == options + 14);
    assert(dhcp_find_option(options, end, 53, 2) == NULL);
    assert(dhcp_find_option(options, options + 13, 61, 7) == NULL);
    assert(dhcp_find_option(options, options + 2, 53, 1) == NULL);
    options[0] = 0;
    assert(dhcp_find_option(options, end, 53, 1) == NULL);
    options[0] = 0x63;
    options[6] = 255;
    assert(dhcp_find_option(options, end, 53, 1) == NULL);
    return 0;
}
