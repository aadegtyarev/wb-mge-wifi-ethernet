#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker run --rm -e HOME=/tmp -v "$PWD:/project" -w /project espressif/idf:v5.5.2 \
  bash -eu -c '
    gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
      -I main tests/packet_validation_test.c -o /tmp/packet-validation-test
    /tmp/packet-validation-test
    gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
      -I main tests/frame_bridge_test.c main/frame_bridge.c -o /tmp/frame-bridge-test
    /tmp/frame-bridge-test
    gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
      -I main tests/bssid_selector_test.c main/bssid_selector.c -o /tmp/bssid-selector-test
    /tmp/bssid-selector-test
    gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
      -I main tests/credentials_test.c main/credentials.c -o /tmp/credentials-test
    /tmp/credentials-test
    idf.py build
  '
