idf_component_register(
    SRCS sta2eth_main.c ethernet_iface.c frame_bridge.c bssid_selector.c indicators.c manual_config.c credentials.c
    PRIV_REQUIRES esp_wifi esp_timer esp_eth esp_http_server nvs_flash
                  esp_driver_gpio esp_driver_i2c
    INCLUDE_DIRS ""
)
