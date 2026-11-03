/* Based on ESP-IDF sta2eth, Copyright 2023-2024 Espressif Systems.
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <stdatomic.h>
#include <stdlib.h>
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "ethernet_init.h"
#include "wired_iface.h"
#include "frame_bridge.h"

static const char *TAG = "ethernet_bridge";
static esp_eth_handle_t eth;
static atomic_bool link_up;
static frame_bridge_t bridge;
static portMUX_TYPE bridge_lock = portMUX_INITIALIZER_UNLOCKED;
static wired_rx_cb_t rx_callback;
static wired_free_cb_t free_callback;

static void eth_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (id == ETHERNET_EVENT_CONNECTED) {
        atomic_store(&link_up, true);
        ESP_LOGI(TAG, "Ethernet link up");
    } else if (id == ETHERNET_EVENT_DISCONNECTED || id == ETHERNET_EVENT_STOP) {
        atomic_store(&link_up, false);
        portENTER_CRITICAL(&bridge_lock);
        bridge = (frame_bridge_t){0};
        portEXIT_CRITICAL(&bridge_lock);
        ESP_LOGI(TAG, "Ethernet link down; client state cleared");
    }
}

void mac_spoof(mac_spoof_direction_t direction, uint8_t *buffer, uint16_t len, uint8_t own_mac[6])
{
    if (!atomic_load(&link_up)) return;
    portENTER_CRITICAL(&bridge_lock);
    if (atomic_load(&link_up)) {
        frame_bridge_rewrite(&bridge, direction == FROM_WIRED ? BRIDGE_FROM_ETHERNET : BRIDGE_TO_ETHERNET,
                             buffer, len, own_mac);
    }
    portEXIT_CRITICAL(&bridge_lock);
}

static esp_err_t wired_recv(esp_eth_handle_t handle, uint8_t *buffer, uint32_t len, void *priv)
{
    (void)handle; (void)priv;
    esp_err_t ret = len <= UINT16_MAX ? rx_callback(buffer, (uint16_t)len, buffer) : ESP_ERR_INVALID_SIZE;
    free(buffer);
    return ret;
}

esp_err_t wired_bridge_init(wired_rx_cb_t rx_cb, wired_free_cb_t free_cb)
{
    uint8_t count = 0;
    esp_eth_handle_t *handles = NULL;
    ESP_ERROR_CHECK(example_eth_init(&handles, &count));
    if (!handles || !count) { free(handles); return ESP_ERR_NOT_FOUND; }
    if (count > 1) ESP_LOGW(TAG, "Only the first Ethernet interface is used");
    eth = handles[0];
    free(handles);
    rx_callback = rx_cb;
    free_callback = free_cb;
    ESP_ERROR_CHECK(esp_eth_update_input_path(eth, wired_recv, NULL));
    bool promiscuous = true;
    ESP_ERROR_CHECK(esp_eth_ioctl(eth, ETH_CMD_S_PROMISCUOUS, &promiscuous));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, eth_event_handler, NULL));
    return esp_eth_start(eth);
}

esp_err_t wired_send(void *buffer, uint16_t len, void *free_arg)
{
    if (!atomic_load(&link_up)) return ESP_ERR_INVALID_STATE;
    esp_err_t ret = esp_eth_transmit(eth, buffer, len);
    if (ret == ESP_OK && free_callback) free_callback(free_arg, NULL);
    return ret;
}
