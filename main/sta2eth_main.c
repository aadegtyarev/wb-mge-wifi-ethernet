/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <esp_timer.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_private/wifi.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "provisioning.h"
#include "wired_iface.h"
#include "indicators.h"
#include "bssid_selector.h"

static const char *TAG = "example_sta2wired";

static EventGroupHandle_t s_event_flags;
static atomic_bool s_wifi_is_connected;
static uint8_t s_sta_mac[6];

static void diagnostics_task(void *arg)
{
    (void)arg;
    for (;;) {
        wifi_ap_record_t ap;
        if (atomic_load(&s_wifi_is_connected) && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            ESP_LOGI(TAG, "Wi-Fi signal: %d dBm", ap.rssi);
        }
        vTaskDelay(pdMS_TO_TICKS(30000));
    }
}

const int CONNECTED_BIT = BIT0;
const int DISCONNECTED_BIT = BIT1;
const int RECONFIGURE_BIT = BIT2;
const int PROV_SUCCESS_BIT = BIT3;
const int PROV_FAIL_BIT = BIT4;
const int SWITCH_AP_BIT = BIT5;

static void switch_ap_task(void *arg)
{
    (void)arg;
    for (;;) {
        xEventGroupWaitBits(s_event_flags, SWITCH_AP_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
        TickType_t started = xTaskGetTickCount();
        indicators_set_switching(true);
        wifi_config_t cfg = {0};
        if (esp_wifi_get_config(WIFI_IF_STA, &cfg) != ESP_OK) goto done;
        uint8_t ssid[33] = {0};
        memcpy(ssid, cfg.sta.ssid, 32);
        wifi_scan_config_t scan = { .ssid = ssid, .show_hidden = true };
        if (esp_wifi_scan_start(&scan, true) != ESP_OK) {
            ESP_LOGW(TAG, "Could not scan access points");
            goto done;
        }
        uint16_t count = 0;
        if (esp_wifi_scan_get_ap_num(&count) != ESP_OK || !count) goto done;
        if (count > 32) count = 32;
        wifi_ap_record_t *aps = calloc(count, sizeof(*aps));
        if (!aps) goto done;
        if (esp_wifi_scan_get_ap_records(&count, aps) != ESP_OK) { free(aps); goto done; }
        wifi_ap_record_t current = {0};
        bool have_current = esp_wifi_sta_get_ap_info(&current) == ESP_OK;
        const uint8_t *reference = have_current ? current.bssid : (cfg.sta.bssid_set ? cfg.sta.bssid : NULL);
        bssid_selector_t selector;
        bssid_selector_init(&selector, reference);
        for (int i = 0; i < count; ++i) {
            if (strncmp((const char *)aps[i].ssid, (const char *)ssid, 32) == 0)
                bssid_selector_add(&selector, aps[i].bssid);
        }
        uint8_t next[6];
        if (bssid_selector_result(&selector, next)) {
            memcpy(cfg.sta.bssid, next, 6);
            cfg.sta.bssid_set = true;
            cfg.sta.channel = 0;
            ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
            esp_err_t ret = esp_wifi_set_config(WIFI_IF_STA, &cfg);
            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "Switching Wi-Fi BSSID to " MACSTR, MAC2STR(cfg.sta.bssid));
                esp_err_t disconnect_result = esp_wifi_disconnect();
                if (disconnect_result == ESP_ERR_WIFI_NOT_CONNECT) esp_wifi_connect();
            } else ESP_LOGW(TAG, "Could not select AP: %s", esp_err_to_name(ret));
        } else ESP_LOGI(TAG, "No other access point with this SSID found");
        free(aps);
    done:
        /* Keep the scan/switch signal visible even if the scan fails quickly. */
        TickType_t elapsed = xTaskGetTickCount() - started;
        TickType_t minimum = pdMS_TO_TICKS(2000);
        if (elapsed < minimum) vTaskDelay(minimum - elapsed);
        indicators_set_switching(false);
    }
}

/**
 * WiFi -- Wired packet path
 */
static esp_err_t wired_recv_callback(void *buffer, uint16_t len, void *ctx)
{
    if (atomic_load(&s_wifi_is_connected)) {
        mac_spoof(FROM_WIRED, buffer, len, s_sta_mac);
        if (esp_wifi_internal_tx(ESP_IF_WIFI_STA, buffer, len) != ESP_OK) {
            ESP_LOGD(TAG, "Failed to send packet to WiFi!");
        }
    }
    return ESP_OK;
}

static void wifi_buff_free(void *buffer, void *ctx)
{
    esp_wifi_internal_free_rx_buffer(buffer);
}

static esp_err_t wifi_recv_callback(void *buffer, uint16_t len, void *eb)
{
    mac_spoof(TO_WIRED, buffer, len, s_sta_mac);
    if (wired_send(buffer, len, eb) != ESP_OK) {
        esp_wifi_internal_free_rx_buffer(eb);
        ESP_LOGD(TAG, "Failed to send packet to Ethernet");
    }
    return ESP_OK;
}

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data)
{
    static unsigned retries;
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Wi-Fi STA disconnected");
        atomic_store(&s_wifi_is_connected, false);
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, NULL);
        if (++retries >= 5) {
            wifi_config_t cfg = {0};
            if (esp_wifi_get_config(WIFI_IF_STA, &cfg) == ESP_OK && cfg.sta.bssid_set) {
                cfg.sta.bssid_set = false;
                cfg.sta.channel = 0;
                if (esp_wifi_set_config(WIFI_IF_STA, &cfg) == ESP_OK)
                    ESP_LOGW(TAG, "Selected AP unavailable; falling back to any AP with configured SSID");
            }
            retries = 0;
        }
        esp_wifi_connect();

        xEventGroupClearBits(s_event_flags, CONNECTED_BIT);
        xEventGroupSetBits(s_event_flags, DISCONNECTED_BIT);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG, "Wi-Fi STA connected");
        retries = 0;
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, wifi_recv_callback);
        atomic_store(&s_wifi_is_connected, true);
        xEventGroupClearBits(s_event_flags, DISCONNECTED_BIT);
        xEventGroupSetBits(s_event_flags, CONNECTED_BIT);
    }
}

static esp_err_t connect_wifi(void)
{
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    // Do not enter setup just because the router is slow or temporarily offline.
    // The disconnect handler continues reconnecting until the user requests setup.
    return esp_wifi_connect();
}

/**
 * GPIO button functionality
 */
#define GPIO_INPUT          CONFIG_EXAMPLE_RECONFIGURE_BUTTON
#define GPIO_LONG_PUSH_US   2000000  /* push for 2 seconds to reconfigure */

static void IRAM_ATTR gpio_isr_handler(void *arg)
{
    static int64_t last_pushed = -1;
    if (gpio_get_level(GPIO_INPUT) == 0) {
        last_pushed = esp_timer_get_time();
    } else {
        uint64_t now = esp_timer_get_time();
        if (last_pushed != -1 && now - last_pushed > GPIO_LONG_PUSH_US) {
            BaseType_t high_task_wakeup = pdFALSE;
            xEventGroupSetBitsFromISR(s_event_flags, RECONFIGURE_BIT, &high_task_wakeup);
            if (high_task_wakeup) {
                portYIELD_FROM_ISR();
            }
        } else if (last_pushed != -1 && now - last_pushed > 60000) {
            BaseType_t high_task_wakeup = pdFALSE;
            xEventGroupSetBitsFromISR(s_event_flags, SWITCH_AP_BIT, &high_task_wakeup);
            if (high_task_wakeup) portYIELD_FROM_ISR();
        }
        last_pushed = -1;
    }
}

static void gpio_init(void)
{
    gpio_config_t io_conf = { .intr_type = GPIO_INTR_ANYEDGE,
                              .pin_bit_mask = (1ULL << GPIO_INPUT),
                              .mode = GPIO_MODE_INPUT,
                              .pull_up_en = 0 /* GPIO34 is input-only, with no internal pull-up */
                            };
    ESP_ERROR_CHECK(gpio_config(&io_conf));
    ESP_ERROR_CHECK(gpio_install_isr_service(0));
    ESP_ERROR_CHECK(gpio_isr_handler_add(GPIO_INPUT, gpio_isr_handler, NULL));
}

/**
 * Application
 */
void app_main(void)
{
    static __NOINIT_ATTR uint32_t s_reconfigure_requested;
    static const uint32_t RECONFIGURE_REQUEST = 0x1C55AA;

    /* Check reset reason and decide if we should re-provision */
    bool do_provision = false;
    esp_reset_reason_t reason = esp_reset_reason();
    ESP_LOGD(TAG, "After restart! %d", reason);
    if (reason != ESP_RST_SW) {
        s_reconfigure_requested = 0;
    } else if (s_reconfigure_requested == RECONFIGURE_REQUEST) {
        do_provision = true;
    }

    /* Initialize NVS and WiFi */
    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Cannot initialize NVS; refusing to erase saved settings automatically");
        ESP_ERROR_CHECK(ret);
    }
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // init the flags and event loop
    s_event_flags = xEventGroupCreate();
    if (!s_event_flags) {
        ESP_LOGE(TAG, "Cannot allocate event group");
        abort();
    }
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    if (xTaskCreate(diagnostics_task, "diagnostics", 3072, NULL, 3, NULL) != pdPASS)
        ESP_LOGW(TAG, "Cannot start diagnostics task");

    /* Init the re-provisioning button (long-press with initiate provisioning restart) */
    gpio_init();
    ESP_ERROR_CHECK(esp_read_mac(s_sta_mac, ESP_MAC_WIFI_STA));

    /* Start the application in configuration mode (to perform provisioning)
     * or in a bridge mode (already provisioned) */
    bool previously_configured = is_provisioned();
    bool setup_mode = do_provision || !previously_configured;
    indicators_start(setup_mode);
    if (setup_mode) {
        ESP_LOGI(TAG, "Starting provisioning");
        ESP_ERROR_CHECK(esp_netif_init());
        if (!esp_netif_create_default_wifi_sta() || !esp_netif_create_default_wifi_ap()) {
            ESP_LOGE(TAG, "Cannot create Wi-Fi setup interfaces");
            abort();
        }
        uint8_t mac[6];
        ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP));
        wifi_config_t ap = {0};
        snprintf((char *)ap.ap.ssid, sizeof(ap.ap.ssid), "MGE-Setup-%02X%02X%02X", mac[3], mac[4], mac[5]);
        ap.ap.ssid_len = strlen((const char *)ap.ap.ssid);
        ap.ap.channel = 1;
        ap.ap.max_connection = 2;
        ap.ap.authmode = WIFI_AUTH_OPEN;
        ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
        ESP_ERROR_CHECK(esp_wifi_start());
        ESP_LOGW(TAG, "Open setup Wi-Fi: %s (expires after 5 minutes)", ap.ap.ssid);
        ESP_ERROR_CHECK(start_provisioning(&s_event_flags, PROV_SUCCESS_BIT, PROV_FAIL_BIT));
    } else {
        ESP_LOGI(TAG, "Starting Ethernet-WiFi bridge");
        if (xTaskCreate(switch_ap_task, "switch_ap", 4096, NULL, 3, NULL) != pdPASS) {
            ESP_LOGE(TAG, "Cannot start AP switching task");
        }
        ESP_ERROR_CHECK(wired_bridge_init(wired_recv_callback, wifi_buff_free));
        ESP_ERROR_CHECK(connect_wifi());
    }

    EventBits_t bits = xEventGroupWaitBits(s_event_flags, RECONFIGURE_BIT | PROV_SUCCESS_BIT | PROV_FAIL_BIT, pdTRUE, pdFALSE,
                                            setup_mode ? pdMS_TO_TICKS(300000) : portMAX_DELAY);
    if (!(bits & (RECONFIGURE_BIT | PROV_SUCCESS_BIT | PROV_FAIL_BIT))) {
        ESP_LOGW(TAG, "Setup timed out; stopping open access point");
        indicators_set_setup(false);
        ESP_ERROR_CHECK(esp_wifi_stop());
        if (previously_configured) {
            s_reconfigure_requested = 0;
            esp_restart();
        }
        bits = xEventGroupWaitBits(s_event_flags, RECONFIGURE_BIT | PROV_SUCCESS_BIT | PROV_FAIL_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
    }
    if (bits & RECONFIGURE_BIT || bits & PROV_FAIL_BIT) {
        // retry provisioning if it previously failed or if requested by the button press
        s_reconfigure_requested = RECONFIGURE_REQUEST;
    } else {
        // provisioning successfully finished, restart to the bridge mode
        s_reconfigure_requested = 0;
    }

    vTaskDelay(pdMS_TO_TICKS(1000));    // to let httpd handle the closure
    esp_restart();
}
