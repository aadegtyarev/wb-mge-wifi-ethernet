/* SPDX-License-Identifier: MIT */
#include "indicators.h"
#include <stdatomic.h>
#include "driver/i2c_master.h"
#include "esp_event.h"
#include "esp_eth.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* WB-MGE v3 TCA9535: P04 Wi-Fi, P05 Ethernet, P07 Status.
 * P06 is Vout and P10 controls MIO: do not drive either. */
#define LED_WIFI (1u << 4)
#define LED_ETH (1u << 5)
#define LED_STATUS (1u << 7)
#define LED_MASK (LED_WIFI | LED_ETH | LED_STATUS)
static i2c_master_dev_handle_t dev;
static atomic_bool wifi_up, wifi_running, eth_up, in_setup, switching;
static const char *TAG = "indicators";

static esp_err_t read_reg(uint8_t reg, uint8_t *v)
{
    return i2c_master_transmit_receive(dev, &reg, 1, v, 1, 100);
}
static esp_err_t write_reg(uint8_t reg, uint8_t value)
{
    uint8_t data[2] = {reg, value};
    return i2c_master_transmit(dev, data, sizeof(data), 100);
}
static void events(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) wifi_running = true;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_STOP) { wifi_running = false; wifi_up = false; }
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) wifi_up = true;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) wifi_up = false;
    if (base == ETH_EVENT && id == ETHERNET_EVENT_CONNECTED) eth_up = true;
    if (base == ETH_EVENT && id == ETHERNET_EVENT_DISCONNECTED) eth_up = false;
}
static void led_task(void *arg)
{
    (void)arg;
    unsigned tick = 0;
    uint8_t output, config, config1;
    if (read_reg(2, &output) != ESP_OK || read_reg(6, &config) != ESP_OK ||
        read_reg(7, &config1) != ESP_OK) goto fail;
    output = (output | LED_WIFI | LED_ETH) & ~LED_STATUS;
    /* P06 and P10 were mistakenly driven by the preceding experimental version.
     * Return them to power-on input/Hi-Z, not an actively driven state. */
    if (write_reg(2, output) != ESP_OK ||
        write_reg(6, (config | (1u << 6)) & ~LED_MASK) != ESP_OK ||
        write_reg(7, config1 | 1u) != ESP_OK) goto fail;
    for (;;) {
        bool blink = (tick & 1) != 0;
        bool status = in_setup ? blink : ((tick / 4) & 1);
        bool wifi = !in_setup && wifi_running && (switching ? blink : (wifi_up || blink));
        uint8_t next = output | LED_WIFI | LED_ETH;
        if (wifi) next &= ~LED_WIFI;
        if (eth_up) next &= ~LED_ETH;
        if (status) next |= LED_STATUS; else next &= ~LED_STATUS;
        if (next != output && write_reg(2, next) == ESP_OK) output = next;
        ++tick;
        vTaskDelay(pdMS_TO_TICKS(250));
    }
fail:
    ESP_LOGW(TAG, "LED expander unavailable; continuing without indicators");
    vTaskDelete(NULL);
}
void indicators_set_setup(bool setup_mode) { in_setup = setup_mode; }
void indicators_set_switching(bool active) { switching = active; }
void indicators_start(bool setup_mode)
{
    in_setup = setup_mode;
    i2c_master_bus_handle_t bus;
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = I2C_NUM_0, .sda_io_num = 32, .scl_io_num = 33,
        .clk_source = I2C_CLK_SRC_DEFAULT, .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7, .device_address = 0x20, .scl_speed_hz = 100000,
    };
    if (i2c_new_master_bus(&bus_cfg, &bus) != ESP_OK || i2c_master_bus_add_device(bus, &dev_cfg, &dev) != ESP_OK) {
        ESP_LOGW(TAG, "Cannot initialize LED expander");
        return;
    }
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, events, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, events, NULL));
    if (xTaskCreate(led_task, "leds", 3072, NULL, 2, NULL) != pdPASS) ESP_LOGW(TAG, "Cannot start LED task");
}
