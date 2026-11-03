/* SPDX-FileCopyrightText: 2023-2024 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 * Modified for WB-MGE: credentials via POST on a temporary setup network.
 */
#include <string.h>
#include <stdlib.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_http_server.h"
#include "dns_server.h"
#include "credentials.h"

static const char *TAG = "wifi_setup";
static httpd_handle_t s_web_server;
static EventGroupHandle_t *s_flags;
static int s_success_bit;

bool is_provisioned(void)
{
    wifi_config_t cfg = {0};
    return esp_wifi_get_config(WIFI_IF_STA, &cfg) == ESP_OK && cfg.sta.ssid[0] != 0;
}

static void wipe(void *buffer, size_t length)
{
    volatile unsigned char *p = buffer;
    while (length--) *p++ = 0;
}

static esp_err_t page_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req,
        "<!doctype html><meta name=viewport content='width=device-width'>"
        "<h1>WB-MGE: Wi-Fi setup</h1>"
        "<p>Warning: setup Wi-Fi and HTTP are open and unencrypted. "
        "Anyone nearby could access settings or intercept your password.</p>"
        "<form action=/ method=post>SSID <input name=ssid maxlength=32 required><br>"
        "Password <input name=password type=password maxlength=64><br>"
        "<button>Save and connect</button></form>");
}

static esp_err_t page_post(httpd_req_t *req)
{
    if (req->content_len <= 0 || req->content_len > 512) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request size");
    }
    char body[513];
    size_t used = 0;
    while (used < req->content_len) {
        int n = httpd_req_recv(req, body + used, req->content_len - used);
        if (n <= 0) {
            wipe(body, sizeof(body));
            return ESP_FAIL;
        }
        used += n;
    }
    body[used] = 0;
    char ssid[100] = {0}, password[200] = {0};
    wifi_config_t cfg = {0};
    if (httpd_query_key_value(body, "ssid", ssid, sizeof(ssid)) != ESP_OK ||
        httpd_query_key_value(body, "password", password, sizeof(password)) != ESP_OK ||
        !credentials_decode(ssid, password, cfg.sta.ssid, cfg.sta.password)) {
        wipe(body, sizeof(body));
        wipe(password, sizeof(password));
        wipe(&cfg, sizeof(cfg));
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid SSID or password");
    }
    wipe(body, sizeof(body));
    wipe(password, sizeof(password));
    esp_err_t err = esp_wifi_set_storage(WIFI_STORAGE_FLASH);
    if (err == ESP_OK) err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    wipe(&cfg, sizeof(cfg));
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Cannot save settings");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t result = httpd_resp_sendstr(req, "Saved. Reconnecting; renew the computer's DHCP lease.");
    if (s_flags) xEventGroupSetBits(*s_flags, s_success_bit);
    return result;
}

static const httpd_uri_t root_get = { .uri = "/", .method = HTTP_GET, .handler = page_get };
static const httpd_uri_t root_post = { .uri = "/", .method = HTTP_POST, .handler = page_post };

esp_err_t start_provisioning(EventGroupHandle_t *flags, int success_bit, int fail_bit)
{
    (void)fail_bit;
    s_flags = flags;
    s_success_bit = success_bit;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = 3;
    config.lru_purge_enable = true;
    esp_err_t err = httpd_start(&s_web_server, &config);
    if (err != ESP_OK) return err;
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_web_server, &root_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_web_server, &root_post));
    dns_server_config_t dns = DNS_SERVER_CONFIG_SINGLE("wifi.settings", "WIFI_AP_DEF");
    start_dns_server(&dns);
    ESP_LOGI(TAG, "Setup via temporary Wi-Fi: http://192.168.4.1/ (HTTP is unencrypted)");
    return ESP_OK;
}
