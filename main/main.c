/* Simple HTTP + SSL Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "esp_eth.h"
#include "protocol_examples_common.h"
#include <esp_https_server.h>
#include "esp_tls.h"
#include "sdkconfig.h"
#include "nvs_flash.h"
#include "nvs.h"

/*Modified https simple server app to showcase use of NVS keys*/

#define CERT_PART_NAME "certs"
#define CERT_NAMESPACE "cert_data"
#define CERT_KEY "servercert"
#define PRIVATE_KEY "prvtkey"

char *server_cert;
uint32_t server_cert_len;
char *priv_key;
uint32_t priv_key_len;
static const char *TAG = "part_example";

/*
    Load string value from 'certs' partition
*/
uint32_t cert_get_str(nvs_handle handle, const char *key, char **value)
{
    size_t value_size;
    if (nvs_get_str(handle, key, NULL, &value_size) != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to get size of key: %s", key);
        return 0;
    }
    *value = malloc(value_size);
    if (nvs_get_str(handle, key, *value, &value_size) != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to load key: %s", key);
        return 0;
    }
    return value_size;
}

/* Get server cert and private key from certs partition*/
static void cert_get_data()
{
    esp_err_t err = nvs_flash_init_partition(CERT_PART_NAME);
    ESP_ERROR_CHECK(err);
    nvs_handle_t cert_handle;
    err = nvs_open_from_partition(CERT_PART_NAME, CERT_NAMESPACE, NVS_READONLY, &cert_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG,"Error (%s) opening NVS handle!", esp_err_to_name(err));
    }
    server_cert_len = cert_get_str(cert_handle, CERT_KEY, &server_cert);
    if (server_cert == NULL || server_cert_len==0)
    {
        ESP_LOGE(TAG,"Error! Unable to read server certificate");
    }
    priv_key_len = cert_get_str(cert_handle, PRIVATE_KEY, &priv_key);
    if (priv_key == NULL || priv_key_len == 0)
    {
        ESP_LOGE(TAG,"Error, Unable to read private key");
    }
    nvs_close(cert_handle);
    nvs_flash_deinit_partition(CERT_PART_NAME);
}

/* An HTTP GET handler */
static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, "<h1>Hello partitioned world!</h1>", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

#if CONFIG_EXAMPLE_ENABLE_HTTPS_USER_CALLBACK
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
static void print_peer_cert_info(const mbedtls_ssl_context *ssl)
{
    const mbedtls_x509_crt *cert;
    const size_t buf_size = 1024;
    char *buf = calloc(buf_size, sizeof(char));
    if (buf == NULL)
    {
        ESP_LOGE(TAG, "Out of memory - Callback execution failed!");
        return;
    }

    // Logging the peer certificate info
    cert = mbedtls_ssl_get_peer_cert(ssl);
    if (cert != NULL)
    {
        mbedtls_x509_crt_info((char *)buf, buf_size - 1, "    ", cert);
        ESP_LOGI(TAG, "Peer certificate info:\n%s", buf);
    }
    else
    {
        ESP_LOGW(TAG, "Could not obtain the peer certificate!");
    }

    free(buf);
}
#endif
/**
 * Example callback function to get the certificate of connected clients,
 * whenever a new SSL connection is created and closed
 *
 * Can also be used to other information like Socket FD, Connection state, etc.
 *
 * NOTE: This callback will not be able to obtain the client certificate if the
 * following config `Set minimum Certificate Verification mode to Optional` is
 * not enabled (enabled by default in this example).
 *
 * The config option is found here - Component config → ESP-TLS
 *
 */
static void https_server_user_callback(esp_https_server_user_cb_arg_t *user_cb)
{
    ESP_LOGI(TAG, "User callback invoked!");
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
    mbedtls_ssl_context *ssl_ctx = NULL;
#endif
    switch (user_cb->user_cb_state)
    {
    case HTTPD_SSL_USER_CB_SESS_CREATE:
        ESP_LOGD(TAG, "At session creation");

        // Logging the socket FD
        int sockfd = -1;
        esp_err_t esp_ret;
        esp_ret = esp_tls_get_conn_sockfd(user_cb->tls, &sockfd);
        if (esp_ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Error in obtaining the sockfd from tls context");
            break;
        }
        ESP_LOGI(TAG, "Socket FD: %d", sockfd);
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
        ssl_ctx = (mbedtls_ssl_context *)esp_tls_get_ssl_context(user_cb->tls);
        if (ssl_ctx == NULL)
        {
            ESP_LOGE(TAG, "Error in obtaining ssl context");
            break;
        }
        // Logging the current ciphersuite
        ESP_LOGI(TAG, "Current Ciphersuite: %s", mbedtls_ssl_get_ciphersuite(ssl_ctx));
#endif
        break;

    case HTTPD_SSL_USER_CB_SESS_CLOSE:
        ESP_LOGD(TAG, "At session close");
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
        // Logging the peer certificate
        ssl_ctx = (mbedtls_ssl_context *)esp_tls_get_ssl_context(user_cb->tls);
        if (ssl_ctx == NULL)
        {
            ESP_LOGE(TAG, "Error in obtaining ssl context");
            break;
        }
        print_peer_cert_info(ssl_ctx);
#endif
        break;
    default:
        ESP_LOGE(TAG, "Illegal state!");
        return;
    }
}
#endif

static const httpd_uri_t root = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server");

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();

    cert_get_data();

    conf.servercert = (unsigned char *)server_cert;
    conf.servercert_len = server_cert_len;
    conf.prvtkey_pem = (unsigned char *)priv_key;
    conf.prvtkey_len = priv_key_len;

#if CONFIG_EXAMPLE_ENABLE_HTTPS_USER_CALLBACK
    conf.user_cb = https_server_user_callback;
#endif
    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret)
    {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }
    // no longer needed, because it was copied over in httpd_ssl_start
    free(priv_key);
    free(server_cert);

    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");
    httpd_register_uri_handler(server, &root);
    return server;
}

static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_ssl_stop(server);
}

static void disconnect_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server)
    {
        if (stop_webserver(*server) == ESP_OK)
        {
            *server = NULL;
        }
        else
        {
            ESP_LOGE(TAG, "Failed to stop https server");
        }
    }
}

static void connect_handler(void *arg, esp_event_base_t event_base,
                            int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL)
    {
        *server = start_webserver();
    }
}

void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* Register event handlers to start server when Wi-Fi or Ethernet is connected,
     * and stop server when disconnection happens.
     */

#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
}
