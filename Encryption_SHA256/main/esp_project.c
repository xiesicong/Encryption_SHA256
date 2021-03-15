/*
    Encryption_SHA256 Example
 */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <stdio.h>
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include <stdio.h>
#include "esp_system.h"
#include "mbedtls/aes.h"
#include "mbedtls/md5.h"
#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include <string.h>
#include <stdio.h>
#include "esp_system.h"

#define LOG_TAG "Encryption_SHA256 Example"

// SHA256加密没有解密
void app_main(void)
{

	int i;
	unsigned char decrypt[32];
	const unsigned char encrypt[] = "https://blog.csdn.net/cnicfhnui";

	//Initialize NVS
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES){
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);

	printf("\n\n-------------------------------- Get Systrm Info Start------------------------------------------\n");
	//获取IDF版本
	printf("     SDK version:%s\n", esp_get_idf_version());
	//获取芯片可用内存
	printf("     esp_get_free_heap_size : %d  \n", esp_get_free_heap_size());
	//获取从未使用过的最小内存
	printf("     esp_get_minimum_free_heap_size : %d  \n", esp_get_minimum_free_heap_size());
	//获取mac地址（station模式）
	uint8_t mac[6];
	esp_read_mac(mac, ESP_MAC_WIFI_STA);
	printf("esp_read_mac(): %02x:%02x:%02x:%02x:%02x:%02x \n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	printf("\n\n-------------------------------- Get Systrm Info End------------------------------------------\n");


    // sha256/224
    printf("Sha256 encrypt str: %s\n", encrypt);
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); // 0表示传sha256 ， 1 表示传SHA-244
    mbedtls_sha256_update(&sha256_ctx, encrypt, strlen((char *)encrypt));
    mbedtls_sha256_finish(&sha256_ctx, decrypt);
    printf("Sha256 encrypt result: ");
    for (i = 0; i < 32; i++){
        printf("%02x", decrypt[i]);
    }
    mbedtls_sha256_free(&sha256_ctx);
    printf("\n");
}