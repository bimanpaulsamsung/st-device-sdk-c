/******************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#include <time.h>
#include <iot_bsp_wifi.h>
#include "iot_os_util.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "wifi_api.h"
#include "iot_debug.h"
#include "sntp.h"
#include "wifi_lwip_helper.h"
#include "wifi_nvdm_config.h"

struct wifi_scan_result {
        iot_wifi_scan_result_t *scan_result;
        int len;
};

enum e_wifi_init_status {
	e_wifi_uninit = 0,
	e_wifi_init,
};
static enum e_wifi_init_status wifi_init_status = e_wifi_uninit;
static SemaphoreHandle_t scan_ready;

static void _initialize_sntp(void)
{
        IOT_INFO("Initializing SNTP");
        sntp_setservername(0, "pool.ntp.org");
        sntp_setservername(1, "1.kr.pool.ntp.org");
        sntp_setservername(2, "1.asia.pool.ntp.org");
        sntp_setservername(3, "us.pool.ntp.org");
        sntp_setservername(4, "1.cn.pool.ntp.org");
        sntp_setservername(5, "1.hk.pool.ntp.org");
        sntp_setservername(6, "europe.pool.ntp.org");
        sntp_setservername(7, "time1.google.com");

        sntp_init();
}

static void _obtain_time(void)
{
        time_t now = 0;
        struct tm timeinfo = { 0 };
        int retry = 0;
        const int retry_count = 10;

        _initialize_sntp();

        while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
                IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, retry_count);
                IOT_DELAY(2000);
                time(&now);
                localtime_r(&now, &timeinfo);
        }

        if (retry < 10) {
                IOT_INFO("[WIFI] system time updated by %ld", now);
        }
}

#define IOT_WIFI_SSID                ("IOT_INIT_AP")
#define IOT_WIFI_PASSWORD            ("12345678")

iot_error_t iot_bsp_wifi_init()
{
	wifi_config_t config = {0};
	wifi_config_ext_t config_ext = {0};

	if(wifi_init_status == e_wifi_init) {
		IOT_INFO("wifi is already initialized, returning");
		return;
	}
#if CONFIG_INIT_NET
#if CONFIG_LWIP_LAYER
        LwIP_Init();
#endif
#endif
    config.opmode = WIFI_MODE_STA_ONLY;
    strcpy((char *)config.sta_config.ssid, IOT_WIFI_SSID);
    strcpy((char *)config.sta_config.password, IOT_WIFI_PASSWORD);
    config.sta_config.ssid_length = strlen(IOT_WIFI_SSID);
    config.sta_config.password_length = strlen(IOT_WIFI_PASSWORD);
	config_ext.sta_auto_connect = 0;

	wifi_init(&config, &config_ext);
	lwip_network_init(config.opmode);
	lwip_net_start(config.opmode);

	wifi_init_status = e_wifi_init;
	scan_ready = xSemaphoreCreateBinary();
	return IOT_ERROR_NONE;
}

iot_error_t wifi_set_sta(iot_wifi_conf *conf)
{
	uint8_t prv_op_mode = 0;
	uint8_t target_mode;
	uint8_t mismatch = 0;
	int32_t ret = 0;
	int new_conf;
    char ssid[IOT_WIFI_MAX_SSID_LEN + 1] = {0,};
    char passwd[IOT_WIFI_MAX_PASS_LEN + 1] = {0,};

	int str_len = sizeof(conf->ssid);
	memcpy(ssid, conf->ssid, str_len);
	if (str_len < IOT_WIFI_MAX_SSID_LEN)
	    ssid[str_len] = '\0';
	else
	    ssid[IOT_WIFI_MAX_SSID_LEN] = '\0';

	str_len = sizeof(conf->pass);
	memcpy(passwd, conf->pass, str_len);
	if (str_len < IOT_WIFI_MAX_PASS_LEN)
	    passwd[str_len] = '\0';
	else
	    passwd[IOT_WIFI_MAX_PASS_LEN] = '\0';

	ret = wifi_config_get_opmode(&prv_op_mode);
	if (ret < 0) {
		IOT_ERROR("MT7682 can't get curr WIFI mode");
		return ret;
	}

	if (prv_op_mode != WIFI_MODE_STA_ONLY)
		mismatch = 1;

	new_conf = wlan_check_ssid_psk(WIFI_PORT_STA, ssid, passwd, 0);

	target_mode = WIFI_MODE_STA_ONLY;

	IOT_INFO("MT7682's C/T WIFI mode:%d/%d, new_conf(%d)",prv_op_mode, target_mode, new_conf);
	if (mismatch || (new_conf != 0)) {
		IOT_INFO("WIFI mode Stop & RADIO off prv_op_mode %d", prv_op_mode);
		if (prv_op_mode == WIFI_MODE_AP_ONLY){
			ret = wlan_ap_stop();
			vTaskDelay(pdMS_TO_TICKS(500));
		}
		else if (prv_op_mode == WIFI_MODE_STA_ONLY)
			ret = wlan_sta_stop();
		else
			IOT_ERROR("Undefined WIFI prv_op_mode(%d)!!", prv_op_mode);
		if (ret != 0)
			IOT_ERROR("Failed STOP wifi mode(%d)!!",prv_op_mode);
	} else {
		wifi_config_set_radio(1);
		IOT_INFO("same WIFI mode %d, just RADIO on", conf->mode);
		return 0;
	}
	IOT_INFO("wlan sta start enter");
	ret = wlan_sta_start(ssid, passwd, 0);
	IOT_INFO("wlan sta start out");
	if (ret < 0)
		IOT_ERROR("MT7682 can't set new WIFI mode:%d", target_mode);

	return ret;
}

iot_error_t wifi_set_ap(iot_wifi_conf *conf)
{
	uint8_t prv_op_mode = 0;
	uint8_t target_mode;
	uint8_t mismatch = 0;
	int32_t ret = 0;
	int new_conf;
    char ssid[IOT_WIFI_MAX_SSID_LEN + 1] = {0,};
    char passwd[IOT_WIFI_MAX_PASS_LEN + 1] = {0,};

	int str_len = sizeof(conf->ssid);
	memcpy(ssid, conf->ssid, str_len);
	if (str_len < IOT_WIFI_MAX_SSID_LEN)
	    ssid[str_len] = '\0';
	else
	    ssid[IOT_WIFI_MAX_SSID_LEN] = '\0';

	str_len = sizeof(conf->pass);
	memcpy(passwd, conf->pass, str_len);
	if (str_len < IOT_WIFI_MAX_PASS_LEN)
	    passwd[str_len] = '\0';
	else
	    passwd[IOT_WIFI_MAX_PASS_LEN] = '\0';

	ret = wifi_config_get_opmode(&prv_op_mode);
	if (ret < 0) {
		IOT_ERROR("MT7682 can't get curr WIFI mode");
		return ret;
	}

	if (prv_op_mode != WIFI_MODE_AP_ONLY)
		mismatch = 1;

	new_conf = wlan_check_ssid_psk(WIFI_PORT_AP, ssid, passwd, 0);

	target_mode = WIFI_MODE_AP_ONLY;

	IOT_INFO("MT7682's C/T WIFI mode:%d/%d, new_conf(%d)",prv_op_mode, target_mode, new_conf);
	if (mismatch || (new_conf != 0)) {
		IOT_INFO("WIFI mode Stop & RADIO off");
		if (prv_op_mode == WIFI_MODE_AP_ONLY)
			ret = wlan_ap_stop();
		else if (prv_op_mode == WIFI_MODE_STA_ONLY)
			ret = wlan_sta_stop();
		else
			IOT_ERROR("Undefined WIFI prv_op_mode(%d)!!", prv_op_mode);
		if (ret != 0)
			IOT_ERROR("Failed STOP wifi mode(%d)!!",prv_op_mode);
	} else {
		wifi_config_set_radio(1);
		IOT_INFO("same WIFI mode %d, just RADIO on", conf->mode);
		return 0;
	}

	ret = wlan_ap_start(ssid, passwd, 6);
	if (ret < 0)
		IOT_ERROR("MT7682 can't set new WIFI mode:%d", target_mode);

	return ret;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	int32_t ret = 0;
    uint8_t prv_op_mode = 0;
    time_t now;
    struct tm timeinfo;

	if (conf == NULL) {
		IOT_ERROR("INVAL conf for set_wifi_mode");
		return -1;
	}

	switch (conf->mode) {
	case IOT_WIFI_MODE_OFF:
		ret = wifi_config_set_radio(0);
		return ret;
	case IOT_WIFI_MODE_STATION:
		wifi_set_sta(conf);
        time(&now);
        localtime_r(&now, &timeinfo);

        if (timeinfo.tm_year < (2016 - 1900)) {
                IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
                _obtain_time();
        }

		break;
	case IOT_WIFI_MODE_SCAN:
		ret = wifi_config_get_opmode(&prv_op_mode);
		if (ret < 0) {
			IOT_ERROR("MT7682 can't get curr WIFI mode");
			return ret;
		}
		if (prv_op_mode != WIFI_MODE_STA_ONLY)
		    wifi_set_sta(conf);
		break;
	case IOT_WIFI_MODE_SOFTAP:
		wifi_set_ap(conf);
		break;
	default:
		IOT_ERROR("MT7682 can't support this mode:%d", conf->mode);
		return -1;
	}
	return IOT_ERROR_NONE;
}

wifi_scan_list_item_t *scan_ap_list = NULL;
static int scan_event_handler_sample(wifi_event_t event_id, unsigned char *payload, unsigned int len)
{
    int handled = 0;
    switch (event_id) {
        case WIFI_EVENT_IOT_SCAN_COMPLETE:
            handled = 1;
            IOT_INFO("[MTK Event Callback Sample]: Scan Done!\n");
			xSemaphoreGive(scan_ready);
            break;
        default:
            handled = 0;
            IOT_INFO("[MTK Event Callback Sample]: Unknown event(%d)\n", event_id);
            break;
    }
    return handled;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	int ret = 0;
	int i = 0;
	uint16_t scan_ap_num = 0;

	if(wifi_init_status != e_wifi_init) {
		IOT_ERROR("wifi not init");
		return 0;
	}

	if (scan_ap_list != NULL) {
		free(scan_ap_list);
		scan_ap_list = NULL;
	}

	wifi_connection_scan_deinit();

	scan_ap_list = malloc(sizeof(wifi_scan_list_item_t) * IOT_WIFI_MAX_SCAN_RESULT);
	if (scan_ap_list == NULL) {
		IOT_ERROR("malloc failed");
		return 0;
	}
	memset(scan_ap_list, 0, sizeof(wifi_scan_list_item_t) * IOT_WIFI_MAX_SCAN_RESULT);

	wifi_connection_register_event_handler(WIFI_EVENT_IOT_SCAN_COMPLETE, (wifi_event_handler_t) scan_event_handler_sample);
	wifi_connection_scan_init(scan_ap_list, IOT_WIFI_MAX_SCAN_RESULT);
	ret = wifi_connection_start_scan(NULL, 0, NULL, 0, 0);
	if (ret < 0) {
		IOT_ERROR("wifi connection scan failed");
		free(scan_ap_list);
		scan_ap_list = NULL;
		return 0;
	}

	xSemaphoreTake(scan_ready, portMAX_DELAY);
	for(i = 0; i < IOT_WIFI_MAX_SCAN_RESULT; i++) {
		IOT_DEBUG("mt7286 scan ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, authmode=%d chan=%d",
			scan_ap_list[i].ssid,
			scan_ap_list[i].bssid[0], scan_ap_list[i].bssid[1], scan_ap_list[i].bssid[2],
			scan_ap_list[i].bssid[3], scan_ap_list[i].bssid[4], scan_ap_list[i].bssid[5], scan_ap_list[i].rssi,
			scan_ap_list[i].auth_mode, scan_ap_list[i].channel);

		if (scan_ap_list[i].ssid_length <= 0) {//ssid is null , skip invalid ap
			continue;
		}

		if (scan_ap_list[i].bssid[0] == 0 && scan_ap_list[i].bssid[1] == 0
			&& scan_ap_list[i].bssid[2] == 0 && scan_ap_list[i].bssid[3] == 0
			&& scan_ap_list[i].bssid[4] == 0 && scan_ap_list[i].bssid[5] == 0) { //mac addr is invalid, skip
			continue;
		}
		memcpy(scan_result[i].ssid, scan_ap_list[i].ssid, strlen((char *)scan_ap_list[i].ssid));
		memcpy(scan_result[i].bssid, scan_ap_list[i].bssid, IOT_WIFI_MAX_BSSID_LEN);

		scan_result[i].rssi = scan_ap_list[i].rssi;
		scan_result[i].freq = iot_util_convert_channel_freq(scan_ap_list[i].channel);
		scan_result[i].authmode = scan_ap_list[i].auth_mode;

		IOT_INFO("scan_ap_num %d mt7286 scan ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, authmode=%d chan=%d",
			scan_ap_num,
			scan_result[i].ssid,
			scan_result[i].bssid[0], scan_result[i].bssid[1], scan_result[i].bssid[2],
			scan_result[i].bssid[3], scan_result[i].bssid[4], scan_result[i].bssid[5], scan_result[i].rssi,
			scan_result[i].freq, scan_result[i].authmode, scan_ap_list[i].channel);
		scan_ap_num++;
	}
	free(scan_ap_list);
	scan_ap_list = NULL;
	wifi_connection_scan_deinit();
	wifi_connection_unregister_event_handler(WIFI_EVENT_IOT_SCAN_COMPLETE,scan_event_handler_sample);
	return scan_ap_num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	iot_error_t ret;
	ret = wifi_config_get_mac_address(WIFI_PORT_STA, wifi_mac->addr);
	if(ret < 0){
		IOT_ERROR("failed to read wifi mac address : %d", ret);
		return IOT_ERROR_READ_FAIL;
	}

	IOT_DEBUG("MAC:%02X-%02X-%02X-%02X-%02X-%02X",
			wifi_mac->addr[0], wifi_mac->addr[1], wifi_mac->addr[2], wifi_mac->addr[3], wifi_mac->addr[4], wifi_mac->addr[5]);
	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
