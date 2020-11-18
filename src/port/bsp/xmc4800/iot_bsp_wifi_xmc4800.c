/******************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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
#include <string.h>
#include "iot_bsp_wifi.h"
#include "iot_debug.h"
#include "esp/esp.h"
#include <sys/time.h>
#include <time.h>

#define ESP_BLOCKING_CMD        (1)
#define ESP_NO_BLOCKING_CMD     (0)
#define ESP_SCAN_AP_SSID_LEN    (21)

enum e_wifi_init_status {
	E_WIFI_UNINIT = 0,
	E_WIFI_INIT,
};

enum e_wifi_role {
	E_WIFI_ROLE_NONE = 0,
	E_WIFI_ROLE_STA,
	E_WIFI_ROLE_AP,
};

static enum e_wifi_init_status wifi_init_status = E_WIFI_UNINIT;
static enum e_wifi_role wifi_role = E_WIFI_ROLE_NONE;

static espr_t esp_callback_func(esp_cb_t* cb)
{
	switch (cb->type) {
	case ESP_CB_INIT_FINISH: {
		IOT_INFO("Library initialized!");
		break;
	}

	case ESP_CB_RESET_FINISH: {
		IOT_INFO("Device reset sequence finished!");
		break;
	}

	case ESP_CB_RESET: {
		IOT_INFO("Device reset detected!");
		break;
	}

	case ESP_CB_WIFI_CONNECTED: {
		IOT_INFO("Successful connect to AP!!!");
		break;
	}

	case ESP_CB_AP_CONNECTED_STA: {
		IOT_INFO("New station just connected to ESP's access point!!!");
		break;
	}

	case ESP_CB_AP_DISCONNECTED_STA: {
		IOT_INFO("New station just disconnected from ESP's access point!");
		break;
	}

	case ESP_CB_AP_IP_STA: {
		IOT_INFO("New station just received IP from ESP's access point!");
		break;
	}

	case ESP_CB_WIFI_DISCONNECTED: {
		IOT_INFO("Disconnected from AP!!!");
		break;
	}

	default: 
		break;
	}

	return espOK;
}

static void _obtain_time(void)
{
	struct tm now;
	esp_datetime_t dt;
	struct timeval tv;
	if (esp_sntp_configure(1, 0, "ntp2.aliyun.com", "cn.pool.ntp.org", "time1.google.com", ESP_BLOCKING_CMD) == espOK) {
		/* Try to get time from network servers */
		IOT_INFO("SNTP configure done\r\n");
		for (int i = 0; i < 10; i++) {
			esp_delay(1000);
			if (esp_sntp_gettime(&dt, ESP_BLOCKING_CMD) == espOK) {
				IOT_INFO("[%d] We have a date and time: %02d.%02d.%02d: %02d:%02d:%02d",i+1,\
						(int)dt.date, (int)dt.month, (int)dt.year,\
						(int)dt.hours, (int)dt.minutes, (int)dt.seconds);
				break;
			}
		}
		now.tm_sec = dt.seconds;
		now.tm_min = dt.minutes;
		now.tm_hour = dt.hours;
		now.tm_mday = dt.date;
		now.tm_mon = dt.month - 1;
		now.tm_year = dt.year - 1900;

		tv.tv_sec  = mktime(&now);
		tv.tv_usec = 0;
		settimeofday(&tv, NULL);
	}
}

iot_error_t iot_bsp_wifi_init(void)
{
	if (E_WIFI_INIT == wifi_init_status) {
		IOT_INFO("WiFi is already inited!");
		return IOT_ERROR_NONE;
	}

	if (esp_init(esp_callback_func, ESP_BLOCKING_CMD) != espOK) {
		IOT_ERROR("Cannot initialize LwESP!");
		return IOT_ERROR_INIT_FAIL;
	}
	IOT_INFO("LwESP initialized!");
	wifi_init_status = E_WIFI_INIT;
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	struct timeval now;
	struct tm *timeinfo;

	IOT_ERROR_CHECK(conf == NULL, IOT_ERROR_INVALID_ARGS, "param null");
	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF: {
		esp_reset(ESP_BLOCKING_CMD);
		wifi_role = E_WIFI_ROLE_NONE;
		IOT_INFO("IOT WiFi mode OFF.");
		break;
	}

	case IOT_WIFI_MODE_SCAN: {
		/* Nothing to do here. */
		IOT_INFO("IOT WiFi mode scan.");
		break;
	}

	case IOT_WIFI_MODE_STATION: {
		if (esp_set_wifi_mode(ESP_MODE_STA, ESP_BLOCKING_CMD) == espOK) {
			IOT_INFO("ESP set to STA mode");
		} else {
			IOT_ERROR("ESP set to STA mode failed");
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}

		if (esp_sta_has_ip()) {
			esp_sta_quit(1);
		}

		if (esp_sta_join((const char *)conf->ssid, (const char *)conf->pass, NULL, 0, ESP_BLOCKING_CMD)==espOK) {
			IOT_INFO("AP connected");
		} else {
			IOT_ERROR("AP connected failed");
			return IOT_ERROR_CONN_CONNECT_FAIL;
		}

		gettimeofday(&now, NULL);
		timeinfo = localtime(&now.tv_sec);
		if (timeinfo->tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}
		wifi_role = E_WIFI_ROLE_STA;
		break;
	}

	case IOT_WIFI_MODE_SOFTAP: {
		if (esp_set_wifi_mode(ESP_MODE_STA_AP, ESP_BLOCKING_CMD) == espOK) {
			IOT_INFO("ESP set to AP mode");
		} else {
			IOT_ERROR("ESP set to AP mode failed");
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}

		if (esp_ap_configure((const char *)conf->ssid, (const char *)conf->pass, 13, ESP_ECN_WPA2_PSK, 5, 0, 1, ESP_BLOCKING_CMD) == espOK) {
			IOT_INFO("Access point configured!");
		} else {
			IOT_ERROR("Cannot configure access point!");
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}
		wifi_role = E_WIFI_ROLE_AP;
		break;
	}

	default:
		IOT_ERROR("bsp cannot support this mode = %d", conf->mode);
		return IOT_ERROR_CONN_OPERATE_FAIL;
    }
    return IOT_ERROR_NONE;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	esp_ap_t APs[IOT_WIFI_MAX_SCAN_RESULT];
	size_t found_aps = 0;

	if (esp_sta_list_ap(NULL, APs, IOT_WIFI_MAX_SCAN_RESULT, &found_aps, ESP_BLOCKING_CMD) == espOK) {
		found_aps = found_aps < IOT_WIFI_MAX_SCAN_RESULT ? found_aps : IOT_WIFI_MAX_SCAN_RESULT;
		IOT_INFO("Number of found ap : %d",found_aps);
		for (int32_t i = 0; i < found_aps; ++i) {
			memcpy(scan_result[i].ssid, APs[i].ssid, ESP_SCAN_AP_SSID_LEN);
			memcpy(scan_result[i].bssid, APs[i].mac.mac, IOT_WIFI_MAX_BSSID_LEN);
			scan_result[i].rssi = APs[i].rssi;
			scan_result[i].freq = iot_util_convert_channel_freq(APs[i].ch);
			scan_result[i].authmode = APs[i].ecn;
		}
	} else {
		IOT_ERROR("Scan failed");
	}

	return (uint16_t)found_aps;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	if (wifi_role == E_WIFI_ROLE_AP) {
		esp_ap_getmac((esp_mac_t*)wifi_mac, 0, ESP_BLOCKING_CMD);
		IOT_INFO("AP mode - get mac");
	} else if (wifi_role == E_WIFI_ROLE_STA) {
		esp_sta_getmac((esp_mac_t*)wifi_mac, 0, ESP_BLOCKING_CMD);
		IOT_INFO("STA mode - get mac");
	} else {
		IOT_ERROR("Error mode");
		return IOT_ERROR_NOT_IMPLEMENTED;
	}

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
