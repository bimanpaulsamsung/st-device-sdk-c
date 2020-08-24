/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "mbed.h"
//#include "WhdSoftAPInterface.h"
//#include "EthernetInterface.h"
//#include "lwip/apps/sntp.h"
#include "wifi.h"

#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_util.h"

#define IOT_STDK_AP_IP		"192.168.4.1"
#define IOT_STDK_AP_NETMASK	"255.255.255.0"
#define IOT_STDK_AP_GATEWAY	"192.168.4.1"
#define IOT_STDK_AP_CHANNEL	IOT_SOFT_AP_CHANNEL

static int WIFI_INITIALIZED = false;
bool ap_mode = false;
WIFI_APs_t aps;

//static void _initialize_sntp(void)
//{
//	IOT_INFO("Initializing SNTP");
//	sntp_setoperatingmode(SNTP_OPMODE_POLL);
//	sntp_setservername(0, "pool.ntp.org");
//	sntp_setservername(1, "1.kr.pool.ntp.org");
//	sntp_setservername(2, "1.asia.pool.ntp.org");
//	sntp_setservername(3, "us.pool.ntp.org");
//	sntp_setservername(4, "1.cn.pool.ntp.org");
//	sntp_setservername(5, "1.hk.pool.ntp.org");
//	sntp_setservername(6, "europe.pool.ntp.org");
//	sntp_setservername(7, "time1.google.com");
//
//	sntp_init();
//}

//static void _obtain_time(void) {
//	time_t now = 0;
//	struct tm timeinfo = { 0 };
//	int retry = 0;
//	const int retry_count = 10;
//
//	time(&now);
//	localtime_r(&now, &timeinfo);
//	IOT_INFO("DATE: (%02d-%02d-%04d %02d:%02d:02%d)", timeinfo.tm_mday,
//			timeinfo.tm_mon+1, timeinfo.tm_year+1900,
//			timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
//
//	_initialize_sntp();
//
//	while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
//		IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, retry_count);
//		IOT_DELAY(2000);
//		time(&now);
//		localtime_r(&now, &timeinfo);
//		IOT_INFO("DATE: (%02d-%02d-%04d %02d:%02d:02%d)", timeinfo.tm_mday,
//				timeinfo.tm_mon+1, timeinfo.tm_year+1900,
//				timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
//	}
//
//	if (retry < 10) {
//		IOT_INFO("[WIFI] system time updated by %ld", now);
//	}
//}

iot_error_t iot_bsp_wifi_init()
{
	if (WIFI_INITIALIZED) {
		return IOT_ERROR_NONE;
	}

	if(WIFI_Init() !=  WIFI_STATUS_OK) {
		IOT_ERROR("WiFi Initialization Failed");
		return IOT_ERROR_UNINITIALIZED;
	}

	IOT_DEBUG("ES-WIFI Initialized.");
	WIFI_INITIALIZED = true;
	return IOT_ERROR_NONE;
}

static int connect_to_ap(char *wifi_ssid, char *wifi_password,
		WIFI_Ecn_t security = WIFI_ECN_WPA2_PSK)
{
	uint8_t  IP_Addr[4];
	if( WIFI_Connect(wifi_ssid, wifi_password, security) == WIFI_STATUS_OK) {
		IOT_INFO("es-wifi module connected");

		if(WIFI_GetIP_Address(IP_Addr) == WIFI_STATUS_OK) {
			IOT_INFO("es-wifi module got IP Address : %d.%d.%d.%d",
					IP_Addr[0],
					IP_Addr[1],
					IP_Addr[2],
					IP_Addr[3]);
		} else {
			IOT_ERROR("es-wifi module CANNOT get IP address");
			return -1;
		}
	} else {
		IOT_ERROR("es-wifi module NOT connected");
		return -1;
	}
	return 0;
}

static int start_ap(char *wifi_ssid, char *wifi_password,
		WIFI_Ecn_t security = WIFI_ECN_WPA2_PSK)
{
	if (ap_mode) {
		IOT_WARN("AP mode Already UP");
		return 0;
	}

	IOT_INFO("Starting AP...");
	if (WIFI_ConfigureAP((uint8_t *)wifi_ssid, (uint8_t *)wifi_password,
			security, IOT_STDK_AP_CHANNEL, 1) == WIFI_STATUS_OK) {
		IOT_INFO("> AP Started.\n");
	} else {
		IOT_ERROR("> ERROR : CANNOT Start AP\n");
		return -1;
	}

	ap_mode = true;
	IOT_INFO("AP started successfully");
	return 0;
}

static int stop_ap(void)
{
	if (WIFI_StopAP() == WIFI_STATUS_OK) {
		IOT_INFO("AP Stopped successfully");
	} else {
		IOT_INFO("Failed to Stop AP");
	}

	ap_mode = false;
	IOT_INFO("AP Stopped successfully");
	return 0;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	IOT_INFO("CODE FLOW");
	if (!conf)
		return IOT_ERROR_INVALID_ARGS;
	IOT_INFO("CODE FLOW");
	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF: {
		IOT_INFO("CODE FLOW");
		stop_ap();
		break;
	}
	case IOT_WIFI_MODE_SCAN: {
		IOT_INFO("SCAN in Mode: %s", ap_mode ? "AP Mode" : "STA Mode");
		IOT_INFO("Scan:");
		if (WIFI_ListAccessPoints(&aps, IOT_WIFI_MAX_SCAN_RESULT) == WIFI_STATUS_OK) {
			for (int i = 0; i < aps.count; i++) {
				IOT_INFO("#AP : %s", aps.ap[i].SSID);
			}
		} else {
			IOT_ERROR("scan() failed");
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}
		IOT_INFO("CODE FLOW");
		break;
	}
	case IOT_WIFI_MODE_STATION: {
		stop_ap();

		IOT_INFO("Start STA mode");
		if (connect_to_ap(conf->ssid, conf->pass) < 0) {
			IOT_ERROR("Could not connect to %s", conf->ssid);
			return IOT_ERROR_CONN_CONNECT_FAIL;
		}

		IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
//		_obtain_time();
		break;
	}
	case IOT_WIFI_MODE_SOFTAP: {
		IOT_INFO("CODE FLOW");
		if (start_ap(conf->ssid, conf->pass) < 0)
			return IOT_ERROR_CONN_OPERATE_FAIL;

		break;
	}
	default:
		IOT_ERROR("iot bsp wifi can't support this mode = %d", conf->mode);
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	return IOT_ERROR_NONE;
}


//static WIFI_Ecn_t nsapi_security_to_ecn(nsapi_security_t sec)
//{
//	switch (sec) {
//	case NSAPI_SECURITY_NONE:
//		return WIFI_ECN_OPEN;
//	case NSAPI_SECURITY_WEP:
//		return WIFI_ECN_WEP;
//	case NSAPI_SECURITY_WPA:
//		return WIFI_ECN_WPA_PSK;
//	case NSAPI_SECURITY_WPA2:
//		return WIFI_ECN_WPA2_PSK;
//	case NSAPI_SECURITY_WPA_WPA2:
//		return WIFI_ECN_WPA_WPA2_PSK;
//	default:
//		return WIFI_ECN_OPEN; /* TODO: Figure out other values */
//	}
//}

static iot_wifi_auth_mode_t get_security_from_ecn(WIFI_Ecn_t sec) {
	switch (sec) {
	case WIFI_ECN_OPEN:
		return IOT_WIFI_AUTH_OPEN;
	case WIFI_ECN_WEP:
		return IOT_WIFI_AUTH_WEP;
	case WIFI_ECN_WPA_PSK:
		return IOT_WIFI_AUTH_WPA_PSK;
	case WIFI_ECN_WPA2_PSK:
		return IOT_WIFI_AUTH_WPA2_PSK;
	case WIFI_ECN_WPA_WPA2_PSK:
		return IOT_WIFI_AUTH_WPA_WPA2_PSK;
	default:
		return IOT_WIFI_AUTH_MAX;
	}
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	int count = 0;

	if (!scan_result) {
		IOT_ERROR("ERROR: Invalid Parameter");
		return 0;
	}

	IOT_INFO("Scan:");

	if (WIFI_ListAccessPoints(&aps, IOT_WIFI_MAX_SCAN_RESULT) == WIFI_STATUS_OK) {
		for (int i = 0; i < aps.count; i++) {
			IOT_INFO("#AP : %s", aps.ap[i].SSID);
		}
	} else {
		IOT_ERROR("scan() failed");
		return 0;
	}

	count = aps.count;

	for (int i = 0; i < count; i++) {
		WIFI_AP_t ap = aps.ap[i];
		IOT_DEBUG("Network: %s secured: %d RSSI: %hhd Ch: %hhd", ap.SSID,
				ap.Ecn, ap.RSSI, ap.Channel);

		memcpy(scan_result[i].ssid, ap.SSID, strlen(ap.SSID));
		/* TODO: Get BSSID */
//		const uint8_t *ap_mac = ap[i].get_bssid();
//		scan_result[i].bssid[0] = ap_mac[0];
//		scan_result[i].bssid[1] = ap_mac[1];
//		scan_result[i].bssid[2] = ap_mac[2];
//		scan_result[i].bssid[3] = ap_mac[3];
//		scan_result[i].bssid[4] = ap_mac[4];
//		scan_result[i].bssid[5] = ap_mac[5];

		scan_result[i].rssi = ap.RSSI;
		scan_result[i].freq = iot_util_convert_channel_freq(ap.Channel);
		scan_result[i].authmode = get_security_from_ecn(ap.Ecn);
	}
	IOT_INFO("%d networks available.", count);

	return count;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac) {
	uint8_t  MAC_Addr[6];

	if (!wifi_mac)
		return IOT_ERROR_INVALID_ARGS;

	if (WIFI_GetMAC_Address(MAC_Addr) == WIFI_STATUS_OK) {
		IOT_INFO("es-wifi module MAC Address : %X:%X:%X:%X:%X:%X",
				MAC_Addr[0], MAC_Addr[1], MAC_Addr[2], MAC_Addr[3],
				MAC_Addr[4], MAC_Addr[5]);
	} else {
		IOT_ERROR("> ERROR : CANNOT get MAC address");
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	for (int i = 0; i < IOT_WIFI_MAX_BSSID_LEN; i++) {
		wifi_mac->addr[i] = MAC_Addr[i];
	}

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
