/******************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "FreeRTOS.h"
#include <time.h>
#include "iot_wifi.h"
#include "qcom_api.h"
#include "iot_bsp_system.h"
#include "nxp_socket.h"

#define DHCP_SERVER_IP		0xC0A80401  //"192.168.4.1"
#define DHCP_CLIENT_IP		0xC0A80402  //"192.168.4.2"
#define DHCP_CLIENT_MAX_IP	0xC0A80410
#define TIME_STR_LEN 		32
#define SNTP_TIME_TRY_MAX	10
#define NXP_MAX_WIFI_SCAN	10

static int WIFI_INITIALIZED = 0;
static int last_scan_count;

static void _obtain_time(void)
{
	int retry = 0;
	tSntpTime sntp_time;
	tSntpTM sntp_tm;
	time_t now_sec = 0;
	char time_str[TIME_STR_LEN] = {0, };

	// 1 - start, 2 - stop
	qcom_enable_sntp_client(1);

	// 1-add, 2-delete
	qcom_sntp_srvr_addr(1, "pool.ntp.org");
	qcom_sntp_srvr_addr(1, "time1.google.com");
	qcom_sntp_srvr_addr(1, "1.kr.pool.ntp.org");
	qcom_sntp_srvr_addr(1, "1.asia.pool.ntp.org");

	//device id 0
	memset(&sntp_time, 0, sizeof(sntp_time));
	qcom_sntp_get_time(0, &sntp_time);

	while (sntp_time.year < 2020 && ++retry < SNTP_TIME_TRY_MAX) {
		IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, SNTP_TIME_TRY_MAX);
		IOT_DELAY(3000);
		qcom_sntp_get_time(0, &sntp_time);
	}

	if (retry < SNTP_TIME_TRY_MAX) {
		IOT_INFO("[WIFI] system time updated to %d-%d-%d-%d-%d", sntp_time.year, sntp_time.mon + 1, sntp_time.yday, sntp_time.hour, sntp_time.min);
		memset(&sntp_tm, 0, sizeof(tSntpTM));
		qcom_sntp_get_time_of_day(0, &sntp_tm);
		snprintf(time_str, TIME_STR_LEN, "%ld", sntp_tm.tv_sec);
		iot_bsp_system_set_time_in_sec(time_str);
	}
}

static void _wifi_callback(int val, uint8_t devId, uint8_t *mac, bool bssConn)
{
	if (val == true) {
		IOT_INFO("Connected for device=%d", devId);

		if (devId == 0) {
			IOT_INFO("%s connect event:", bssConn ? "AP" : "CLIENT");
		}
	} else if (val == INVALID_PROFILE) { // this event is used to indicate RSNA failure
		IOT_INFO("4 way handshake failure for device=%d", devId);
	} else if (val == PEER_FIRST_NODE_JOIN_EVENT) { // this event is used to RSNA success
		IOT_INFO("4 way handshake success for device=%d", devId);
	} else if (val == false) {
		IOT_INFO("Not Connected for device=%d", devId);
		if (devId == 0) {
			IOT_INFO("%s disconnect event:", bssConn ? "AP" : "CLIENT");
		}
	} else {
		IOT_INFO("last tx rate : %d kbps--for device=%d", val, devId);
	}
}

iot_error_t iot_bsp_wifi_init()
{
	WIFIReturnCode_t ret = eWiFiSuccess;

	ret = WIFI_On();
	IOT_ERROR_CHECK((ret != eWiFiSuccess), IOT_ERROR_INIT_FAIL, "iot wifi initialize failed.");

	//g_devid in iot_wifi.c is set to 0
	qcom_set_connect_callback(0, (void *)_wifi_callback);

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_wifi_set_softap(iot_wifi_conf *conf)
{
	WIFIReturnCode_t err = eWiFiSuccess;
	WIFINetworkParams_t net_config;
	uint32_t address = DHCP_SERVER_IP;
	uint32_t submask = 0xffffff00;
	uint32_t gateway = DHCP_SERVER_IP ;

	memset(&net_config, 0x0, sizeof(net_config));

	net_config.pcSSID = conf->ssid;
	net_config.ucSSIDLength = strlen(conf->ssid);
	net_config.pcPassword = conf->pass;
	net_config.ucPasswordLength = strlen(conf->pass);
	net_config.xSecurity = eWiFiSecurityWPA2;

	qcom_ipconfig(0, QCOM_IPCONFIG_STATIC, &address, &submask, &gateway);

	if (qcom_dhcps_set_pool(0, DHCP_CLIENT_IP, DHCP_CLIENT_MAX_IP, 0xFFFFFF) != A_OK) {
		IOT_ERROR("qcom_dhcps_set_pool failed.");
		return IOT_ERROR_INVALID_ARGS;
	}

	qcom_ipconfig(0, QCOM_IPCONFIG_QUERY, &address, &submask, &gateway);
	IOT_DEBUG("current ip config 0x%x , mask 0x%x, gateway 0x%x", address, submask, gateway);

	err = WIFI_ConfigureAP(&net_config);
	IOT_ERROR_CHECK(err != eWiFiSuccess, IOT_ERROR_INVALID_ARGS, "Wifi configure softap failed, err %d", err);

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_wifi_set_station(iot_wifi_conf *conf)
{
	WIFIReturnCode_t err = eWiFiSuccess;
	WIFINetworkParams_t net_config;
	uint32_t connectip = 0;

	qcom_disconnect(0);

	WIFI_SetMode(eWiFiModeStation);

	memset(&net_config, 0x0, sizeof(net_config));
	net_config.pcSSID = conf->ssid;
	net_config.ucSSIDLength = strlen(conf->ssid);
	net_config.pcPassword = conf->pass;
	net_config.ucPasswordLength = strlen(conf->pass);
	net_config.xSecurity = conf->authmode < IOT_WIFI_AUTH_WPA_WPA2_PSK ? conf->authmode : eWiFiSecurityNotSupported;

	//iot-wifi return till got ip successfully
	err = WIFI_ConnectAP(&net_config);
	IOT_ERROR_CHECK(err != eWiFiSuccess, IOT_ERROR_INVALID_ARGS, "Wifi Connect AP failed, err %d", err);

	WIFI_GetIP(&connectip);
	IOT_DEBUG("Connect AP, got ip %d.%d.%d.%d", (connectip >> 24), (connectip >> 16) & 0xFF, (connectip >> 8) & 0xFF, connectip & 0xFF);

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_wifi_set_scan(void)
{
	//We do nothing for set scan mode
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	struct timeval now;
	struct tm *timeinfo;
	unsigned int ux_bits = 0;
	iot_error_t ret = IOT_ERROR_NONE;

	IOT_ERROR_CHECK(conf == NULL, IOT_ERROR_INVALID_ARGS, "param null");
	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF:
		WIFI_Off();

		break;

	case IOT_WIFI_MODE_SCAN:
		_iot_wifi_set_scan();

		break;

	case IOT_WIFI_MODE_STATION:
		ret = _iot_wifi_set_station(conf);
		if (ret != IOT_ERROR_NONE) {
			break;
		}
		IOT_INFO("AP Connected");

		gettimeofday(&now, NULL);
		timeinfo = localtime(&now);

		if (timeinfo && timeinfo->tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}

		break;

	case IOT_WIFI_MODE_SOFTAP:
		ret = _iot_wifi_set_softap(conf);
		if(ret == IOT_ERROR_NONE) {
			IOT_INFO("AP Mode Started");
		}

		break;

	default:
		IOT_ERROR("bsp cannot support this mode = %d", conf->mode);
		break;
	}

	return ret;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	int i;
	int buff_cnt;
	int16_t resultsCount = 0;
	WIFIReturnCode_t err = eWiFiSuccess;
	WIFIScanResult_t *buffer = NULL;
	WIFIDeviceMode_t mode = eWiFiModeNotSupported;

	if (WIFI_GetMode(&mode) == eWiFiSuccess && mode == eWiFiModeAP) {
		IOT_DEBUG("scan during softap mode, just return count of last time scan.");
		return last_scan_count;
	}

	buff_cnt = (NXP_MAX_WIFI_SCAN > IOT_WIFI_MAX_SCAN_RESULT)? IOT_WIFI_MAX_SCAN_RESULT : NXP_MAX_WIFI_SCAN;

	buffer = (WIFIScanResult_t*)malloc(buff_cnt * sizeof(WIFIScanResult_t));
	IOT_ERROR_CHECK(buffer == NULL, 0, "malloc scan buffer failed.");
	memset(buffer, 0, buff_cnt * sizeof(WIFIScanResult_t));

	err = WIFI_Scan(buffer, buff_cnt);
	if (err != eWiFiSuccess) {
		IOT_ERROR("WIFI_Scan get scan result failed.");
		free(buffer);
		return 0;
	}

	/*
		typedef enum
		{
			eWiFiSecurityOpen = 0,    // Open - No Security.
			eWiFiSecurityWEP,         // WEP Security.
			eWiFiSecurityWPA,         // WPA Security.
			eWiFiSecurityWPA2,        // WPA2 Security.
			eWiFiSecurityNotSupported // Unknown Security.
		} WIFISecurity_t;
	*/
	for (i = 0; i < buff_cnt; i++) {
		if (buffer[i].cSSID[0] == 0) {
			continue;
		}

		strncpy(scan_result[resultsCount].ssid, buffer[i].cSSID, (sizeof(scan_result[i].ssid) - 1));
		strncpy(scan_result[resultsCount].bssid, buffer[i].ucBSSID, IOT_WIFI_MAX_BSSID_LEN);
	
		scan_result[resultsCount].rssi = buffer[i].cRSSI;
		scan_result[resultsCount].freq = iot_util_convert_channel_freq(buffer[i].cChannel);
		scan_result[resultsCount].authmode = (buffer[i].xSecurity < eWiFiSecurityNotSupported)? buffer[i].xSecurity : IOT_WIFI_AUTH_MAX;
	
		IOT_DEBUG("[scan result]ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, chan=%d",
				scan_result[resultsCount].ssid,
				scan_result[resultsCount].bssid[0], scan_result[resultsCount].bssid[1], scan_result[resultsCount].bssid[2],
				scan_result[resultsCount].bssid[3], scan_result[resultsCount].bssid[4], scan_result[resultsCount].bssid[5],
				scan_result[resultsCount].rssi,	scan_result[resultsCount].freq, buffer[i].cChannel);

		resultsCount++;
	}

	free(buffer);
	last_scan_count = resultsCount;
	return resultsCount;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	WIFIReturnCode_t err = eWiFiSuccess;

	err = WIFI_GetMAC(wifi_mac->addr);
	IOT_ERROR_CHECK(err != eWiFiSuccess, IOT_ERROR_BAD_REQ, "WIFI_GetMAC failed.");

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
