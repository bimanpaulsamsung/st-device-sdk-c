/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#include "iot_bsp_wifi.h"
#include "iot_debug.h"
#include "FreeRTOS.h"
#include <event_groups.h>
#include "wdrv_mrf24wn_iwpriv.h"
#include <time.h>
#include <sys/socket.h>
#include "system_config.h"

#define WIFI_INTERFACE_NAME "MRF24WN"
#define IS_WF_INTF(x) ((strcmp(x, "MRF24W") == 0) || (strcmp(x, "MRF24WN") == 0))
#define WF_DEFAULT_POWER_SAVE WDRV_DEFAULT_POWER_SAVE

#define SNTP_TIME_TRY_MAX       10
#define MICROCHIP_MAX_WIFI_SCAN 15

WF_CONFIG_DATA _wifi_cfg;
extern WDRV_MRF24WN_PRIV g_wdrv_priv;


static void _obtain_time(void)
{
	int retry = 0;
	uint32_t now_sec = 0;
	TCPIP_SNTP_RESULT ret;
	struct timeval now;
	struct tm *timeinfo;

	/*start connection, sntp server already set with TCPIP_NTP_SERVER in system_config.h
	  if necessary we can update server with TCPIP_SNTP_ConnectionParamSet*/
	//"pool.ntp.org" "time1.google.com" "1.kr.pool.ntp.org" "1.asia.pool.ntp.org"
	ret = TCPIP_SNTP_ConnectionInitiate();
	if (ret != SNTP_RES_OK) {
		IOT_ERROR("TCPIP_SNTP_ConnectionParamSet failed %d", ret);
		return;
	}

	while (TCPIP_SNTP_TimeStampStatus() != SNTP_RES_OK && retry++ < SNTP_TIME_TRY_MAX) {
		IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, SNTP_TIME_TRY_MAX);
		IOT_DELAY(3000);
	}

	if (TCPIP_SNTP_TimeStampStatus() == SNTP_RES_OK) {
		now_sec = TCPIP_SNTP_UTCSecondsGet();
		memset(&now, 0, sizeof(now));
		now.tv_sec = now_sec;
		settimeofday(&now, NULL);

		timeinfo = localtime(&now);
		if (timeinfo)
			IOT_INFO("[WIFI] system time(UTC seconds) updated to %d, localtime %d-%d-%d, %d:%d", now_sec, timeinfo->tm_year, timeinfo->tm_mon ,timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min);
		else
			IOT_ERROR("[WIFI] system time(UTC seconds) updated to %d, but timeinfo null", now_sec);
	} else {
		IOT_ERROR("Failed to get time from SNTP..");
	}
}


static void _WIFI_PowerSave_Config(bool enable)
{
	IWPRIV_SET_PARAM param;

#if WF_DEFAULT_POWER_SAVE == WF_ENABLED
	param.powerSave.enabled = enable;
	iwpriv_set(POWERSAVE_SET, &param);
#endif
}

static void _TCPIP_IF_Down(TCPIP_NET_HANDLE netH)
{
	TCPIP_STACK_NetDown(netH);
}

static void _TCPIP_IF_Up(TCPIP_NET_HANDLE netH)
{
	SYS_MODULE_OBJ tcpipStackObj;
	TCPIP_STACK_INIT tcpip_init_data;
	const TCPIP_NETWORK_CONFIG *pIfConf;
	uint16_t net_ix = TCPIP_STACK_NetIndexGet(netH);

	tcpipStackObj = TCPIP_STACK_Initialize(0, 0);
	TCPIP_STACK_InitializeDataGet(tcpipStackObj, &tcpip_init_data);
	pIfConf = tcpip_init_data.pNetConf + net_ix;
	TCPIP_STACK_NetUp(netH, pIfConf);
}

static void _TCPIP_IFModules_Disable(TCPIP_NET_HANDLE netH)
{
	const char *netName = TCPIP_STACK_NetNameGet(netH);

	if (IS_WF_INTF(netName) && TCPIP_STACK_NetIsUp(netH))
		_WIFI_PowerSave_Config(false);
	TCPIP_DHCPS_Disable(netH);
	TCPIP_DHCP_Disable(netH);
	TCPIP_DNSS_Disable(netH);
	TCPIP_DNS_Disable(netH, true);
	TCPIP_MDNS_ServiceDeregister(netH);
}

static int _get_drv_security_mode(iot_wifi_auth_mode_t authmode)
{
	switch (authmode) {
		case IOT_WIFI_AUTH_OPEN:
			return WDRV_SECURITY_OPEN;
		case IOT_WIFI_AUTH_WEP:
			return WDRV_SECURITY_WEP_40;
		case IOT_WIFI_AUTH_WPA_PSK:
			return WDRV_SECURITY_WPA_WITH_PASS_PHRASE;
		case IOT_WIFI_AUTH_WPA2_PSK:
			return WDRV_SECURITY_WPA2_WITH_PASS_PHRASE;
		case IOT_WIFI_AUTH_WPA_WPA2_PSK:
			return WDRV_SECURITY_WPA2_WITH_PASS_PHRASE;
		case IOT_WIFI_AUTH_WPA2_ENTERPRISE:
			return -1;
		default:
			break;
	}
	return -1;
}

static iot_error_t _set_softap(iot_wifi_conf *conf)
{
	IWPRIV_SET_PARAM param;

	//stdk first config softap, we don't Down/Up here.
	if ((strlen(conf->ssid) >= sizeof(_wifi_cfg.ssid)) || (strlen(conf->pass) >= sizeof(_wifi_cfg.securityKey))) {
		IOT_ERROR("too long ssid or password to set driver");
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	strcpy((char *)_wifi_cfg.ssid, conf->ssid);
	_wifi_cfg.ssidLen = strlen(conf->ssid);
	_wifi_cfg.securityMode = _get_drv_security_mode(conf->authmode);
	if (_wifi_cfg.securityMode < 0) {
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	//Going to save the key, if required.
	strcpy(_wifi_cfg.securityKey, conf->pass);
	_wifi_cfg.securityKeyLen = strlen(conf->pass);
	_wifi_cfg.networkType = WDRV_NETWORK_TYPE_SOFT_AP;
	param.config.data = &_wifi_cfg;
	iwpriv_set(CONFIG_SET, &param);

	WDRV_Connect();

	return IOT_ERROR_NONE;
}

static int _set_station(iot_wifi_conf *conf)
{
	IWPRIV_SET_PARAM param;

	if ((strlen(conf->ssid) >= sizeof(_wifi_cfg.ssid)) || (strlen(conf->pass) >= sizeof(_wifi_cfg.securityKey))) {
		IOT_ERROR("too long ssid or password to set driver");
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	strcpy((char *)_wifi_cfg.ssid, conf->ssid);
	_wifi_cfg.ssidLen = strlen(conf->ssid);
	_wifi_cfg.securityMode = _get_drv_security_mode(conf->authmode);
	if (_wifi_cfg.securityMode < 0) {
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	//Going to save the key, if required.
	strcpy(_wifi_cfg.securityKey, conf->pass);
	_wifi_cfg.securityKeyLen = strlen(conf->pass);
	_wifi_cfg.networkType = WDRV_NETWORK_TYPE_INFRASTRUCTURE;
	param.config.data = &_wifi_cfg;
	iwpriv_set(CONFIG_SET, &param);

	//switch from softap to station mode, need to down/up netif
	TCPIP_NET_HANDLE netH = TCPIP_STACK_NetHandleGet(WIFI_INTERFACE_NAME);
	_TCPIP_IFModules_Disable(netH);
	_TCPIP_IF_Down(netH);
	_TCPIP_IF_Up(netH);

	//allow WDRV_MRF24WN_Tasks to do WDRV_Connect
	param.conn.initConnAllowed = true;
	iwpriv_set(INITCONN_OPTION_SET, &param);

	int timeOut = 0;
	while (timeOut++ < 100) {
		if (isLinkUp())
			break;

		vTaskDelay(200 / portTICK_PERIOD_MS);
	}

	if (timeOut >= 100) {
		IOT_ERROR("set station time out ->\r\n");
		return IOT_ERROR_CONN_CONNECT_FAIL;
	} else {
		IOT_INFO("set station successfully ->\r\n");
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_init(void)
{
	IOT_INFO("WIFI initialized with system bootup procedure, we do nothing here.");
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	struct timeval now;
	struct tm *timeinfo;
	iot_error_t ret = IOT_ERROR_NONE;
	TCPIP_NET_HANDLE netH;

	IOT_ERROR_CHECK(conf == NULL, IOT_ERROR_INVALID_ARGS, "param null");
	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF:
		//correspond to wifi_init, we do nothing for both.
		break;

	case IOT_WIFI_MODE_SCAN:
		IOT_INFO("currently we do nothing for set_scan.");

		break;

	case IOT_WIFI_MODE_STATION:
		ret = _set_station(conf);
		if (ret != IOT_ERROR_NONE) {
			IOT_ERROR("set station failed %d", ret);
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
		ret = _set_softap(conf);
		if(ret == IOT_ERROR_NONE) {
			IOT_INFO("AP Mode Started");
		} else {
			IOT_ERROR("set softap failed %d", ret);
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
	uint16_t ap_num = 0;
	uint16_t idx = 0;
	uint16_t cpsize, maxsize;
	IWPRIV_GET_PARAM param;
	IWPRIV_EXECUTE_PARAM exeParam;
	WDRV_SCAN_RESULT *scanResult;

	/*Check if scan already in progress*/
	if (WDRV_EXT_ScanIsInProgress()) {
		 IOT_ERROR("Scan already in progress");
		 return 0;
	}

	iwpriv_get(SCANRESULTS_COUNT_GET, &param);
	if (param.scan.numberOfResults == 0) {
		iwpriv_execute(SCAN_START, &exeParam);
		do {
			iwpriv_get(SCANSTATUS_GET, &param);
		} while (param.scan.scanStatus == IWPRIV_SCAN_IN_PROGRESS);
		do {
			iwpriv_execute(SCANRESULTS_SAVE, &exeParam);
		} while (exeParam.scan.saveStatus == IWPRIV_IN_PROGRESS);
	}

	iwpriv_get(SCANRESULTS_COUNT_GET, &param);
	IOT_INFO("wifi scan, get %d items\r\n", param.scan.numberOfResults);

	maxsize = (MICROCHIP_MAX_WIFI_SCAN < IOT_WIFI_MAX_SCAN_RESULT) ? MICROCHIP_MAX_WIFI_SCAN : IOT_WIFI_MAX_SCAN_RESULT;
	cpsize = (param.scan.numberOfResults < maxsize) ? param.scan.numberOfResults : maxsize;
	for (; idx < cpsize; idx++) {
		memset(&param, 0, sizeof(param));
		param.scan.index = idx;
		iwpriv_get(SCANRESULT_GET, &param);
		scanResult = (WDRV_SCAN_RESULT*)param.scan.data;
		if (!scanResult) {
			IOT_INFO("No scan data for index %d\r\n", idx);
			continue;
		}

		/*Fill in scan result buffer*/
		strncpy(scan_result[ap_num].ssid, scanResult->ssid, IOT_WIFI_MAX_SSID_LEN);
		strncpy(scan_result[ap_num].bssid, scanResult->bssid, IOT_WIFI_MAX_BSSID_LEN );
		scan_result[ap_num].authmode = IOT_WIFI_AUTH_WPA_WPA2_PSK; //scan result have no auth type info, use default here.
		scan_result[ap_num].rssi = scanResult->rssi;
		scan_result[ap_num].freq = iot_util_convert_channel_freq(scanResult->channel);

		IOT_DEBUG("ssid %s\r\n", scanResult->ssid);
		ap_num++;
	}

	return ap_num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	if (wifi_mac)
		memcpy(wifi_mac->addr, g_wdrv_priv.macAddr, IOT_WIFI_MAX_BSSID_LEN);

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
