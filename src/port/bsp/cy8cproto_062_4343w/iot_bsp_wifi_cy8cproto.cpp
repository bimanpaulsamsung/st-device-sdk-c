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
#include "WhdSoftAPInterface.h"
#include "EthernetInterface.h"
#include "lwip/apps/sntp.h"

#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_util.h"

#define IOT_STDK_AP_IP		"192.168.1.1"
#define IOT_STDK_AP_NETMASK	"255.255.255.0"
#define IOT_STDK_AP_GATEWAY	"192.168.1.1"
#define IOT_STDK_AP_CHANNEL	1

static int WIFI_INITIALIZED = false;
bool ap_mode = false;

static void _initialize_sntp(void)
{
	IOT_INFO("Initializing SNTP");
	sntp_setoperatingmode(SNTP_OPMODE_POLL);
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

static void _obtain_time(void) {
	time_t now = 0;
	struct tm timeinfo = { 0 };
	int retry = 0;
	const int retry_count = 10;

	time(&now);
	localtime_r(&now, &timeinfo);
	IOT_INFO("DATE: (%02d-%02d-%04d %02d:%02d:02%d)", timeinfo.tm_mday,
			timeinfo.tm_mon+1, timeinfo.tm_year+1900,
			timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

	_initialize_sntp();

	while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
		IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, retry_count);
		IOT_DELAY(2000);
		time(&now);
		localtime_r(&now, &timeinfo);
		IOT_INFO("DATE: (%02d-%02d-%04d %02d:%02d:02%d)", timeinfo.tm_mday,
				timeinfo.tm_mon+1, timeinfo.tm_year+1900,
				timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
	}

	if (retry < 10) {
		IOT_INFO("[WIFI] system time updated by %ld", now);
	}
}

iot_error_t iot_bsp_wifi_init()
{
	if (WIFI_INITIALIZED) {
		return IOT_ERROR_NONE;
	}

	/*
	 * get mac once after wm init, avoid getting mac during wifi provisioning,
	 * which would cause a dead lock issue
	 */
	struct iot_mac init_mac;
	iot_bsp_wifi_get_mac(&init_mac);

	WIFI_INITIALIZED = true;

	return IOT_ERROR_NONE;
}

static int connect_to_ap(char *wifi_ssid, char *wifi_password,
		nsapi_security_t security = NSAPI_SECURITY_WPA_WPA2)
{
	WiFiInterface *wifi;
	wifi = WiFiInterface::get_default_instance();
	if (!wifi) {
		IOT_ERROR("ERROR: No WiFiInterface found.");
		return -1;
	}

	IOT_INFO("Connecting to %s...", wifi_ssid);
	int ret = wifi->connect(wifi_ssid, wifi_password, security);
	if (ret != 0) {
		IOT_ERROR("Connection error: %d[0x%x]", ret, ret);
		return -1;
	}

	IOT_INFO("Success");
	IOT_INFO("IP: %s", wifi->get_ip_address());
	IOT_DEBUG("MAC: %s", wifi->get_mac_address());
	IOT_DEBUG("Netmask: %s", wifi->get_netmask());
	IOT_DEBUG("Gateway: %s", wifi->get_gateway());
	IOT_DEBUG("RSSI: %d", wifi->get_rssi());
	return 0;
}

static int start_ap(char *wifi_ssid, char *wifi_password,
		nsapi_security_t security = NSAPI_SECURITY_WPA_WPA2)
{
	WhdSoftAPInterface *_wifi;
	nsapi_error_t error_code;

	_wifi = WhdSoftAPInterface::get_default_instance();

	if (ap_mode) {
		IOT_WARN("AP mode Already UP");
		return 0;
	}

	IOT_INFO("Starting AP...");
	_wifi->set_network(IOT_STDK_AP_IP, IOT_STDK_AP_NETMASK, IOT_STDK_AP_GATEWAY);
	error_code = _wifi->start(wifi_ssid, wifi_password, security, IOT_STDK_AP_CHANNEL,
			true, NULL, false);
	IOT_ERROR_CHECK(error_code != NSAPI_ERROR_OK, -1, "Failed to Start AP");

	ap_mode = true;
	IOT_INFO("AP started successfully");
	return 0;
}

static int stop_ap(void)
{
	WhdSoftAPInterface *_wifi;
	nsapi_error_t error_code;

	_wifi = WhdSoftAPInterface::get_default_instance();

	if (!ap_mode) {
		IOT_WARN("AP mode Already DOWN ");
		return 0;
	}
	IOT_INFO("Stopping AP");

	error_code = _wifi->stop();
	IOT_ERROR_CHECK(error_code != NSAPI_ERROR_OK, -1, "Failed to Stop AP");

	ap_mode = false;
	IOT_INFO("AP Stopped successfully");
	return 0;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF: {
		stop_ap();
		break;
	}
	case IOT_WIFI_MODE_SCAN: {
		stop_ap();

		WiFiInterface *wifi;
		wifi = WiFiInterface::get_default_instance();
		IOT_INFO("Scan:");

		int count = wifi->scan(NULL,0);

		if (count <= 0) {
			IOT_ERROR("scan() failed with return value: %d", count);
		}
		break;
	}
	case IOT_WIFI_MODE_STATION: {
		stop_ap();

		IOT_INFO("Start STA mode");
		if (connect_to_ap(conf->ssid, conf->pass) < 0) {
			IOT_ERROR("Could not connect to %s", conf->ssid);
			return IOT_ERROR_CONNECT_FAIL;
		}

		IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
		_obtain_time();
		break;
	}
	case IOT_WIFI_MODE_SOFTAP: {
		if (start_ap(conf->ssid, conf->pass) < 0)
			return IOT_ERROR_CONNECT_FAIL;

		break;
	}
	default:
		IOT_ERROR("iot bsp wifi can't support this mode = %d", conf->mode);
		return IOT_ERROR_INIT_FAIL;
	}

	return IOT_ERROR_NONE;
}

static iot_wifi_auth_mode_t get_security_from_nsapi(nsapi_security_t sec) {
	switch (sec) {
	case NSAPI_SECURITY_NONE:
		return IOT_WIFI_AUTH_OPEN;
	case NSAPI_SECURITY_WEP:
		return IOT_WIFI_AUTH_WEP;
	case NSAPI_SECURITY_WPA:
		return IOT_WIFI_AUTH_WPA_PSK;
	case NSAPI_SECURITY_WPA2:
		return IOT_WIFI_AUTH_WPA2_PSK;
	case NSAPI_SECURITY_WPA_WPA2:
		return IOT_WIFI_AUTH_WPA_WPA2_PSK;
	case NSAPI_SECURITY_WPA2_ENT:
		return IOT_WIFI_AUTH_WPA2_ENTERPRISE;
	default:
		return IOT_WIFI_AUTH_MAX;
	}
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	WiFiAccessPoint *ap;
	WiFiInterface *wifi;
	wifi = WiFiInterface::get_default_instance();
	IOT_INFO("Scan:");

	int count = wifi->scan(NULL,0);
	if (count <= 0) {
		IOT_ERROR("scan() failed with return value: %d", count);
		return 0;
	}

	/* Limit number of network arbitrary to 15 */
	count = count < 15 ? count : 15;

	ap = new WiFiAccessPoint[count];
	count = wifi->scan(ap, count);

	if (count <= 0) {
		IOT_ERROR("scan() failed with return value: %d", count);
		return 0;
	}

	scan_result = new iot_wifi_scan_result_t[count];
	for (int i = 0; i < count; i++) {
		IOT_DEBUG("Network: %s secured: %s BSSID: %hhX:%hhX:%hhX:%hhx:%hhx:%hhx RSSI: %hhd Ch: %hhd", ap[i].get_ssid(),
				sec2str(ap[i].get_security()), ap[i].get_bssid()[0], ap[i].get_bssid()[1], ap[i].get_bssid()[2],
				ap[i].get_bssid()[3], ap[i].get_bssid()[4], ap[i].get_bssid()[5], ap[i].get_rssi(), ap[i].get_channel());

		memcpy(scan_result[i].ssid, ap[i].get_ssid(), strlen(ap[i].get_ssid()));
		const uint8_t *ap_mac = ap[i].get_bssid();
		scan_result[i].bssid[0] = ap_mac[0];
		scan_result[i].bssid[1] = ap_mac[1];
		scan_result[i].bssid[2] = ap_mac[2];
		scan_result[i].bssid[3] = ap_mac[3];
		scan_result[i].bssid[4] = ap_mac[4];
		scan_result[i].bssid[5] = ap_mac[5];

		scan_result[i].rssi = ap[i].get_rssi();
		scan_result[i].freq = iot_util_convert_channel_freq(ap[i].get_channel());
		scan_result[i].authmode = get_security_from_nsapi(ap[i].get_security());
	}
	IOT_INFO("%d networks available.", count);

	delete[] ap;
	return count;
}

//TODO: get correct MAC address
extern "C" void mbed_mac_address(char *s);

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac) {
	WiFiInterface *wifi;
	wifi = WiFiInterface::get_default_instance();
	if (!wifi) {
		IOT_ERROR("ERROR: No WiFiInterface found.");
		return IOT_ERROR_NET_INVALID_INTERFACE;
	}

	char mac[6];
	mbed_mac_address(mac);
	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
