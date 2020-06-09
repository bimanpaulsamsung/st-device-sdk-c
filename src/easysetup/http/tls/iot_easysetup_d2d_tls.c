/* ***************************************************************************
 *
 * Copyright (c) 2019-2020 Samsung Electronics All Rights Reserved.
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

#include <string.h>
#include <time.h>
#include "JSON.h"
#include "iot_main.h"
#include "iot_bsp_random.h"
#include "iot_bsp_system.h"
#include "iot_easysetup.h"
#include "iot_internal.h"
#include "iot_nv_data.h"
#include "iot_util.h"
#include "iot_debug.h"

#define HASH_SIZE (4)
#define PIN_SIZE	8
#define MAC_ADDR_BUFFER_SIZE	20
#define URL_BUFFER_SIZE		64
#define WIFIINFO_BUFFER_SIZE	20
#define ES_CONFIRM_MAX_DELAY	10000

iot_error_t iot_easysetup_create_ssid(struct iot_devconf_prov_data *devconf, char *ssid, size_t ssid_len)
{
	char *serial = NULL;
	unsigned char hash_buffer[IOT_CRYPTO_SHA256_LEN] = { 0, };
	unsigned char base64url_buffer[IOT_CRYPTO_CAL_B64_LEN(IOT_CRYPTO_SHA256_LEN)] = { 0, };
	size_t base64_written = 0;
	char ssid_build[33] = { 0, };
	unsigned char last_sn[HASH_SIZE + 1] = { 0,};
	unsigned char hashed_sn[HASH_SIZE + 1] = { 0,};
	size_t length;
	int i, setup_type;
	iot_error_t err = IOT_ERROR_NONE;

	IOT_WARN_CHECK((devconf == NULL || ssid == NULL || ssid_len == 0), IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");

	err = iot_nv_get_serial_number(&serial, &length);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to get serial number : %d\n", err);
		goto out;
	}
	err = iot_crypto_sha256((unsigned char*)serial, length, hash_buffer);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed sha256 (str: %s, len: %zu\n", serial, length);
		goto out;
	}
	err = iot_crypto_base64_encode_urlsafe(hash_buffer, sizeof(hash_buffer),
						base64url_buffer, sizeof(base64url_buffer), &base64_written);
	if (err != IOT_ERROR_NONE)
		goto out;

	if (base64_written >= HASH_SIZE) {
		devconf->hashed_sn = iot_os_malloc(base64_written + 1);
		if (!devconf->hashed_sn) {
			err = IOT_ERROR_MEM_ALLOC;
			goto out;
		}
		memset(devconf->hashed_sn, '\0', base64_written + 1);
		memcpy(devconf->hashed_sn, base64url_buffer, base64_written);
		memcpy(hashed_sn, base64url_buffer, HASH_SIZE);
	} else {
		err = IOT_ERROR_CRYPTO_BASE64_URLSAFE;
		goto out;
	}
	hashed_sn[HASH_SIZE] = '\0';

	for (i = 0; i < HASH_SIZE; i++) {
		if (length < (HASH_SIZE - i))
			last_sn[i] = 0;
		else
			last_sn[i] = serial[length - (HASH_SIZE - i)];
	}
	last_sn[HASH_SIZE] = '\0';
	IOT_INFO(">> %s[%c%c%c%c] <<", devconf->device_onboarding_id,
				last_sn[0], last_sn[1],
				last_sn[2], last_sn[3]);

	setup_type = 7;

	snprintf(ssid_build, sizeof(ssid_build), "%s_E4%3s%3s%1d%4s%4s",
			devconf->device_onboarding_id, devconf->mnid, devconf->setupid, setup_type, hashed_sn, last_sn);

	memcpy(ssid, ssid_build, ssid_len < strlen(ssid_build) ? ssid_len : strlen(ssid_build));
out:
	if (err && devconf->hashed_sn) {
		iot_os_free(devconf->hashed_sn);
		devconf->hashed_sn = NULL;
	}
	if (serial) {
		iot_os_free(serial);
	}
	return err;
}

void st_conn_ownership_confirm(IOT_CTX *iot_ctx, bool confirm)
{
	struct iot_context *ctx = (struct iot_context*)iot_ctx;

	if (ctx->curr_otm_feature == OVF_BIT_BUTTON) {
		if (confirm == true) {
			IOT_INFO("To confirm is reported!!");
			iot_os_eventgroup_set_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
		}
	}
}

STATIC_FUNCTION
char *_es_json_parse_string(JSON_H *json, const char *name)
{
	char *buf = NULL;
	JSON_H *recv = NULL;
	unsigned int buf_len;

	if (!json || !name) {
		IOT_ERROR("invalid args");
		return NULL;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(json, name)) == NULL) {
		IOT_ERROR("failed to find '%s'", name);
		return NULL;
	}
	buf_len = (strlen(recv->valuestring) + 1);

	IOT_DEBUG("'%s' (%d): %s",
			name, buf_len, recv->valuestring);

	if ((buf = (char *)iot_os_malloc(buf_len)) == NULL) {
		IOT_ERROR("failed to malloc for buf");
		return NULL;
	}
	memset(buf, 0, buf_len);
	memcpy(buf, recv->valuestring, strlen(recv->valuestring));

	return buf;
}

STATIC_FUNCTION
iot_error_t _es_time_set(unsigned char *time)
{
	char time_str[11] = {0,};
	iot_error_t err = IOT_ERROR_NONE;
	struct tm tm = { 0 };
	time_t now = 0;

	if (sscanf((char *)time, "%4d-%2d-%2dT%2d.%2d.%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
		IOT_ERROR("Invalid UTC time!!");
		return IOT_ERROR_EASYSETUP_INVALID_TIME;
	}

	/*
	This code is applied by the Year 2038 problem.
	The Year 2038 problem relates to representing time in many digital systems
	as the number of seconds passed since 00:00:00 UTC on 1 January 1970 and storing it as a signed 32-bit integer.
	Such implementations cannot encode times after 03:14:07 UTC on 19 January 2038.
	The Year 2038 problem is caused by insufficient capacity used to represent time.
	If it meet the problem, the time info will be updated by SNTP.
	*/
	if (sizeof(time_t) == 4) {
		if (tm.tm_year >= 2038) {
			IOT_ERROR("Not support time by year 2038 problem(Y2038 Problem)");
			return IOT_ERROR_NONE;
		}
	}

	tm.tm_year -= 1900;
	tm.tm_mon -= 1;

	now = mktime(&tm);
	snprintf(time_str, sizeof(time_str), "%ld", now);

	err = iot_bsp_system_set_time_in_sec(time_str);
	if (err) {
		IOT_ERROR("Time set error!!");
		err = IOT_ERROR_EASYSETUP_INVALID_TIME;
	}
	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _es_deviceinfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx) {
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		return IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "protocolVersion", JSON_CREATE_STRING("0.4.7"));
	JSON_ADD_ITEM_TO_OBJECT(root, "firmwareVersion", JSON_CREATE_STRING(ctx->device_info.firmware_version));
	JSON_ADD_ITEM_TO_OBJECT(root, "hashedSn", JSON_CREATE_STRING((char *)ctx->devconf.hashed_sn));
	JSON_ADD_NUMBER_TO_OBJECT(root, "wifiSupportFrequency", (double) iot_bsp_wifi_get_freq());

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;

	if (root)
		JSON_DELETE(root);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_keyinfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
	JSON_H *array = NULL;
	unsigned int i;
	iot_error_t err = IOT_ERROR_NONE;
	unsigned char *p_datetime_str = NULL;
	unsigned char *p_regionaldatetime_str = NULL;
	unsigned char *p_timezoneid_str = NULL;

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid json format of payload");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "datetime")) == NULL) {
		IOT_INFO("no datetime info");
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto temp_exit;
	}
	p_datetime_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	err = _es_time_set(p_datetime_str);
	if (err) {
		goto exit_secret;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "regionaldatetime")) == NULL) {
		IOT_INFO("no regionaldatetime info");
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit_secret;
	}
	p_regionaldatetime_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	IOT_DEBUG("regionaldatetime = %s", p_regionaldatetime_str);

	if ((recv = JSON_GET_OBJECT_ITEM(root, "timezoneid")) == NULL) {
		IOT_INFO("no timezoneid info");
		err  = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto exit_secret;
	}
	p_timezoneid_str = (unsigned char *)JSON_GET_STRING_VALUE(recv);

	IOT_DEBUG("timezoneid = %s", p_timezoneid_str); // TODO: where to store

temp_exit:// TODO: once app is published with time info feature, it should be deleted.

	JSON_DELETE(root);

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_secret;
	}

	array = JSON_CREATE_ARRAY();
	if (!array) {
		err = IOT_ERROR_MEM_ALLOC;
		goto exit_secret;
	}

	for (i = OVF_BIT_JUSTWORKS; i < OVF_BIT_MAX_FEATURE; i++) {
		if (ctx->devconf.ownership_validation_type & (unsigned)(1 << i)) {
			JSON_ADD_ITEM_TO_ARRAY(array, JSON_CREATE_NUMBER(i));
		}
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "otmSupportFeatures", array);
	
	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
exit_secret:
exit:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirm_check_manager(struct iot_context *ctx, enum ownership_validation_feature confirm_feature, char *sn)
{
	char *dev_sn = NULL;
	unsigned int curr_event = 0;
	size_t devsn_len;
	iot_error_t err = IOT_ERROR_NONE;

	iot_os_eventgroup_clear_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM);
	ctx->curr_otm_feature = confirm_feature;

	IOT_REMARK("IOT_STATE_PROV_CONFIRMING");

	err = iot_state_update(ctx, IOT_STATE_PROV_CONFIRM,
			IOT_STATE_OPT_NEED_INTERACT);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed handle cmd (%d): %d", IOT_STATE_PROV_CONFIRM, err);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		goto out;
	}

	switch (confirm_feature)
	{
		case OVF_BIT_JUSTWORKS:
			IOT_INFO("There is no confirmation request. The check is skipped");
			break;
		case OVF_BIT_QR:
			IOT_INFO("The QR code confirmation is requested\n");
			if (sn == NULL) {
				IOT_ERROR("to get invalid QR serial num\n");
				err = IOT_ERROR_EASYSETUP_INVALID_QR;
				goto out;
			}

			err = iot_nv_get_serial_number(&dev_sn, &devsn_len);
			if (err != IOT_ERROR_NONE) {
				IOT_ERROR("failed to get serial num\n");
				err = IOT_ERROR_EASYSETUP_SERIAL_NOT_FOUND;
				goto out;
			}

			if (!strcmp(sn, dev_sn)) {
				IOT_INFO("confirm");
			} else {
				IOT_ERROR("confirm fail");
				err = IOT_ERROR_EASYSETUP_INVALID_SERIAL_NUMBER;
				goto out;
			}
			break;
		case OVF_BIT_BUTTON:
			IOT_INFO("The button confirmation is requested");

			curr_event = iot_os_eventgroup_wait_bits(ctx->iot_events, IOT_EVENT_BIT_EASYSETUP_CONFIRM, false, ES_CONFIRM_MAX_DELAY);
			IOT_DEBUG("curr_event = %d", curr_event);

			if (curr_event & IOT_EVENT_BIT_EASYSETUP_CONFIRM) {
				IOT_INFO("confirm");
			} else {
				IOT_ERROR("confirm failed");
				err = IOT_ERROR_EASYSETUP_CONFIRM_DENIED;
				goto out;
			}
			break;
		case OVF_BIT_PIN:
			IOT_INFO("The pin number confirmation is requested");
			return err;
		default:
			IOT_INFO("Not Supported confirmation type is requested");
			return err;
	}

	err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SCAN);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't send WIFI mode scan.(%d)", err);
		err = IOT_ERROR_EASYSETUP_WIFI_SCAN_NOT_FOUND;
	}

out:
	if (dev_sn)
		free(dev_sn);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirminfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx || !in_payload) {
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "otmSupportFeature")) == NULL) {
		IOT_INFO("no otmsupportfeature info");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	IOT_INFO("otmSupportFeature = %d", recv->valueint);

	if ((recv->valueint >= OVF_BIT_JUSTWORKS) && (recv->valueint < OVF_BIT_MAX_FEATURE)) {
		char *sn = NULL;

		if (recv->valueint == OVF_BIT_QR)
			sn = _es_json_parse_string(root, "sn");

		err = _es_confirm_check_manager(ctx, recv->valueint, sn);
		if (err != IOT_ERROR_NONE)
			goto out;
	} else {
		IOT_ERROR("Not supported otmsupportfeature : %d", recv->valueint);
		err = IOT_ERROR_EASYSETUP_CONFIRM_NOT_SUPPORT ;
		goto out;
	}
	JSON_DELETE(root);


	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
	
	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_confirm_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	bool validation = true;
	char pin[PIN_SIZE + 1];
	char *final_msg = NULL;
	JSON_H *recv = NULL;
	JSON_H *root = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx || !ctx->pin) {
		IOT_ERROR("no pin from device app");
		return IOT_ERROR_EASYSETUP_PIN_NOT_FOUND;
	}

	if (ctx->curr_otm_feature != OVF_BIT_PIN) {
		IOT_ERROR("otm is not pin.");
		return IOT_ERROR_EASYSETUP_INVALID_CMD;
	}

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	if ((recv = JSON_GET_OBJECT_ITEM(root, "pin")) == NULL) {
		IOT_INFO("no pin info");
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}

	if (strlen(JSON_GET_STRING_VALUE(recv)) != PIN_SIZE) {
		IOT_ERROR("pin size mistmatch");
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}

	strncpy(pin, recv->valuestring, sizeof(pin) - 1);
	pin[PIN_SIZE] = '\0';
	IOT_INFO("pin = %s", pin);
	for (i = 0; i < PIN_SIZE; i++) {
		if (pin[i] > '9' || pin[i] < '0') {
			IOT_ERROR("invalid pin number from application");
			validation = false;
			break;
		}
	}

	for (i = 0; i < PIN_SIZE; i++) {
		if (ctx->pin->pin[i] != pin[i]) {
			IOT_ERROR("the reported pin number is not matched[%d]", i);
			validation = false;
			break;
		}
	}

	if (!validation) {
		err = IOT_ERROR_EASYSETUP_INVALID_PIN;
		goto out;
	}
	JSON_DELETE(root);

	/*
	 * output payload
	 */
	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;

	err = iot_wifi_ctrl_request(ctx, IOT_WIFI_MODE_SCAN);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Can't send WIFI mode scan.(%d)", err);
		err = IOT_ERROR_EASYSETUP_WIFI_SCAN_NOT_FOUND;
	}

out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_wifiscaninfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *final_msg = NULL;
	char wifi_bssid[WIFIINFO_BUFFER_SIZE] = {0, };
	JSON_H *root = NULL;
	JSON_H *array = NULL;
	JSON_H *array_obj = NULL;
	int i;
	iot_error_t err = IOT_ERROR_NONE;

	if (!ctx) {
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
	}

	if (!ctx->scan_num)
		return IOT_ERROR_EASYSETUP_WIFI_SCAN_NOT_FOUND;

	array = JSON_CREATE_ARRAY();
	if (!array) {
		IOT_ERROR("json_array create failed");
		return IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
	}

	for(i = 0; i < ctx->scan_num; i++) {
		if ((ctx->scan_result[i].authmode <  IOT_WIFI_AUTH_OPEN) ||
			(ctx->scan_result[i].authmode >= IOT_WIFI_AUTH_WPA2_ENTERPRISE)) {
			IOT_DEBUG("Unsupported authType %d, %s", ctx->scan_result[i].authmode,
								(char *)ctx->scan_result[i].ssid);
			continue;
		}
		snprintf(wifi_bssid, sizeof(wifi_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
						ctx->scan_result[i].bssid[0], ctx->scan_result[i].bssid[1],
						ctx->scan_result[i].bssid[2], ctx->scan_result[i].bssid[3],
						ctx->scan_result[i].bssid[4], ctx->scan_result[i].bssid[5]);

		array_obj = JSON_CREATE_OBJECT();
		if (!array_obj) {
			IOT_ERROR("json create failed");
			err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
			goto out;
		}
		JSON_ADD_ITEM_TO_OBJECT(array_obj, "bssid", JSON_CREATE_STRING(wifi_bssid));
		JSON_ADD_ITEM_TO_OBJECT(array_obj, "ssid", JSON_CREATE_STRING((char*)ctx->scan_result[i].ssid));
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "rssi", (double) ctx->scan_result[i].rssi);
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "frequency", (double) ctx->scan_result[i].freq);
		JSON_ADD_NUMBER_TO_OBJECT(array_obj, "authType", ctx->scan_result[i].authmode);
		JSON_ADD_ITEM_TO_ARRAY(array, array_obj);
	}

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "wifiScanInfo", array);

	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_wifi_auth_mode_t _decide_wifi_auth_mode(const JSON_H *item, struct iot_wifi_prov_data *wifi_prov, const struct iot_context *ctx)
{
	iot_wifi_auth_mode_t auth_mode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
	int i;

	if (!ctx || !wifi_prov) {
		return IOT_WIFI_AUTH_WPA_WPA2_PSK;
	}

	if (item == NULL) {
		IOT_INFO("no authType");
		for (i = 0; i < ctx->scan_num; i++) {
			if (!strcmp(wifi_prov->ssid, (char *)ctx->scan_result[i].ssid)) {
				auth_mode = ctx->scan_result[i].authmode;
				IOT_DEBUG("%s is type %d", wifi_prov->ssid, auth_mode);
				break;
			}
		}
		if (i == ctx->scan_num) {
			if (strlen(wifi_prov->password) == 0) {
				IOT_DEBUG("%s doesn't exist in scan list. So assume it as Open", wifi_prov->ssid);
				auth_mode = IOT_WIFI_AUTH_OPEN;
			} else {
				IOT_DEBUG("%s doesn't exist in scan list. So assume it as WPA", wifi_prov->ssid);
				auth_mode = IOT_WIFI_AUTH_WPA_WPA2_PSK;
			}
		}
	} else {
		for (i = 0; i < ctx->scan_num; i++) {
			if (!strcmp(wifi_prov->ssid, (char *)ctx->scan_result[i].ssid)) {
				if (item->valueint == ctx->scan_result[i].authmode) {
					auth_mode = item->valueint;
				} else {
					auth_mode = ctx->scan_result[i].authmode;
				}
				break;
			}
		}
		if (i == ctx->scan_num) {
			auth_mode = item->valueint;
		}
		IOT_DEBUG("%s is type %d", wifi_prov->ssid, auth_mode);
	}

	return auth_mode;
}

STATIC_FUNCTION
iot_error_t _es_wifi_prov_parse(struct iot_context *ctx, char *in_payload)
{
	struct iot_wifi_prov_data *wifi_prov = NULL;
	char bssid[] = "00:00:00:00:00:00";
	JSON_H *item = NULL;
	JSON_H *root = NULL;
	JSON_H *wifi_credential = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_credential = JSON_GET_OBJECT_ITEM(root, "wifiCredential")) == NULL) {
		IOT_ERROR("failed to find wifiCredential");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}

	if ((wifi_prov = (struct iot_wifi_prov_data *)malloc(sizeof(struct iot_wifi_prov_data))) == NULL) {
		IOT_ERROR("failed to malloc for wifi_prov_data");
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto wifi_parse_out;
	}

	memset(wifi_prov, 0, sizeof(struct iot_wifi_prov_data));

	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "ssid")) == NULL) {
		IOT_ERROR("failed to find ssid");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto wifi_parse_out;
	}
	strncpy(wifi_prov->ssid, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->ssid) - 1);

	// password is optional.
	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "password")) == NULL)
		IOT_INFO("No wifi password");
	else
		strncpy(wifi_prov->password, JSON_GET_STRING_VALUE(item), sizeof(wifi_prov->password) - 1);

	if ((item = JSON_GET_OBJECT_ITEM(wifi_credential, "macAddress")) == NULL)
		IOT_INFO("no macAddress");
	else
		strncpy(bssid, JSON_GET_STRING_VALUE(item), sizeof(bssid));

	err = iot_util_convert_str_mac(bssid, &wifi_prov->bssid);
	if (err) {
		IOT_ERROR("Failed to convert str to mac address (error : %d) : %s", err, bssid);
		err = IOT_ERROR_EASYSETUP_INVALID_MAC;
		goto wifi_parse_out;
	}

	wifi_prov->security_type =
		_decide_wifi_auth_mode(JSON_GET_OBJECT_ITEM(wifi_credential, "authType"), wifi_prov, ctx);

	err = iot_nv_set_wifi_prov_data(wifi_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		err = IOT_ERROR_EASYSETUP_WIFI_DATA_WRITE_FAIL;
		goto wifi_parse_out;
	}

	IOT_INFO("ssid: %s", wifi_prov->ssid);
	IOT_DEBUG("password: %s", wifi_prov->password);
	IOT_INFO("mac addr: %s", bssid);

wifi_parse_out:
	if (wifi_prov)
		free(wifi_prov);
	if (root)
		JSON_DELETE(root);
	return err;
}

STATIC_FUNCTION
iot_error_t _es_cloud_prov_parse(char *in_payload)
{
	struct iot_cloud_prov_data *cloud_prov = NULL;
	char *full_url = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;
	url_parse_t url = { .protocol = NULL, .domain = NULL, .port = 0};

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid payload json format");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	if ((cloud_prov = (struct iot_cloud_prov_data *)malloc(sizeof(struct iot_cloud_prov_data))) == NULL) {
		IOT_ERROR("failed to alloc mem");
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		goto cloud_parse_out;
	}

	memset(cloud_prov, 0, sizeof(struct iot_cloud_prov_data));

	if ((full_url = _es_json_parse_string(root, "brokerUrl")) == NULL) {
		IOT_ERROR("failed to find brokerUrl");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto cloud_parse_out;
	}

	err = iot_util_url_parse(full_url, &url);
	if (err) {
		IOT_ERROR("failed to parse broker url");
		err = IOT_ERROR_EASYSETUP_INVALID_BROKER_URL;
		goto cloud_parse_out;
	}

	if ((cloud_prov->label = _es_json_parse_string(root, "deviceName")) == NULL) {
		IOT_INFO("No deviceName");
	}

	cloud_prov->broker_url = url.domain;
	cloud_prov->broker_port = url.port;

	err = iot_nv_set_cloud_prov_data(cloud_prov);
	if (err) {
		IOT_ERROR("failed to set the cloud prov data");
		cloud_prov->broker_url = NULL;
		cloud_prov->broker_port = 0;
		err = IOT_ERROR_EASYSETUP_CLOUD_DATA_WRITE_FAIL;
		goto cloud_parse_out;
	}

	IOT_INFO("brokerUrl: %s:%d", cloud_prov->broker_url, cloud_prov->broker_port);
	IOT_INFO("deviceName : %s", cloud_prov->label);

cloud_parse_out:
	if (err) {
		if (url.domain) {
			iot_os_free(url.domain);
		}
	}

	if (url.protocol) {
		iot_os_free(url.protocol);
	}
	if (full_url) {
		iot_os_free(full_url);
	}
	if (cloud_prov) {
		iot_os_free(cloud_prov);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_wifiprovisioninginfo_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	char *recv_msg = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_PARSE(in_payload);
	if (!root) {
		IOT_ERROR("Invalid args");
		err = IOT_ERROR_EASYSETUP_INVALID_REQUEST;
		goto out;
	}

	recv_msg = JSON_PRINT(root);

	err = _es_wifi_prov_parse(ctx, (char *)recv_msg);
	if (err) {
		IOT_ERROR("failed to parse wifi_prov");
		goto out;
	}

	err = _es_cloud_prov_parse((char *)recv_msg);
	if (err) {
		IOT_ERROR("failed to parse cloud_prov");
		goto out;
	}

	if (ctx->lookup_id == NULL) {
		ctx->lookup_id = iot_os_malloc(IOT_REG_UUID_STR_LEN + 1);
	}

	err = iot_get_random_id_str(ctx->lookup_id,
			(IOT_REG_UUID_STR_LEN + 1));
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get new lookup_id(%d)", err);
		err = IOT_ERROR_EASYSETUP_LOOKUPID_GENERATE_FAIL;
		goto out;
	}

	IOT_DEBUG("lookupid = %s", ctx->lookup_id);

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}
	JSON_ADD_ITEM_TO_OBJECT(root, "lookupId", JSON_CREATE_STRING(ctx->lookup_id));

	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;

	err = iot_nv_get_prov_data(&ctx->prov_data);
	if (err) {
		err = IOT_ERROR_EASYSETUP_WIFI_DATA_READ_FAIL;
		IOT_WARN("No provisining from nv");
	} else {
		IOT_INFO("provisioning success");
	}
out:
	if (recv_msg) {
		free(recv_msg);
	}
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

STATIC_FUNCTION
iot_error_t _es_setupcomplete_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *final_msg = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	final_msg = JSON_PRINT(root);

	*out_payload = final_msg;
out:
	if (root) {
		JSON_DELETE(root);
	}
	return err;
}

#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
static iot_error_t _es_log_systeminfo_handler(struct iot_context *ctx, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "version", JSON_CREATE_STRING("1.0"));

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;

out:
	if (root)
		JSON_DELETE(root);
	return err;
}

static iot_error_t _es_log_create_dump_handler(struct iot_context *ctx, char *in_payload, char **out_payload)
{
	char *output_ptr = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;

out:
	if (root)
		JSON_DELETE(root);
	return err;
}

static iot_error_t _es_log_get_dump_handler(struct iot_context *ctx, char **out_payload)
{
	char *log_dump = NULL;
	char *output_ptr = NULL;
	JSON_H *item = NULL;
	JSON_H *root = NULL;
	iot_error_t err = IOT_ERROR_NONE;

	item = JSON_CREATE_OBJECT();
	if (!item) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_JSON_CREATE_ERROR;
		goto out;
	}

	log_dump = iot_debug_get_log();
	JSON_ADD_NUMBER_TO_OBJECT(item, "code", 1);
	JSON_ADD_ITEM_TO_OBJECT(item, "message", JSON_CREATE_STRING(log_dump));

	root = JSON_CREATE_OBJECT();
	if (!root) {
		IOT_ERROR("json create failed");
		err = IOT_ERROR_EASYSETUP_MEM_ALLOC_ERROR;
		if (item) {
			JSON_DELETE(item);
		}
		goto out;
	}

	JSON_ADD_ITEM_TO_OBJECT(root, "error", item);

	output_ptr = JSON_PRINT(root);

	*out_payload = output_ptr;
out:
	if (root)
		JSON_DELETE(root);
	return err;
}
#endif

iot_error_t iot_easysetup_request_handler(struct iot_context *ctx, struct iot_easysetup_payload request)
{
	iot_error_t err = IOT_ERROR_NONE;
	int ret = IOT_OS_TRUE;
	struct iot_easysetup_payload response;

	if (!ctx)
		return IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;

	response.step = request.step;
	response.payload = NULL;

	switch (request.step) {
	case IOT_EASYSETUP_STEP_DEVICEINFO:
		err = _es_deviceinfo_handler(ctx, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle deviceinfo %d", err);
		}
		break;
	case IOT_EASYSETUP_STEP_WIFISCANINFO:
		err = _es_wifiscaninfo_handler(ctx, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle wifiscaninfo %d", err);
		}
		break;
	case IOT_EASYSETUP_STEP_KEYINFO:
		err = _es_keyinfo_handler(ctx, request.payload, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle keyinfo %d", err);
		}
		break;
	case IOT_EASYSETUP_STEP_CONFIRMINFO:
		err = _es_confirminfo_handler(ctx, request.payload, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle confirminfo %d", err);
		}
		break;
	case IOT_EASYSETUP_STEP_CONFIRM:
		err = _es_confirm_handler(ctx, request.payload, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle confirm %d", err);
		}
		break;
	case IOT_EASYSETUP_STEP_WIFIPROVIONINGINFO:
		err = _es_wifiprovisioninginfo_handler(ctx, request.payload, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle wifiprovisionininginfo %d", err);
		}
		break;
	case IOT_EASYSETUP_STEP_SETUPCOMPLETE:
		err = _es_setupcomplete_handler(ctx, request.payload, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle setupcomplete %d", err);
		}
		break;
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP_LOG_SUPPORT)
	case IOT_EASYSETUP_STEP_LOG_SYSTEMINFO:
		err = _es_log_systeminfo_handler(ctx, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle logsysteminfo %d", err);
		}
		break;
	case IOT_EASYSETUP_STEP_LOG_CREATE_DUMP:
		err = _es_log_create_dump_handler(ctx, request.payload, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle logcreatedump %d", err);
		}
	break;
	case IOT_EASYSETUP_STEP_LOG_GET_DUMP:
		err = _es_log_get_dump_handler(ctx, &response.payload);
		if (err) {
			IOT_ERROR("failed to handle loggetdump %d", err);
		}
		break;
#endif
	default:
		IOT_WARN("invalid step %d", request.step);
		err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		break;
	}

	response.err = err;

	if (ctx->easysetup_resp_queue) {
		ret = iot_os_queue_send(ctx->easysetup_resp_queue, &response, 0);
		if (ret != IOT_OS_TRUE) {
			IOT_ERROR("Cannot put the response into easysetup_resp_queue");
			err = IOT_ERROR_EASYSETUP_INTERNAL_SERVER_ERROR;
		} else {
			iot_os_eventgroup_set_bits(ctx->iot_events,
				IOT_EVENT_BIT_EASYSETUP_RESP);
			err = IOT_ERROR_NONE;
		}
	} else {
		IOT_ERROR("easysetup_resp_queue is deleted");
		err = IOT_ERROR_NONE;
	}

	return err;
}
