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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "iot_main.h"
#include "iot_debug.h"
#include "wifi.h"
#define WIFI_WRITE_TIMEOUT 10000
#define WIFI_READ_TIMEOUT  10000


#define IOT_MBEDTLS_READ_TIMEOUT_MS 30000

//TODO: handle for each socket
static unsigned char readbuf[1200];
static int cache = 0;

static int at_read_select(iot_net_interface_t *net)
{
	uint16_t ret = 0;
	int wifi_code;

	if (cache > 0) {
		return 1;
	}

	wifi_code = WIFI_ReceiveData((uint8_t)net->context.fd, readbuf, 1, &ret, 500);

	if (wifi_code != WIFI_STATUS_OK || ret == 0) {
		return 0;
	}

	IOT_INFO("Socket Buffer: [%02x]", readbuf[0]);
	cache = ret;
	return 1;
}

static int at_cache_read(uint8_t socket, uint8_t *buf, uint16_t len, uint16_t *RcvDatalen, uint32_t Timeout)
{
	int recvLen = 0;
	uint16_t ret = 0;
	int wifi_code = 0;

	if (len == 0) {
		*RcvDatalen = 0;
		return 0;
	}

	if (cache > 0) {
		memcpy(buf, readbuf, cache);
		recvLen = cache;
		cache = 0;
	}

	//Normal read with len = len - cache
	if ((len - recvLen) == 0) {
		*RcvDatalen = recvLen;
		return (recvLen? 0: -1);
	}

	wifi_code = WIFI_ReceiveData(socket, buf+recvLen, len-recvLen, &ret, Timeout);

	if (wifi_code == WIFI_STATUS_OK) {
		recvLen += ret;
	} else {
		IOT_ERROR("mbedtls_ssl_read = %d", -wifi_code);
		return recvLen;
	}

	*RcvDatalen = recvLen;
	return (recvLen? 0: -1);
}


static iot_error_t _iot_net_check_interface(iot_net_interface_t *net)
{
//	IOT_WARN("FLOW");
	if (net == NULL) {
		IOT_ERROR("interface is null");
		return IOT_ERROR_NET_INVALID_INTERFACE;
	}

	return IOT_ERROR_NONE;
}

static void _iot_net_show_status(iot_net_interface_t *net)
{
	if (_iot_net_check_interface(net)) {
		return;
	}

	/* TODO: Print stats */
}

static int _iot_net_select(iot_net_interface_t *net, unsigned int timeout_ms)
{
	int ret = 0;

	if (_iot_net_check_interface(net)) {
		return 0;
	}

	ret = at_read_select(net);
	if (ret) {
		IOT_DEBUG("DATA AVAILABLE");
	} else {
		IOT_DEBUG("DATA UNAVAILABLE");
	}
	return ret;
}

static void _iot_net_cleanup_platform_context(iot_net_interface_t *net)
{
	IOT_WARN("FLOW");
	if (_iot_net_check_interface(net)) {
		return;
	}

	/* TODO close connection if open */

	net->context.fd = -1;
}

static iot_error_t _iot_net_tls_connect(iot_net_interface_t *net)
{
	iot_error_t err;
	const char *pers = "iot_net_mbedtls";
	unsigned char remoteip[4] = {0,};
	int ret;
	uint32_t socket = 0;

	err = _iot_net_check_interface(net);
	if (err) {
		return err;
	}

	if ((net->connection.ca_cert == NULL) ||
	    (net->connection.ca_cert_len == 0)) {
		IOT_ERROR("ca cert is invalid");
		ret = IOT_ERROR_INVALID_ARGS;
		goto exit;
	}

	IOT_INFO("Loading the CA root certificate %d@%p",
				net->connection.ca_cert_len + 1,
				net->connection.ca_cert);

	IOT_INFO("Connecting to %s:%d", net->connection.url, net->connection.port);

	if (WIFI_GetHostAddress(net->connection.url, remoteip) != WIFI_STATUS_OK) {
		IOT_ERROR("DNS Resolution failed");
		goto exit;
	}

	/* TODO: CA cert verify */
	ret = WIFI_OpenSSLClientConnection(socket, pers, remoteip, net->connection.port);
	if (ret != WIFI_STATUS_OK) {
		IOT_ERROR("SSL Connection failed");
		goto exit;
	}

	net->context.fd = socket;

	return IOT_ERROR_NONE;

exit:
	_iot_net_cleanup_platform_context(net);

	return IOT_ERROR_NET_CONNECT;
}

static void _iot_net_tls_disconnect(iot_net_interface_t *net)
{
	int ret;
	ret = WIFI_CloseClientConnection(net->context.fd);
	if (ret != WIFI_STATUS_OK) {
		IOT_ERROR("SSL DisConnection failed");
	}

	_iot_net_cleanup_platform_context(net);
}

static int _iot_net_tls_read(iot_net_interface_t *net,
		unsigned char *buf, size_t len, iot_os_timer timer)
{
	int recvLen = 0;
	uint16_t ret = 0;
	int wifi_code;

	IOT_DEBUG("%d@%p", len, buf);

	if (_iot_net_check_interface(net)) {
		return 0;
	}

	if (buf == NULL || timer == NULL) {
		return -1;
	}

	if (len == 0) {
		return 0;
	}

	do {
		wifi_code = at_cache_read(net->context.fd, buf+recvLen, len-recvLen, &ret, WIFI_READ_TIMEOUT);

		if (wifi_code == WIFI_STATUS_OK) {
			recvLen += ret;
		} else {
			IOT_ERROR("mbedtls_ssl_read = %d", -wifi_code);
			return recvLen;
		}
	} while(recvLen < len && !iot_os_timer_isexpired(timer));

	return recvLen;
}

static int _iot_net_tls_write(iot_net_interface_t *net,
		unsigned char *buf, int len, iot_os_timer timer)
{
	int sentLen = 0;
	uint16_t ret = 0;
	int wifi_code;

	IOT_DEBUG("%d@%p", len, buf);

	if (_iot_net_check_interface(net)) {
		return 0;
	}

	do {
		wifi_code = WIFI_SendData(net->context.fd, buf + sentLen, (size_t)len - sentLen, &ret, WIFI_WRITE_TIMEOUT);

		if (wifi_code == WIFI_STATUS_OK) {
			sentLen += ret;
		} else {
			IOT_ERROR("ssl_write = %d\n", -ret);
			return -1;
		}
	} while (sentLen < len && !iot_os_timer_isexpired(timer));

	return sentLen;
}

iot_error_t iot_net_init(iot_net_interface_t *net)
{
	iot_error_t err;

	err = _iot_net_check_interface(net);
	if (err) {
		return err;
	}

	net->connect = _iot_net_tls_connect;
	net->disconnect = _iot_net_tls_disconnect;
	net->select = _iot_net_select;
	net->read = _iot_net_tls_read;
	net->write = _iot_net_tls_write;
	net->show_status = _iot_net_show_status;

	return IOT_ERROR_NONE;
}
