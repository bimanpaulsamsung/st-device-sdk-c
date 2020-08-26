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
#include <sys/socket.h>

#include "iot_main.h"
#include "iot_debug.h"
#include "wifi.h"
#define WIFI_WRITE_TIMEOUT 10000
#define WIFI_READ_TIMEOUT  10000


#define IOT_MBEDTLS_READ_TIMEOUT_MS 30000

static iot_error_t _iot_net_check_interface(iot_net_interface_t *net)
{
	IOT_WARN("FLOW");
	if (net == NULL) {
		IOT_ERROR("interface is null");
		return IOT_ERROR_NET_INVALID_INTERFACE;
	}

	return IOT_ERROR_NONE;
}

static void _iot_net_show_status(iot_net_interface_t *net)
{
	struct timeval tv;
	struct timeval timeout = {0};
	int socket;
	int sock_err = 0;
	socklen_t err_len = sizeof(sock_err);
	fd_set rfdset;
	fd_set wfdset;

	IOT_WARN("FLOW");
	if (_iot_net_check_interface(net)) {
		return;
	}

	socket = net->context.fd;

	/* TODO: Print stats */
}

static int _iot_net_select(iot_net_interface_t *net, unsigned int timeout_ms)
{
	struct timeval timeout;
	fd_set fdset;
	int socket;
	int ret = 1; //Assign true for testing

	IOT_WARN("FLOW");
	if (_iot_net_check_interface(net)) {
		return 0;
	}

	socket = net->context.fd;
	IOT_WARN("FLOW");
	/* TODO: check if data is present */

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
	char port[5] = {0};
	unsigned char remoteip[4] = {0,};
	unsigned int flags;
	int ret;
	uint32_t socket = 0;
	IOT_WARN("FLOW");
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

	IOT_DEBUG("Connecting to %s:%d", net->connection.url, net->connection.port);

	if (WIFI_GetHostAddress(net->connection.url, remoteip) != WIFI_STATUS_OK) {
		IOT_ERROR("DNS Resolution failed");
		goto exit;
	}
	IOT_WARN("FLOW");
	/* TODO: CA cert verify */
	ret = WIFI_OpenSSLClientConnection(socket, pers, remoteip, net->connection.port);
	if (ret != WIFI_STATUS_OK) {
		IOT_ERROR("SSL Connection failed");
		goto exit;
	}
	IOT_WARN("FLOW");
	net->context.fd = socket;

	return IOT_ERROR_NONE;

exit:
	_iot_net_cleanup_platform_context(net);

	return IOT_ERROR_NET_CONNECT;
}

static void _iot_net_tls_disconnect(iot_net_interface_t *net)
{
	int ret;
	IOT_WARN("FLOW");
	ret = WIFI_CloseClientConnection(net->context.fd);
	if (ret != WIFI_STATUS_OK) {
		IOT_ERROR("SSL DisConnection failed");
	}
	IOT_WARN("FLOW");
	_iot_net_cleanup_platform_context(net);
	IOT_WARN("FLOW");
}

static int _iot_net_tls_read(iot_net_interface_t *net,
		unsigned char *buf, size_t len, iot_os_timer timer)
{
	int recvLen = 0, ret = 0, wifi_code;

	IOT_DEBUG("%d@%p", len, buf);

	if (_iot_net_check_interface(net)) {
		return 0;
	}
	IOT_WARN("FLOW");
	if (buf == NULL || timer == NULL) {
		return -1;
	}

	if (len == 0) {
		return 0;
	}
	IOT_WARN("FLOW");
	IOT_DEBUG("############READ BUFFER#############");
	do {
//		ret = mbedtls_ssl_read(&net->context.ssl, buf, len);
		IOT_WARN("Requested Len: %d", len-recvLen);
		wifi_code = WIFI_ReceiveData(net->context.fd, buf+recvLen, len-recvLen, &ret, WIFI_READ_TIMEOUT);
		IOT_WARN("Length Received: %d", ret);
		for (int i=0; i< ret; i++) {
				printf("%02x ", buf[recvLen+i]);
			}

		if (wifi_code == WIFI_STATUS_OK) {
			recvLen += ret;
		} else {
			IOT_ERROR("mbedtls_ssl_read = %d", -wifi_code);
			return recvLen;
		}
	} while(recvLen < len && !iot_os_timer_isexpired(timer));

	for (int i=0; i< recvLen; i++) {
		printf("%02x ", buf[i]);
	}
	IOT_DEBUG("############READ BUFFER#############");

	IOT_WARN("FLOW");
	return recvLen;
}

static int _iot_net_tls_write(iot_net_interface_t *net,
		unsigned char *buf, int len, iot_os_timer timer)
{
	int sentLen = 0, ret = 0, wifi_code;

	IOT_DEBUG("%d@%p", len, buf);

	IOT_DEBUG("############WRITE BUFFER#############");
	for (int i=0; i< len; i++) {
		printf("%02x ", buf[i]);
	}
	IOT_DEBUG("############WRITE END#############");
	if (_iot_net_check_interface(net)) {
		return 0;
	}
	IOT_WARN("FLOW");
	do {
//		ret = mbedtls_ssl_write(&net->context.ssl, buf + sentLen, (size_t)len - sentLen);
		wifi_code = WIFI_SendData(net->context.fd, buf + sentLen, (size_t)len - sentLen, &ret, WIFI_WRITE_TIMEOUT);

		if (wifi_code == WIFI_STATUS_OK) {
			sentLen += ret;
		} else {
			IOT_ERROR("ssl_write = %d\n", -ret);
			return -1;
		}
	} while (sentLen < len && !iot_os_timer_isexpired(timer));


	IOT_WARN("FLOW");
	return sentLen;
}

iot_error_t iot_net_init(iot_net_interface_t *net)
{
	iot_error_t err;
	IOT_WARN("FLOW");
	err = _iot_net_check_interface(net);
	if (err) {
		return err;
	}
	IOT_WARN("FLOW");
	net->connect = _iot_net_tls_connect;
	net->disconnect = _iot_net_tls_disconnect;
	net->select = _iot_net_select;
	net->read = _iot_net_tls_read;
	net->write = _iot_net_tls_write;
	net->show_status = _iot_net_show_status;
	IOT_WARN("FLOW");
	return IOT_ERROR_NONE;
}
