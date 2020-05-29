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

#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <netinet/in.h>
#include <unistd.h>
#endif
#include "../easysetup_http.h"
#include "iot_os_util.h"
#include "iot_debug.h"
#include "iot_easysetup.h"

#define PORT 8888
#define RX_BUFFER_MAX    1024

static char *tx_buffer = NULL;

static iot_os_thread es_tcp_task_handle = NULL;

static int listen_sock = -1;
static int deinit_processing = 0;

static void _clear_listen_socket(void)
{
	if (listen_sock != -1) {
		IOT_INFO("Shutting down listen socket");
		shutdown(listen_sock, SHUT_RD);
		close(listen_sock);
		listen_sock = -1;
	}
}

static void es_tcp_task(void *pvParameters)
{
	char *payload = NULL;
	char rx_buffer[RX_BUFFER_MAX];
	int addr_family, ip_protocol, sock, ret, len, type, cmd;
	iot_error_t err = IOT_ERROR_NONE;
	struct sockaddr_in sourceAddr;
	size_t content_len;
	uint addrLen;

	while (!deinit_processing) {
		struct sockaddr_in destAddr;
		destAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		destAddr.sin_family = AF_INET;
		destAddr.sin_port = htons(PORT);
		addr_family = AF_INET;
		ip_protocol = IPPROTO_IP;

		listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
		if (listen_sock < 0) {
			IOT_ERROR("Unable to create socket: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CREATE_FAIL, errno);
			break;
		}

		ret = bind(listen_sock, (struct sockaddr *)&destAddr, sizeof(destAddr));
		if (ret != 0) {
			IOT_ERROR("Socket unable to bind: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_BIND_FAIL, errno);
			break;
		}

		ret = listen(listen_sock, 1);
		if (ret != 0) {
			IOT_ERROR("Error occurred during listen: errno %d", errno);
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_LISTEN_FAIL, errno);
			break;
		}

		while (1) {
			addrLen = sizeof(sourceAddr);
			content_len = 0;

			sock = accept(listen_sock, (struct sockaddr *)&sourceAddr, &addrLen);
			if (sock < 0) {
				IOT_ERROR("Unable to accept connection: errno %d", errno);
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_ACCEPT_FAIL, errno);
				break;
			}

			memset(rx_buffer, '\0', sizeof(rx_buffer));

			len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);

			if (len < 0) {
				IOT_ERROR("recv failed: errno %d", errno);
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
				break;
			}
			else if (len == 0) {
				IOT_ERROR("Connection closed");
				IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_CON_CLOSE, 0);
				break;
			}
			else {
				rx_buffer[len] = '\0';

				err = es_msg_parser(rx_buffer, &payload, &cmd, &type, &content_len);

				if ((err == IOT_ERROR_NONE) && (content_len > strlen((char *)payload)))
				{
					memset(rx_buffer, '\0', sizeof(rx_buffer));
					len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
					if (len < 0) {
						IOT_ERROR("recv failed: errno %d", errno);
						IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_RECV_FAIL, errno);
						break;
					}
					payload = rx_buffer;
				}

				if(err == IOT_ERROR_INVALID_ARGS)
					http_msg_handler(cmd, &tx_buffer, D2D_ERROR, payload);
				else
					http_msg_handler(cmd, &tx_buffer, type, payload);

				if (!tx_buffer) {
					IOT_ERROR("tx_buffer is NULL");
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_INTERNAL_SERVER_ERROR, 0);
					break;
				}

				len = strlen((char *)tx_buffer);
				tx_buffer[len] = 0;

				ret = send(sock, tx_buffer, len, 0);
				if (ret < 0) {
					IOT_ERROR("Error is occurred during sending: errno %d", ret);
					IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_SEND_FAIL, ret);
					break;
				}
				if (tx_buffer) {
					free(tx_buffer);
					tx_buffer = NULL;
				}
				//Transfer finished in this loop, sock resources should be clean.
				shutdown(sock, SHUT_RD);
				close(sock);
				sock = -1;
			}
		}

		if (sock != -1) {
			IOT_ERROR("Shutting down socket and restarting...");
			IOT_ES_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_EASYSETUP_SOCKET_SHUTDOWN, ret);
			shutdown(sock, SHUT_RD);
			close(sock);
		}
		//sock resources should be clean
		if (!deinit_processing) {
			_clear_listen_socket();
		}
	}

	if (!deinit_processing) {
		_clear_listen_socket();
	}

	/*set es_tcp_task_handle to null, prevent dulicate delete in es_tcp_deinit*/
	es_tcp_task_handle = NULL;
	iot_os_thread_delete(NULL);
}


void es_http_init(void)
{
	IOT_INFO("http tcp init!!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 0);
	iot_os_thread_create(es_tcp_task, "es_tcp_task", (1024 * 4), NULL, 5, (iot_os_thread * const)(&es_tcp_task_handle));
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_INIT, 1);
}

void es_http_deinit(void)
{
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 0);

	deinit_processing = 1;
	//sock resources should be clean
	_clear_listen_socket();

	if (es_tcp_task_handle) {
		iot_os_thread_delete(es_tcp_task_handle);
		es_tcp_task_handle = NULL;
	}

	if (tx_buffer) {
		free(tx_buffer);
		tx_buffer = NULL;
	}

	deinit_processing = 0;
	IOT_INFO("http tcp deinit complete!");
	IOT_ES_DUMP(IOT_DEBUG_LEVEL_INFO, IOT_DUMP_EASYSETUP_TCP_DEINIT, 1);
}

