/* ***************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
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
#include "iot_easysetup_http_impl.h"
#include "iot_easysetup.h"

#define HTTP_PORT 8888

bool is_http_conn_handle_initialized(HTTP_CONN_H *handle)
{
	return true;
}

void http_cleanup_all_connection(HTTP_CONN_H *handle)
{
	return;
}

void http_cleanup_accepted_connection(HTTP_CONN_H *handle)
{
	return;
}

ssize_t http_packet_send(HTTP_CONN_H *handle, char *tx_buffer, size_t tx_buffer_len)
{
	return 0;
}

iot_error_t http_packet_read(HTTP_CONN_H *handle, char *rx_buffer, size_t rx_buffer_size, size_t *received_len,
							 size_t *http_header_len)
{
	return IOT_ERROR_NONE;
}

iot_error_t http_packet_read_remaining(HTTP_CONN_H *handle, char *rx_buffer, size_t rx_buffer_size, size_t offset,
									   size_t expected_len)
{
	return IOT_ERROR_NONE;
}

void http_try_configure_connection(HTTP_CONN_H *handle)
{
	return;
}

iot_error_t http_initialize_connection(HTTP_CONN_H *handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t http_accept_connection(HTTP_CONN_H *handle)
{
	return IOT_ERROR_NONE;
}
