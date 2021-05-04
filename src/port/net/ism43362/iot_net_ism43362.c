/* ***************************************************************************
 *
 * Copyright (c) 2021 Samsung Electronics All Rights Reserved.
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

#include "iot_net.h"

static void _iot_net_show_status(iot_net_interface_t *net)
{
	return;
}

static int _iot_net_select(iot_net_interface_t *net, unsigned int timeout_ms)
{
	return 0;
}

static iot_error_t _iot_net_tls_connect(iot_net_interface_t *net)
{
	return IOT_ERROR_NONE;
}

static void _iot_net_tls_disconnect(iot_net_interface_t *net)
{
	return;
}

static int _iot_net_tls_read(iot_net_interface_t *net,
		unsigned char *buf, size_t len, iot_os_timer timer)
{
	return 0;
}

static int _iot_net_tls_write(iot_net_interface_t *net,
		unsigned char *buf, int len, iot_os_timer timer)
{
	return 0;
}

iot_error_t iot_net_init(iot_net_interface_t *net)
{
	return IOT_ERROR_NONE;
}
