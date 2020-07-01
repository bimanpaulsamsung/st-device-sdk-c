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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "platform/mbed_rtc_time.h"
#include "iot_bsp_system.h"
#include "iot_debug.h"
#include "mbed.h"
#include "rtc_api.h"

const char* iot_bsp_get_bsp_name()
{
	return "rda5981c";
}

const char* iot_bsp_get_bsp_version_string()
{
	return "";
}

int _gettimeofday_r(struct _reent* r, struct timeval* tv, void* tz)
{
	uint64_t msec;

	(void) tz;

	if (!(rtc_isenabled())) {
		set_time(0);
	}

	time_t t = 0;
	t = rtc_read();  // return seconds

	if (tv) {
		tv->tv_sec = t;
		tv->tv_usec = 0;
	}

	return 0;
}

void iot_bsp_system_reboot()
{
	NVIC_SystemReset();
}

void iot_bsp_system_poweroff()
{
	NVIC_SystemReset();
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	IOT_WARN_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");

	time_t seconds = time(NULL);

	snprintf(buf, buf_len, "%lld", seconds);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	IOT_WARN_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	time_t seconds;

	sscanf(time_in_sec, "%lld", &seconds);
	set_time(seconds);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_get_uniqueid(unsigned char **uid, size_t *olen)
{
	return IOT_ERROR_NOT_IMPLEMENTED;
}
