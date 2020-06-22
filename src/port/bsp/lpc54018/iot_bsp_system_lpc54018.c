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

#include "iot_bsp_system.h"
#include "iot_debug.h"
#include "FreeRTOS.h"
#include "task.h"
#include "qcom_api.h"
#include <time.h>

static uint64_t s_boot_time;

const char* iot_bsp_get_bsp_name()
{
	return "lpc54018";
}

const char* iot_bsp_get_bsp_version_string()
{
	return "";
}

int __wrap_gettimeofday(struct timeval* tv, void* tz)
{
	uint64_t msec;

	(void) tz;
	if (tv) {
		msec = s_boot_time + A_TIME_GET_MSEC();
		tv->tv_sec = msec / 1000;
		tv->tv_usec = (msec  % 1000) * 1000;
	}

	return 0;
}

int _settimeofday(const struct timeval* tv, const struct timezone* tz)
{
	uint64_t now;
	uint64_t since_boot;

	(void) tz;

	if (tv) {
		now = ((uint64_t) tv->tv_sec) * 1000000LL + tv->tv_usec;
		now /=  1000;
		since_boot = A_TIME_GET_MSEC();
		s_boot_time = (now - since_boot);
	}

	return 0;
}

void iot_bsp_system_reboot()
{
	boot_cpureset();
}

void iot_bsp_system_poweroff()
{
	boot_cpureset();
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	struct timeval tv = {0,};

	IOT_ERROR_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");

	gettimeofday(&tv, NULL);
	snprintf(buf, buf_len, "%ld", tv.tv_sec);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	struct timeval tv = {0,};

	IOT_ERROR_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	sscanf(time_in_sec, "%ld", &tv.tv_sec);
	_settimeofday(&tv, NULL);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_get_uniqueid(unsigned char **uid, size_t *olen)
{
	return IOT_ERROR_NOT_IMPLEMENTED;
}
