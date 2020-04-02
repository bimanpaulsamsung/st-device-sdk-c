/******************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
 *
 *
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
#include <reent.h>
#include <sys/time.h>


int _gettimeofday_r(struct _reent* r, struct timeval* tv, void* tz)
{
	struct timespec ts = {0,};

	clock_gettime(CLOCK_REALTIME, &ts);

	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = 0;

	return IOT_ERROR_NONE;
}

int settimeofday(const struct timeval* tv, const struct timezone* tz)
{
	(void) tz;

	struct timespec tspec = {0,};
	if (tv) {
		tspec.tv_nsec = tv->tv_usec * 1000;
		tspec.tv_sec = tv->tv_sec;
		if (clock_settime(CLOCK_REALTIME, &tspec) != 0) {
			IOT_ERROR(" Failed to set current time");
			return IOT_ERROR_WRITE_FAIL;
		}
	}
	return IOT_ERROR_NONE;
}


extern PRCMMCUReset(_Bool bIncludeSubsystem);
void iot_bsp_system_reboot()
{
	PRCMMCUReset(1);
}

void iot_bsp_system_poweroff()
{
	PRCMMCUReset(1);
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	IOT_ERROR_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");
	struct timespec ts = {0,};
	clock_gettime(CLOCK_REALTIME, &ts);
	snprintf(buf, buf_len, "%ld", ts.tv_sec);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	IOT_ERROR_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");
	struct timespec ts = {0,};
	sscanf(time_in_sec, "%ld", &ts.tv_sec);
	clock_settime(CLOCK_REALTIME, &ts);
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_get_uniqueid(unsigned char **uid, size_t *olen)
{
	return IOT_ERROR_NOT_IMPLEMENTED;
}
