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

#include "iot_bsp_system.h"
#include "iot_debug.h"
#include <sys/time.h>
#include <time.h>
#include "FreeRTOSConfig.h"
#include "xmc_wdt.h"

volatile struct timeval current_time;
unsigned int time_set_tick;

#define US_PER_SEC  (1000 * 1000)

XMC_WDT_CONFIG_t WATCHDOG_0_Config =
{
	.window_upper_bound   = 0x10U,
	.window_lower_bound   = 0x0U,
	.prewarn_mode         = false,
	.run_in_debug_mode    = 0U,
	.service_pulse_width  = 0U
};

void iot_bsp_system_reboot()
{
	XMC_WDT_Init(&WATCHDOG_0_Config);
	XMC_WDT_Start();
}

void iot_bsp_system_poweroff()
{
	XMC_WDT_Init(&WATCHDOG_0_Config);
	XMC_WDT_Start();
}

int gettimeofday(struct timeval *tv , void *tz)
{
	unsigned int tick_past = 0;

	if(tv) {
		/* XMC4800 timer freq 1tick = 1ms */
		tick_past = xTaskGetTickCount() - time_set_tick;

		tv->tv_sec = current_time.tv_sec + (tick_past / configTICK_RATE_HZ);
		tv->tv_usec = current_time.tv_usec + (tick_past % configTICK_RATE_HZ) * 1000;

		tv->tv_sec += tv->tv_usec / US_PER_SEC;
		tv->tv_usec %= US_PER_SEC;
	}
	return 0;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz)
{
	if (tv) {
		current_time.tv_usec = tv->tv_usec;
		current_time.tv_sec= tv->tv_sec;
		time_set_tick = xTaskGetTickCount();
	}
	return 0;
}

time_t time(time_t *tod)
{
	static time_t t;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	t = (time_t)tv.tv_sec;
	if (tod != NULL)
		*tod = t;
	return t;
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
	IOT_ERROR_CHECK(buf == NULL, IOT_ERROR_INVALID_ARGS, "buffer for time is NULL");
	struct timeval tv = {0,};

	gettimeofday(&tv, NULL);
	snprintf(buf, buf_len, "%ld", tv.tv_sec);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
	IOT_ERROR_CHECK(time_in_sec == NULL, IOT_ERROR_INVALID_ARGS, "time data is NULL");

	struct timeval tv = {0,};

	sscanf(time_in_sec, "%ld", &tv.tv_sec);
	settimeofday(&tv, NULL);

	return IOT_ERROR_NONE;
}

const char* iot_bsp_get_bsp_name()
{
	return "xmc4800";
}

const char* iot_bsp_get_bsp_version_string()
{
	return "";
}
