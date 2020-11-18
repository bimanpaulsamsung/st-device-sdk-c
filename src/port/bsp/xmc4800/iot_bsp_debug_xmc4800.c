/******************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include "FreeRTOSConfig.h"
#include "iot_bsp_debug.h"

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	va_list va;
	unsigned int time = 0;

	if (level == IOT_DEBUG_LEVEL_ERROR) {
		printf("E: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		printf("W: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		printf("I: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		printf("D: %s ", tag);
	} else {
		printf("D: %s ", tag);
	}

	//Transfer ticks to ms
	time = (1000 / configTICK_RATE_HZ) * xTaskGetTickCount();
	printf("[%u] ", time);

	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);

	printf("\r\n");
}

void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
}
