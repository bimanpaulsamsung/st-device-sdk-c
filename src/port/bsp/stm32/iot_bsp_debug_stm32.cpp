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
#include <stdarg.h>

#include "iot_bsp_debug.h"
#include "mbed.h"
#include "platform/mbed_assert.h"
#include "platform/mbed_debug.h"
#include "platform/mbed_error.h"
#include "platform/mbed_stats.h"

#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET "\x1b[0m"
#define BUF_SIZE 512
#define MAX_THREAD_INFO 10

Mutex mutex;
mbed_stats_heap_t heap_info;
mbed_stats_stack_t stack_info[ MAX_THREAD_INFO ];

void iot_bsp_dump(char* buf)
{
	/* TODO: implement dump */
}

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	char buf[BUF_SIZE] = {0,};
	va_list va;

	va_start(va, fmt);
	vsnprintf(buf, BUF_SIZE, fmt, va);
	va_end(va);

	iot_bsp_dump(buf);
	mutex.lock();
	if (level == IOT_DEBUG_LEVEL_ERROR) {
		printf(COLOR_RED "E %s: %s\n" COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		printf(COLOR_YELLOW "W %s: %s\n" COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		printf(COLOR_GREEN "I %s: %s\n" COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		printf("D %s: %s\n", tag, buf);
	} else {
		printf("D %s: %s\n", tag, buf);
	}
	mutex.unlock();
}

void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
	static int count = 0;
	char buf[BUF_SIZE] = {0,};
	va_list va;

	va_start(va, fmt);
	vsnprintf(buf, BUF_SIZE, fmt, va);
	va_end(va);

	/* Need to enable MBED_HEAP_STATS_ENABLED macro in mbed os for this function to work */
	mbed_stats_heap_get(&heap_info);

	if (count == 0) {
		iot_bsp_debug(IOT_DEBUG_LEVEL_WARN, tag, "%s(%d) > [MEMCHK][%d] Heap total size : %d", func, line, count, heap_info.total_size);
	}

	iot_bsp_debug(IOT_DEBUG_LEVEL_WARN, tag, "%s(%d) > " "[MEMCHK][%d][%s] "
			"Current Size:%d, Maximum Size:%d, Total Size:%d, Reserved Size:%d, Overhead Size:%d", func, line, ++count, buf,
			heap_info.current_size, heap_info.max_size, heap_info.total_size, heap_info.reserved_size, heap_info.overhead_size);
}
