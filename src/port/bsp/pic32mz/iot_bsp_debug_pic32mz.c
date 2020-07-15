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
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "iot_bsp_debug.h"
#include "FreeRTOS.h"
#include "system_definitions.h"


//notice that we can max print log size is DEBUG_PRINT_BUFFER_SIZE
#define IOT_LOG_SIZE 512
#define IOT_BUFFER_SIZE (3 * SYS_CMD_PRINT_BUFFER_SIZE)
static char iot_dbg_buf[IOT_BUFFER_SIZE];
static char tmp_buf[IOT_LOG_SIZE];
static int buff_pos = 0;

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	size_t header_len = 0;
	size_t len = 0;
	size_t padding = 0;
	va_list args;

	if (level == IOT_DEBUG_LEVEL_ERROR) {
		snprintf(tmp_buf, IOT_LOG_SIZE, "E: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		snprintf(tmp_buf, IOT_LOG_SIZE, "W: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		snprintf(tmp_buf, IOT_LOG_SIZE, "I: %s ", tag);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		snprintf(tmp_buf, IOT_LOG_SIZE, "D: %s ", tag);
	} else {
		snprintf(tmp_buf, IOT_LOG_SIZE, "D: %s ", tag);
	}

	header_len = strlen(tmp_buf);

	va_start( args, fmt );
	len = vsnprintf(&tmp_buf[header_len], (IOT_LOG_SIZE - header_len - 3), fmt, args);
	va_end( args );

	if (len > 0) {
		len += header_len;
		if (len > (IOT_LOG_SIZE - 3))
			len = IOT_LOG_SIZE - 3;

		strncpy(&tmp_buf[len], "\r\n", 3);
		len += 3;

		if (len + buff_pos >= IOT_BUFFER_SIZE) {
			buff_pos = 0;
		}

		strcpy(&iot_dbg_buf[buff_pos], tmp_buf);
		SYS_MESSAGE(&iot_dbg_buf[buff_pos]);

		padding = len % 4;

		if (padding > 0) {
			padding = 4 - padding;
		}

		buff_pos += len + padding;
	}
}
