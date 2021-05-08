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

#include "iot_bsp_debug.h"
#include "stm32l4xx_hal.h"
#include "iot_debug.h"

#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET "\x1b[0m"
#define BUF_SIZE 512

#ifdef __GNUC__
	#define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#else
	#define PUTCHAR_PROTOTYPE int fputc(int ch, FILE *f)
#endif

static UART_HandleTypeDef huart1;
static bool uart_init_flag = false;

PUTCHAR_PROTOTYPE
{
	HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 10);
	return ch;
}

static void MX_USART1_UART_Init(void)
{
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    __disable_irq();
	while (1)
	{
		/* User can add his own implementation to report the HAL error return state */
		break;
	}
  }
}

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
	char buf[BUF_SIZE] = {0,};
	va_list va;

	if (uart_init_flag == false) {
		uart_init_flag = true;
		MX_USART1_UART_Init();
	}

	va_start(va, fmt);
	vsnprintf(buf, BUF_SIZE, fmt, va);
	va_end(va);

	if (level == IOT_DEBUG_LEVEL_ERROR) {
		printf(COLOR_RED"E %s: %s\r\n"COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_WARN) {
		printf(COLOR_YELLOW"W %s: %s\r\n"COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_INFO) {
		printf(COLOR_GREEN"I %s: %s\r\n"COLOR_RESET, tag, buf);
	} else if (level == IOT_DEBUG_LEVEL_DEBUG) {
		printf("D %s: %s\r\n", tag, buf);
	} else {
		printf("D %s: %s\r\n", tag, buf);
	}
}

void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
	return;
}
