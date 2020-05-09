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

#include "iot_bsp_random.h"
#include "fsl_common.h"
#include "rng.h"
#include "iot_debug.h"
#include "qcom_api.h"

unsigned int iot_bsp_random()
{
	hal_rng_status_t status;
	unsigned int randomNumber;
	static int seed = 0;

	status = HAL_RngGetData(&randomNumber, sizeof(randomNumber));
	if (status != kStatus_HAL_RngSuccess) {
		IOT_ERROR("HAL_RngGetData status failed.");
		if (!seed) {
			srand(A_TIME_GET_MSEC());
			seed = 1;
		}
		randomNumber = rand();
	}
	return randomNumber;
}

