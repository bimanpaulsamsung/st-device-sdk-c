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

#include "iot_bsp_random.h"
#include "iot_debug.h"
#include <stdlib.h>
#include "trng_api.h"

unsigned int iot_bsp_random()
{
	trng_t obj;
	uint32_t randomInt;
	size_t output_length;

	trng_init(&obj);
	int ret = trng_get_bytes(&obj, (uint8_t *)&randomInt,
			sizeof(randomInt), &output_length);
	trng_free(&obj);

	if (ret != 0) {
		IOT_ERROR("Random Number generation failed");
		return 0;
	}

	return randomInt;
}
