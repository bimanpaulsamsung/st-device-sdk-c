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
#include "trng_api.h"

static trng_t trng_obj;

unsigned int iot_bsp_random()
{
	uint32_t randNum;
	int32_t len = sizeof(uint32_t);
	size_t olen;

	trng_init(&trng_obj);
	trng_get_bytes(&trng_obj, (uint8_t *)&randNum, len, &olen);

	return randNum;
}
