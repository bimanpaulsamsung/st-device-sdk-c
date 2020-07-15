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
#include <time.h>

unsigned int iot_bsp_random()
{
	static int seed = 0;

#ifdef SYS_RANDOM_USE_CRYPTO_STRENGTH
	if (seed == 0) {
		SYS_RANDOM_CryptoSeedSet(time(NULL), sizeof(time_t));
		seed = 1;
	}

	return SYS_RANDOM_CryptoGet();
#else
	if (seed == 0) {
		SYS_RANDOM_PseudoSeedSet(time(NULL));
		seed = 1;
	}

	return SYS_RANDOM_PseudoGet();
#endif
}
