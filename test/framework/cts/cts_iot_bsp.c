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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "bsp/iot_bsp_wifi.h"
#include "bsp/iot_bsp_nv_data.h"
#include "bsp/iot_bsp_random.h"
#include "bsp/iot_bsp_system.h"
#include "iot_error.h"

#define RAND_TEST_COUNT (10)

void CTS_iot_bsp_random_verify_randomness(void **state)
{
    unsigned int random_result[10];
    int i, j;

    // When
    for (i = 0; i < RAND_TEST_COUNT; i++) {
        random_result[i] = iot_bsp_random();
    }
    // Then
    for (i = 0; i < RAND_TEST_COUNT; i++) {
        j = i;
        while (++j < RAND_TEST_COUNT) {
            assert_int_not_equal(random_result[i], random_result[j]);
        }
    }
}

void CTS_iot_bsp_system_get_uniqueid_verify_consistency(void **state)
{
    iot_error_t err1, err2;
    unsigned char *unique_id_1;
    unsigned char *unique_id_2;
    size_t out_len_1 = 0;
    size_t out_len_2 = 0;

    // When
    err1 = iot_bsp_system_get_uniqueid(&unique_id_1, &out_len_1);
    err2 = iot_bsp_system_get_uniqueid(&unique_id_2, &out_len_2);

    // Then
    assert_int_equal(err1, IOT_ERROR_NONE);
    assert_true(out_len_1 > 0);

    assert_int_equal(err2, IOT_ERROR_NONE);
    assert_int_equal(out_len_1, out_len_2);
    assert_memory_equal(unique_id_1, unique_id_2, out_len_1);

    // Teardown
    free(unique_id_1);
    free(unique_id_2);
}

void CTS_iot_bsp_wifi_get_mac_verify_consistency(void** state)
{
    iot_error_t err_1, err_2;
    struct iot_mac iotmac_1;
    struct iot_mac iotmac_2;

    // Given
    memset(&iotmac_1, '\0', sizeof(struct iot_mac));
    memset(&iotmac_2, '\0', sizeof(struct iot_mac));

    // When: get mac address twice
    err_1 = iot_bsp_wifi_get_mac(&iotmac_1);
    err_2 = iot_bsp_wifi_get_mac(&iotmac_2);

    // Then: API should return success and two mac address should be same.
    assert_int_equal(err_1, IOT_ERROR_NONE);
    assert_int_equal(err_2, IOT_ERROR_NONE);
    assert_memory_equal(&iotmac_1, &iotmac_2, sizeof(struct iot_mac));
}

void CTS_iot_bsp_nv_get_data_path(void** state)
{
    for (int i = IOT_NVD_WIFI_PROV_STATUS; i < IOT_NVD_MAX; i++) {
        assert_non_null(iot_bsp_nv_get_data_path(i));
    }
}

int CTS_iot_bsp_test()
{
    const struct CMUnitTest CTS_iot_bsp_api[] = {
            cmocka_unit_test(CTS_iot_bsp_random_verify_randomness),
            cmocka_unit_test(CTS_iot_bsp_system_get_uniqueid_verify_consistency),
            cmocka_unit_test(CTS_iot_bsp_wifi_get_mac_verify_consistency),
            cmocka_unit_test(CTS_iot_bsp_nv_get_data_path),
    };

    return cmocka_run_group_tests_name("iot_bsp", CTS_iot_bsp_api, NULL, NULL);
}