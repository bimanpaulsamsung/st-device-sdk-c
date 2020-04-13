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
#include <string.h>
#include "os/iot_os_util.h"

struct cts_queue_data {
    int number;
    char name[20];
};

void CTS_iot_os_queue_basic_operation(void** state)
{
    struct cts_queue_data send_data;
    struct cts_queue_data receive_data;
    iot_os_queue *test_queue = NULL;
    int result;

    // Given
    send_data.number = 512;
    strncpy(send_data.name, "Test String", sizeof(send_data.name));

    // When: create queue
    test_queue = iot_os_queue_create(1, sizeof(struct cts_queue_data));
    // Then: success
    assert_non_null(test_queue);
    // When: send data
    result = iot_os_queue_send(test_queue, &send_data, 0);
    // Then: success to send
    assert_int_equal(result, IOT_OS_TRUE);
    // When: receive data
    result = iot_os_queue_receive(test_queue, &receive_data, 0);
    // Then: success to receive and verify data
    assert_int_equal(result, IOT_OS_TRUE);
    assert_int_equal(send_data.number, receive_data.number);
    assert_string_equal(send_data.name, receive_data.name);

    // Teardown
    iot_os_queue_delete(test_queue);
}

int CTS_iot_os_test()
{
    const struct CMUnitTest CTS_iot_os_api[] = {
            cmocka_unit_test(CTS_iot_os_queue_basic_operation),
    };

    return cmocka_run_group_tests_name("iot_os", CTS_iot_os_api, NULL, NULL);
}