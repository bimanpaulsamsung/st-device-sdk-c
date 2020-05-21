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
#include <iot_debug.h>
#include "os/iot_os_util.h"

struct cts_queue_data {
    int number;
    char name[20];
};

void CTS_iot_os_queue_BASIC_OPERATION(void** state)
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

#define BIT_0 (1u << 0u)
#define BIT_1 (1u << 1u)
#define BIT_2 (1u << 2u)
#define BIT_3 (1u << 3u)
#define BIT_ALL (BIT_0 | BIT_1 | BIT_2 | BIT_3)

int CTS_iot_os_eventgroup_wait_bits_SETUP(void** state)
{
    iot_os_eventgroup *event_group = NULL;

    event_group = iot_os_eventgroup_create();
    assert_non_null(event_group);
    *state = (void*) event_group;

    return 0;
}

int CTS_iot_os_eventgroup_wait_bits_TEARDOWN(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *)*state;

    iot_os_eventgroup_delete(event_group);

    return 0;
}

// This test purposed to test return value and event clearance
// Given: multiple bits are set to bits_to_set
// When: wait single bit with clear_on_exit option
// Then: return bits_to_set and event cleared
void CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_SINGLE_BIT_WAIT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0, 3
    result = iot_os_eventgroup_set_bits(event_group, BIT_0 | BIT_3);
    assert_int_equal(result, BIT_0 | BIT_3);
    // When: wait until bit 0 set (clear_on_exit true)
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0, 1, 0, 5);
    // Then: get bits_to_set (0, 3)
    assert_int_equal(result, BIT_0 | BIT_3);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, BIT_3);
}

// This test purposed to test return value and event clearance
// Given: multiple bits are set to bits_to_set
// When: wait multiple bits with clear_on_exit option
// Then: return bits_to_set and all events cleared
void CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_MULTI_BITS_WAIT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0, 3
    result = iot_os_eventgroup_set_bits(event_group, BIT_0 | BIT_3);
    assert_int_equal(result, BIT_0 | BIT_3);
    // When: wait until bit 0, 3 set (clear_on_exit true)
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0 | BIT_3, 1, 0, 5);
    // Then: get bits_to_set (0, 3)
    assert_int_equal(result, BIT_0 | BIT_3);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, 0);
}


// This test purposed to test return value and event clearance
// Given: multiple bits are set to bits_to_set
// When: wait single bit without clear_on_exit option
// Then: return bits_to_set and event not cleared
void CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_SINGLE_BIT_WAIT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0, 3
    result = iot_os_eventgroup_set_bits(event_group, BIT_0 | BIT_3);
    assert_int_equal(result, BIT_0 | BIT_3);
    // When: wait until bit 0 set (clear_on_exit false)
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0, 0, 0, 5);
    // Then: get bit 0, 3
    assert_int_equal(result, BIT_0 | BIT_3);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, BIT_0 | BIT_3);
}

// This test purposed to test return value and event clearance
// Given: single bit is set to bits_to_set
// When: wait multiple bits without clear_on_exit, wait_for_all_bits option
// Then: return bits_to_set and all events cleared
void CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WAIT_MULTI_BITS(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0
    result = iot_os_eventgroup_set_bits(event_group, BIT_0);
    assert_int_equal(result, BIT_0);
    // When: wait until any of bit 0, 3 set
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0 | BIT_3, 0, 0, 5);
    // Then: get bit 0
    assert_int_equal(result, BIT_0);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, BIT_0);
}

// This test purposed to test return value and event clearance
// Given: single bit is set to bits_to_set
// When: wait with wait_for_all_bits enabled, but clear_on_exit disabled to make timeout
// Then: return bits_to_set and all events cleared
void CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WAIT_FOR_ALL_BITS_TIMEOUT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0
    result = iot_os_eventgroup_set_bits(event_group, BIT_0);
    assert_int_equal(result, BIT_0);
    // When: wait until any of bit 0, 3 set
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0 | BIT_3, 0, 1, 5);
    // Then: get bit 0
    assert_int_equal(result, BIT_0);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, BIT_0);
}

// This test purposed to test return value and event clearance
// Given: single bit is set to bits_to_set
// When: wait with wait_for_all_bits, clear_on_exit enabled to make timeout
// Then: return bits_to_set and all events cleared
void CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_WAIT_FOR_ALL_BITS_TIMEOUT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0
    result = iot_os_eventgroup_set_bits(event_group, BIT_0);
    assert_int_equal(result, BIT_0);
    // When: wait until any of bit 0, 3 set
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0 | BIT_3, 1, 1, 5);
    // Then: get bit 0
    assert_int_equal(result, BIT_0);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, BIT_0);
}

// This test purposed to test return value and event clearance
// Given: single bit is set to bits_to_set
// When: wait any bits with clear_on_exit option
// Then: return bits_to_set and all events cleared
void CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_ANY_BITS_WAIT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0
    result = iot_os_eventgroup_set_bits(event_group, BIT_0);
    assert_int_equal(result, BIT_0);
    // When: wait until any of bits set (clear_on_exit true)
    result = iot_os_eventgroup_wait_bits(event_group, BIT_ALL, 1, 0, 5);
    // Then: get bits_to_set (0)
    assert_int_equal(result, BIT_0);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, 0);
}

// This test purposed to test return value and event clearance
// Given: multiple bits are set to bits_to_set
// When: wait multiple bits with wait_for_all_bits enabled, but clear_on_exit disabled.
// Then: return bits_to_set and events remained
void CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WAIT_ALL_BITS(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 0, 3
    result = iot_os_eventgroup_set_bits(event_group, BIT_0 | BIT_3);
    assert_int_equal(result, BIT_0 | BIT_3);
    // When: wait until both of bit 0, 3 set
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0 | BIT_3, 0, 1, 5);
    // Then: get bit 0, 3
    assert_int_equal(result, BIT_0 | BIT_3);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, BIT_0 | BIT_3);
}

// This test purposed to test return value and event clearance
// Given: multiple bits are set to bits_to_set
// When: wait different bits to make timeout with wait_for_all_bits enabled, but clear_on_exit disabled.
// Then: return bits_to_set and events remained
void CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WITH_TIMEOUT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    unsigned int result = 0;

    // Given: set bit 1, 2
    result = iot_os_eventgroup_set_bits(event_group, BIT_1 | BIT_2);
    assert_int_equal(result, BIT_1 | BIT_2);
    // When: wait until both of bit 0, 3 set
    result = iot_os_eventgroup_wait_bits(event_group, BIT_0 | BIT_3, 0, 1, 3);
    // Then: get value without bit 0, 3 - timeout
    assert_int_equal(result, BIT_1 | BIT_2);
    // Teardown
    result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
    assert_int_equal(result, BIT_1 | BIT_2);
}

int CTS_iot_os_queue_test()
{
    const struct CMUnitTest CTS_iot_os_queue_api[] = {
            cmocka_unit_test(CTS_iot_os_queue_BASIC_OPERATION),
    };

    return cmocka_run_group_tests_name("iot_os_queue", CTS_iot_os_queue_api, NULL, NULL);
}

int CTS_iot_os_eventgroup_test()
{
    const struct CMUnitTest CTS_iot_os_eventgroup_api[] = {
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_SINGLE_BIT_WAIT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_MULTI_BITS_WAIT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_SINGLE_BIT_WAIT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WAIT_FOR_ALL_BITS_TIMEOUT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_WAIT_FOR_ALL_BITS_TIMEOUT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WAIT_MULTI_BITS),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_CLEAR_ON_EXIT_ANY_BITS_WAIT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WAIT_ALL_BITS),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_NOT_CLEAR_ON_EXIT_WITH_TIMEOUT),
    };

    return cmocka_run_group_tests_name("iot_os_eventgroup", CTS_iot_os_eventgroup_api,
                CTS_iot_os_eventgroup_wait_bits_SETUP, CTS_iot_os_eventgroup_wait_bits_TEARDOWN);
}