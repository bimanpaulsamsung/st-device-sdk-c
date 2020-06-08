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

struct eventgroup_single_set_test_data {
    unsigned int bits_to_set;
    unsigned int bits_to_wait_for;
    unsigned int expected_return_for_wait;
    int clear_on_exit;
    unsigned int wait_time_ms;
};
// This test purposed to test return value and event clearance
// Given: set single bit
// When: wait in various condition
// Then: return bits_to_set and event cleared
void CTS_iot_os_eventgroup_wait_bits_SET_SINGLE_BIT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    struct eventgroup_single_set_test_data test_data[] = {
            {BIT_0, BIT_0, BIT_0, 1, 5},
            {BIT_0, BIT_0, BIT_0, 0, 5},
            {BIT_0, BIT_ALL, BIT_0, 1, 5},
            {BIT_0, BIT_ALL, BIT_0, 0, 5},
    };

    for (int i = 0; i < sizeof(test_data)/sizeof(struct eventgroup_single_set_test_data); i++) {
        int result;
        unsigned int event;
        // Given
        result = iot_os_eventgroup_set_bits(event_group, test_data[i].bits_to_set);
        assert_int_equal(result, IOT_OS_TRUE);
        // When
        event = iot_os_eventgroup_wait_bits(event_group, test_data[i].bits_to_wait_for, test_data[i].clear_on_exit, test_data[i].wait_time_ms);
        // Then
        assert_int_equal(event, test_data[i].expected_return_for_wait);
        // Teardown
        result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
        assert_int_equal(result, IOT_OS_TRUE);
    }
}

// This test purposed to test return value and event clearance
// Given: set multi bits
// When: wait in various condition
// Then: return bits_to_set and all events cleared
void CTS_iot_os_eventgroup_wait_bits_SET_MULTI_BITS(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    struct eventgroup_single_set_test_data test_data[] = {
            {BIT_0 | BIT_2, BIT_0, BIT_0 | BIT_2, 1, 5},
            {BIT_0 | BIT_2, BIT_0, BIT_0 | BIT_2, 0, 5},
    };

    for (int i = 0; i < sizeof(test_data)/sizeof(struct eventgroup_single_set_test_data); i++) {
        int result;
        unsigned int event;
        // Given
        result = iot_os_eventgroup_set_bits(event_group, test_data[i].bits_to_set);
        assert_int_equal(result, IOT_OS_TRUE);
        // When
        event = iot_os_eventgroup_wait_bits(event_group, test_data[i].bits_to_wait_for, test_data[i].clear_on_exit, test_data[i].wait_time_ms);
        // Then
        assert_int_equal(event, test_data[i].expected_return_for_wait);
        // Teardown
        result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
        assert_int_equal(result, IOT_OS_TRUE);
    }
}


// This test purposed to test return value and event clearance
// Given: set bits
// When: wait which causes timeout in various condition
// Then: return bits_to_set and event not cleared
void CTS_iot_os_eventgroup_wait_bits_TIMEOUT(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    struct eventgroup_single_set_test_data test_data[] = {
            {BIT_0, BIT_1, BIT_0, 1, 3},
            {BIT_0, BIT_1, BIT_0, 0, 3},
            {BIT_0, BIT_1 | BIT_3, BIT_0, 1, 3},
            {BIT_0, BIT_1 | BIT_3, BIT_0, 0, 3},
            {BIT_0 | BIT_2, BIT_1 | BIT_3, BIT_0 | BIT_2, 1, 3},
            {BIT_0 | BIT_2, BIT_1 | BIT_3, BIT_0 | BIT_2, 0, 3},
    };

    for (int i = 0; i < sizeof(test_data)/sizeof(struct eventgroup_single_set_test_data); i++) {
        int result;
        unsigned int event;
        // Given
        result = iot_os_eventgroup_set_bits(event_group, test_data[i].bits_to_set);
        assert_int_equal(result, IOT_OS_TRUE);
        // When
        event = iot_os_eventgroup_wait_bits(event_group, test_data[i].bits_to_wait_for, test_data[i].clear_on_exit, test_data[i].wait_time_ms);
        // Then
        assert_int_equal(event, test_data[i].expected_return_for_wait);
        // Teardown
        result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
        assert_int_equal(result, IOT_OS_TRUE);
    }
}

struct eventgroup_double_set_test_data {
    unsigned int bits_to_set_1;
    unsigned int bits_to_set_2;
    unsigned int bits_to_wait_for;
    unsigned int expected_return_for_wait;
    int clear_on_exit;
    unsigned int wait_time_ms;
};
// This test purposed to test return value and event clearance
// Given: set bits with seperated call
// When: wait which causes timeout in various condition
// Then: return bits_to_set and event not cleared
void CTS_iot_os_eventgroup_wait_bits_MULTIPLE_SET(void** state)
{
    iot_os_eventgroup *event_group = (iot_os_eventgroup *) *state;
    struct eventgroup_double_set_test_data test_data[] = {
            {BIT_0, BIT_1, BIT_1, BIT_0 | BIT_1, 1, 3},
            {BIT_0, BIT_1, BIT_1, BIT_0 | BIT_1, 0, 3},
            {BIT_0, BIT_1, BIT_1 | BIT_3, BIT_0 | BIT_1, 1, 3},
            {BIT_0, BIT_1, BIT_1 | BIT_3, BIT_0 | BIT_1, 0, 3},
            {BIT_0 | BIT_1, BIT_1 | BIT_2, BIT_0, BIT_0 | BIT_1 | BIT_2, 1, 3},
            {BIT_0 | BIT_1, BIT_1 | BIT_2, BIT_0, BIT_0 | BIT_1 | BIT_2, 0, 3},
            {BIT_0 | BIT_1, BIT_1 | BIT_2, BIT_ALL, BIT_0 | BIT_1 | BIT_2, 1, 3},
            {BIT_0 | BIT_1, BIT_1 | BIT_2, BIT_ALL, BIT_0 | BIT_1 | BIT_2, 0, 3},
    };

    for (int i = 0; i < sizeof(test_data)/sizeof(struct eventgroup_double_set_test_data); i++) {
        int result;
        unsigned int event;
        // Given
        result = iot_os_eventgroup_set_bits(event_group, test_data[i].bits_to_set_1);
        assert_int_equal(result, IOT_OS_TRUE);
        result = iot_os_eventgroup_set_bits(event_group, test_data[i].bits_to_set_2);
        assert_int_equal(result, IOT_OS_TRUE);
        // When
        event = iot_os_eventgroup_wait_bits(event_group, test_data[i].bits_to_wait_for, test_data[i].clear_on_exit, test_data[i].wait_time_ms);
        // Then
        assert_int_equal(event, test_data[i].expected_return_for_wait);
        // Teardown
        result = iot_os_eventgroup_clear_bits(event_group, BIT_ALL);
        assert_int_equal(result, IOT_OS_TRUE);
    }
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
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_SET_SINGLE_BIT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_SET_MULTI_BITS),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_TIMEOUT),
            cmocka_unit_test(CTS_iot_os_eventgroup_wait_bits_MULTIPLE_SET),
    };

    return cmocka_run_group_tests_name("iot_os_eventgroup", CTS_iot_os_eventgroup_api,
                                       CTS_iot_os_eventgroup_wait_bits_SETUP, CTS_iot_os_eventgroup_wait_bits_TEARDOWN);
}