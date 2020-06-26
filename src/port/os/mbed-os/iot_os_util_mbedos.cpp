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

#include <string.h>
#include <stdio.h>

#include "iot_error.h"
#include "iot_os_util.h"
#include "iot_debug.h"

#include "cmsis_os2.h"
#include "mbed.h"
#include "MbedStdkQueue.h"
#include "MbedLinkedList.h"
#include "us_ticker_api.h"

#define OS_NAME "ARM MBED"

const unsigned int iot_os_max_delay = osWaitForever;
const unsigned int iot_os_true = 1;
const unsigned int iot_os_false = 0;

typedef void (*callbackFN)(void *); /* define Thread callback function type */

static char mbedversion[10];
static MbedLinkedList threadlist;

/* Thread */
static osPriority_t get_mbed_priority(int priority)
{
	switch (priority) {
	case 0:
		return osPriorityNone;
	case 1:
		return osPriorityIdle;
	case 2:
		return osPriorityLow;
	case 3:
		return osPriorityBelowNormal;
	case 4:
		return osPriorityNormal;
	case 5:
		return osPriorityAboveNormal;
	case 6:
		return osPriorityHigh;
	case 7:
		return osPriorityRealtime;
	default:
		return osPriorityNormal;
	}
}

int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	Thread *thread = new Thread(get_mbed_priority(priority), stack_size, nullptr, name);
	IOT_ERROR_CHECK(!thread, IOT_OS_FALSE, "Memory allocation Failed!!!");

	osStatus status = thread->start(callback((callbackFN)thread_function, data));
	if (status) {
		delete thread;
		return IOT_OS_FALSE;
	}

	if (threadlist.insert(thread) != LINKED_LIST_ERROR_NONE)
		IOT_WARN("Failed to Insert");

	if (thread_handle)
		*thread_handle = thread;

	return IOT_OS_TRUE;
}

static bool comp(void *loopdata, void *compdata)
{
	if (!loopdata || !compdata)
		return false;

	osThreadId_t tid = (osThreadId_t)compdata;
	Thread *t = (Thread *)loopdata;

	if (t->get_id() == tid)
		return true;

	return false;
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{
	Thread *thread = (Thread *)thread_handle;

	if (!thread) {
		osThreadId_t tid = osThreadGetId();
		linked_list_error_t ret  = threadlist.search(comp,
				(void *)tid, (void **)&thread);
		if (ret != LINKED_LIST_ERROR_NONE) {
			IOT_ERROR("Invalid Thread!!!");
			return;
		}
	}
	threadlist.remove(thread);
	delete thread;
}

void iot_os_thread_yield()
{
	osThreadYield();
}

/* Queue */
iot_os_queue* iot_os_queue_create(int queue_length, int item_size)
{
	MbedStdkQueue *queue = new MbedStdkQueue(queue_length, item_size);
	return queue;
}

int iot_os_queue_reset(iot_os_queue* queue_handle)
{
	MbedStdkQueue *queue = (MbedStdkQueue *)queue_handle;
	IOT_ERROR_CHECK(queue == NULL, IOT_OS_FALSE, "Invalid Queue");
	IOT_WARN("Queue Reset");
	queue->queueReset();
	return IOT_OS_TRUE;
}

void iot_os_queue_delete(iot_os_queue* queue_handle)
{
	MbedStdkQueue *queue = (MbedStdkQueue *)queue_handle;
	if (!queue) {
		IOT_ERROR("Queue Delete: Invalid Queue!!!");
		return;
	}
	delete queue;
}

int iot_os_queue_send(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	MbedStdkQueue *queue = (MbedStdkQueue *)queue_handle;
	IOT_ERROR_CHECK(queue == NULL, IOT_OS_FALSE, "Invalid Queue");
	IOT_ERROR_CHECK(data == NULL, IOT_OS_FALSE, "Invalid Data");

	if (queue->put(data, wait_time_ms) != osOK) {
		IOT_ERROR("Failed to put data in queue");
		return IOT_OS_FALSE;
	}
	return IOT_OS_TRUE;
}

int iot_os_queue_receive(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms)
{
	MbedStdkQueue *queue = (MbedStdkQueue *)queue_handle;
	IOT_ERROR_CHECK(queue == NULL, IOT_OS_FALSE, "Invalid Queue");
	IOT_ERROR_CHECK(data == NULL, IOT_OS_FALSE, "Invalid data Buffer");

	IOT_DEBUG("Queue Count: %d", queue->count());
	osEvent evt = queue->get(data, wait_time_ms);
	IOT_DEBUG("Queue STATUS: %d", evt.status);
	if (evt.status == osEventMessage) {
		return IOT_OS_TRUE;
	}
	IOT_ERROR("Failed to get data from queue");
	return IOT_OS_FALSE;
}

/* Event Group */
iot_os_eventgroup* iot_os_eventgroup_create(void)
{
	EventFlags *ef = new EventFlags();
	return ef;
}

void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	if (!ef) {
		IOT_ERROR("Event Delete: Invalid Event!!!");
		return;
	}
	delete ef;
}

unsigned char iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_wait_for, const int clear_on_exit,
		const unsigned int wait_time_ms)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	uint32_t ret;

	IOT_ERROR_CHECK(ef == NULL, IOT_OS_FALSE, "Invalid Event");

	IOT_DEBUG("Any of bits to wait for: 0x%x", bits_to_wait_for);
	ret = ef->wait_any((uint32_t)bits_to_wait_for, wait_time_ms, clear_on_exit);
	if (ret & osFlagsError) {
		IOT_DEBUG("Did not receive Event for bits 0x%x | Ret [0x%x]",
				bits_to_wait_for, ret);
		return 0;
	}
	IOT_DEBUG("Received ANY | Bits: 0x%x | Value: 0x%x", bits_to_wait_for, ret);
	return (unsigned char)ret;
}

int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_set)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_ERROR_CHECK(ef == NULL, IOT_OS_FALSE, "Invalid Event");
	IOT_DEBUG("bits_to_set: 0x%x", bits_to_set);

	uint32_t ret = ef->set((uint32_t)bits_to_set);
	if (ret & osFlagsError)
		return IOT_OS_FALSE;

	return IOT_OS_TRUE;
}

int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_clear)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_ERROR_CHECK(ef == NULL, IOT_OS_FALSE, "Invalid Event");
	IOT_INFO("bits_to_set: 0x%x", bits_to_clear);

	uint32_t ret = ef->clear((uint32_t)bits_to_clear);
	if (ret & osFlagsError)
		return IOT_OS_FALSE;

	return IOT_OS_TRUE;
}

/* Mutex */
int iot_os_mutex_init(iot_os_mutex* mutex)
{
	IOT_ERROR_CHECK(!mutex, IOT_OS_FALSE, "Invalid Parameters!!!");

	Mutex *sem =  new Mutex();
	IOT_ERROR_CHECK(!sem, IOT_OS_FALSE, "Memory Allocation Failed!!!");

	mutex->sem = sem;
	return IOT_OS_TRUE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	IOT_ERROR_CHECK(!mutex || !mutex->sem, IOT_OS_FALSE, "Invalid Parameters!!!");
	Mutex *sem = (Mutex *)mutex->sem;
	osStatus ret = sem->lock();
	if (ret == osOK)
		return IOT_OS_TRUE;

	return  IOT_OS_FALSE;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	IOT_ERROR_CHECK(!mutex, IOT_OS_FALSE, "Invalid Parameters!!!");
	Mutex *sem = (Mutex *)mutex->sem;
	osStatus ret = sem->unlock();

	if (ret == osOK)
		return IOT_OS_TRUE;

	return  IOT_OS_FALSE;
}

void iot_os_mutex_destroy(iot_os_mutex* mutex)
{
	if (!mutex || !mutex->sem) {
		IOT_ERROR("Invalid Parameters!!!");
		return;
	}
	delete (Mutex *)mutex->sem;
	mutex->sem = NULL;
}

/* Delay */
void iot_os_delay(unsigned int delay_ms)
{
	osDelay(delay_ms);
}

static unsigned int xTaskGetTickCount(void)
{
	return (int)rtos::Kernel::get_ms_count(); // TICK in milliseconds
}

static void vTaskSetTimeOutState(unsigned int *mstime)
{
	if (mstime)
		*mstime = xTaskGetTickCount();
}

static bool xTaskCheckForTimeOut(unsigned int begin, unsigned int timeout)
{
	unsigned int mstime = xTaskGetTickCount();

	if (mstime < (begin + timeout))
		return false;

	return true;
}

typedef struct Mbedos_Timer {
	unsigned int msWait;
	unsigned int beginTime;
} Mbedos_Timer;

void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms)
{
	((Mbedos_Timer *)timer)->msWait = timeout_ms; /* convert milliseconds to ticks */
	vTaskSetTimeOutState(&((Mbedos_Timer *)timer)->beginTime); /* Record the time at which this function was entered. */
}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	Mbedos_Timer *mbedos_timer = (Mbedos_Timer *)timer;
	unsigned int cTime = xTaskGetTickCount();

	if (cTime < (mbedos_timer->beginTime + mbedos_timer->msWait))
		return (mbedos_timer->beginTime + mbedos_timer->msWait - cTime);

	return 0;
}

char iot_os_timer_isexpired(iot_os_timer timer)
{
	Mbedos_Timer *mbedos_timer = (Mbedos_Timer *)timer;
	return xTaskCheckForTimeOut(mbedos_timer->beginTime,mbedos_timer->msWait);
}

int iot_os_timer_init(iot_os_timer *timer)
{
	if (!timer)
		return IOT_ERROR_INVALID_ARGS;

	*timer = malloc(sizeof(Mbedos_Timer));
	if (*timer == NULL)
		return IOT_ERROR_MEM_ALLOC;

	memset(*timer, '\0', sizeof(Mbedos_Timer));
	return IOT_ERROR_NONE;
}

void iot_os_timer_destroy(iot_os_timer *timer)
{
	if (timer == NULL || *timer == NULL)
		return;

	free(*timer);
	*timer = NULL;
}

const char* iot_os_get_os_name(void)
{
	return OS_NAME;
}

const char* iot_os_get_os_version_string(void)
{
	snprintf(mbedversion, 10, "%d.%d", MBED_MAJOR_VERSION, MBED_MINOR_VERSION);
	return mbedversion;
}
