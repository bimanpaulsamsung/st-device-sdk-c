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
#include <map>
#include <iterator>
#include <iostream>
#include "us_ticker_api.h"

const unsigned int iot_os_max_delay = osWaitForever;
const unsigned int iot_os_true = 1;
const unsigned int iot_os_false = 0;

typedef void (*callbackFN)(void *); /* define Thread callback function type */

static MbedLinkedList threadlist;
std::map<osThreadId_t, void *> mapOfWords;

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	Thread *thread = new Thread(osPriorityNormal, stack_size, nullptr, name);
	IOT_ERROR_CHECK(!thread, IOT_OS_FALSE, "Memory allocation Failed!!!");

	osStatus status = thread->start(callback((callbackFN)thread_function, data));
	if (status) {
		delete thread;
		return IOT_OS_FALSE;
	}

	threadlist.insert(thread);

	osThreadId_t id = thread->get_id();
	mapOfWords.insert(std::pair<osThreadId_t, void *>(id, (void *)thread));

	if (thread_handle)
		*thread_handle = thread;

	return IOT_OS_TRUE;
}

static bool comp(void *loopdata, void *compdata)
{
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

		std::map<osThreadId_t, void *>::iterator it = mapOfWords.find(tid);
		if (it == mapOfWords.end()) {
			IOT_ERROR("Invalid Thread!!!");
		}

		std::pair<osThreadId_t, void *> P = *it;
		osThreadId_t thid= P.first;
		Thread *th = (Thread *)P.second;

		if (ret != LINKED_LIST_ERROR_NONE) {
			IOT_ERROR("Invalid Thread!!!");
			return;
		}
	}
	threadlist.remove(thread);
	osThreadId_t id = thread->get_id();
	mapOfWords.erase(id);
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

	if (queue->empty()) {
		IOT_DEBUG("Queue Empty!!!");
		return IOT_OS_FALSE;
	}

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

unsigned int iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_wait_for, const int clear_on_exit,
		const int wait_for_all_bits, const unsigned int wait_time_ms)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	uint32_t ret;

	IOT_ERROR_CHECK(ef == NULL, IOT_OS_FALSE, "Invalid Event");

	if (wait_for_all_bits) {
		IOT_DEBUG("all_of_bits_to_wait_for: 0x%x", bits_to_wait_for);
		ret =  ef->wait_all(bits_to_wait_for, wait_time_ms, clear_on_exit);
		if (ret & osFlagsError) {
			IOT_DEBUG("Event not received for bits 0x%x | Ret [0x%x]",
					bits_to_wait_for, ret);
			return 0;
		}
		IOT_DEBUG("Received ALL | Bits: 0x%x | Value: 0x%x",
				bits_to_wait_for, ret);
		return ret;
	}

	IOT_DEBUG("any_of_bits_to_wait_for: 0x%x", bits_to_wait_for);
	ret = ef->wait_any(bits_to_wait_for, wait_time_ms, clear_on_exit);
	if (ret & osFlagsError) {
		IOT_DEBUG("Did not receive Event for bits 0x%x | Ret [0x%x]",
				bits_to_wait_for, ret);
		return 0;
	}
	IOT_DEBUG("Received ANY | Bits: 0x%x | Value: 0x%x", bits_to_wait_for, ret);
	return ret;
}

unsigned int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_set)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_ERROR_CHECK(ef == NULL, 0, "Invalid Event");
	IOT_DEBUG("bits_to_set: 0x%x", bits_to_set);
	return ef->set(bits_to_set);
}

unsigned int iot_os_eventgroup_get_bits(iot_os_eventgroup* eventgroup_handle)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_ERROR_CHECK(ef == NULL, 0, "Invalid Event");
	return ef->get();
}

unsigned int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned int bits_to_clear)
{
	EventFlags *ef = (EventFlags *)eventgroup_handle;
	IOT_ERROR_CHECK(ef == NULL, 0, "Invalid Event");
	IOT_INFO("bits_to_set: 0x%x", bits_to_clear);
	return ef->clear(bits_to_clear);
}

/* Mutex */
int iot_os_mutex_init(iot_os_mutex* mutex)
{
	IOT_ERROR_CHECK(!mutex, IOT_ERROR_INVALID_ARGS, "Invalid Parameters!!!");

	Mutex *sem =  new Mutex();
	IOT_ERROR_CHECK(!sem, IOT_ERROR_MEM_ALLOC, "Memory Allocation Failed!!!");

	mutex->sem = sem;
	return IOT_ERROR_NONE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	IOT_ERROR_CHECK(!mutex || !mutex->sem, IOT_ERROR_INVALID_ARGS, "Invalid Parameters!!!");
	Mutex *sem = (Mutex *)mutex->sem;
	osStatus ret = sem->lock();
	if (ret == osOK)
		return IOT_ERROR_NONE;

	return  IOT_ERROR_BAD_REQ;
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	IOT_ERROR_CHECK(!mutex, IOT_ERROR_INVALID_ARGS, "Invalid Parameters!!!");
	Mutex *sem = (Mutex *)mutex->sem;
	osStatus ret = sem->unlock();

	if (ret == osOK)
		return IOT_ERROR_NONE;

	return  IOT_ERROR_BAD_REQ;
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
	return (us_ticker_read() / 1000L);
}

static void vTaskSetTimeOutState(unsigned int *mstime)
{
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
