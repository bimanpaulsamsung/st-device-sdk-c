/***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#include <stdlib.h>
#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "iot_debug.h"
#include "FreeRTOS.h"
#include "semphr.h"
#include "mflash_file.h"

#define MAX_NV_ITEM_CNT		19
#define STDK_NV_SECTOR_SIZE		(0x1000)
#define NV_BASE_ADDRESS		(0x10100000)

mflash_file_t nv_table[MAX_NV_ITEM_CNT] = {
	{.path = "WifiProvStatus",	.max_size = STDK_NV_SECTOR_SIZE},  // WifiProvStatus
	{.path = "IotAPSSID",		.max_size = STDK_NV_SECTOR_SIZE},  // IotAPSSID
	{.path = "IotAPPASS",		.max_size = STDK_NV_SECTOR_SIZE},  // IotAPPASS
	{.path = "IotAPBSSID",		.max_size = STDK_NV_SECTOR_SIZE},  // IotAPBSSID
	{.path = "IotAPAuthType",	.max_size = STDK_NV_SECTOR_SIZE},  // IotAPAuthType
	{.path = "CloudProvStatus",	.max_size = STDK_NV_SECTOR_SIZE},  // CloudProvStatus
	{.path = "ServerURL",		.max_size = STDK_NV_SECTOR_SIZE},  // ServerURL
	{.path = "ServerPort",		.max_size = STDK_NV_SECTOR_SIZE},  // ServerPort
	{.path = "Label",		.max_size = STDK_NV_SECTOR_SIZE},  // Label
	{.path = "DeviceID",		.max_size = STDK_NV_SECTOR_SIZE},  // DeviceID
	{.path = "PrivateKey",		.max_size = STDK_NV_SECTOR_SIZE},  // PrivateKey
	{.path = "PublicKey",		.max_size = STDK_NV_SECTOR_SIZE},  // PublicKey
	{.path = "PKType",		.max_size = STDK_NV_SECTOR_SIZE},  // PKType
	{.path = "RootCert",		.max_size = STDK_NV_SECTOR_SIZE},  // RootCert
	{.path = "SubCert",		.max_size = STDK_NV_SECTOR_SIZE},  // SubCert
	{.path = "DeviceCert",		.max_size = STDK_NV_SECTOR_SIZE},  // DeviceCert
	{.path = "ClaimID",		.max_size = STDK_NV_SECTOR_SIZE},  // ClaimID
	{.path = "SerialNum",		.max_size = STDK_NV_SECTOR_SIZE},  // SerialNum
	{0,} //last item must be 0 for driver to check the end
};

static SemaphoreHandle_t flash_mutex;
static SemaphoreHandle_t nv_mutex;

static void device_mutex_lock(void)
{
	if(flash_mutex == NULL)
		flash_mutex = xSemaphoreCreateMutex();

	xSemaphoreTake(flash_mutex, portMAX_DELAY);
}

static void device_mutex_unlock(void)
{
	xSemaphoreGive(flash_mutex);
}

static void nv_mutex_lock(void)
{
	if(nv_mutex == NULL)
		nv_mutex = xSemaphoreCreateMutex();

	xSemaphoreTake(nv_mutex, portMAX_DELAY);
}

static void nv_mutex_unlock(void)
{
	xSemaphoreGive(nv_mutex);
}

static void nv_data_preload(void)
{
	int i;
	size_t last_address;

	nv_mutex_lock();
	last_address = NV_BASE_ADDRESS;
	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		nv_table[i].flash_addr = last_address;
		last_address += nv_table[i].max_size;
		IOT_DEBUG("add storage : file %s, addr %X, size %d", nv_table[i].path, nv_table[i].flash_addr, nv_table[i].max_size);
	}
	nv_mutex_unlock();
}

static int nv_storage_init(void)
{
	static bool initialized;

	if (initialized)
		return 0;

	flash_mutex = xSemaphoreCreateMutex();
	nv_mutex = xSemaphoreCreateMutex();

	nv_data_preload();

	if (mflash_init(nv_table, 1) != pdTRUE) {
		IOT_ERROR("mflash_init failed");
		return -1;
	}

	initialized = true;
	return 0;
}

static int nv_storage_erase(const char *store)
{
	int ret = 0;
	uint8_t *buf;
	mflash_file_t tmp_file = {0};

	nv_storage_init();

	if (mflash_find_file(store, &tmp_file) != 0)
		return -1;

	buf = malloc(tmp_file.max_size);
	if (!buf) {
		IOT_ERROR("failed to malloc for buf");
		return -1;
	}
	memset(buf, 0xFF, tmp_file.max_size);

	device_mutex_lock();
	if (false == mflash_save_file(store, (uint8_t *)buf, tmp_file.max_size)) {
		IOT_ERROR("Erase %s failed",store);
		ret = -1;
	}

	free(buf);
	device_mutex_unlock();
	return ret;
}

iot_error_t iot_bsp_fs_init()
{
	nv_storage_init();
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t *handle)
{
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	return iot_bsp_fs_open(filename, FS_READONLY, handle);
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char *buffer, size_t *length)
{
	iot_error_t ret = IOT_ERROR_NONE;
	unsigned int bytesread = 0;
	char *rdata = NULL;

	if (!buffer || *length == 0 || *length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_READ_FAIL;

	nv_storage_init();
	device_mutex_lock();
	if (mflash_read_file(handle.filename, &rdata, &bytesread) != true) {
		IOT_ERROR("mflash read %s fail", handle.filename);
		ret = IOT_ERROR_FS_READ_FAIL;
	} else {
		IOT_INFO("mflash read  %s success", handle.filename);
		bytesread = (*length < bytesread)? *length : bytesread;
		memcpy(buffer, rdata, bytesread);
		*length = bytesread;
	}
	device_mutex_unlock();
	return ret;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, size_t length)
{
	iot_error_t ret = IOT_ERROR_NONE;

	if (!data || length == 0 || length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_WRITE_FAIL;

	nv_storage_init();

	device_mutex_lock();
	if (false == mflash_save_file(handle.filename, (uint8_t *)data, length)) {
		IOT_ERROR("Write %s failed",handle.filename);
		ret = IOT_ERROR_FS_WRITE_FAIL;
	}
	device_mutex_unlock();
	return ret;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	int ret;

	ret = nv_storage_erase(filename);
	IOT_ERROR_CHECK(ret != 0, IOT_ERROR_FS_REMOVE_FAIL, "nvs erase fail ");
	return IOT_ERROR_NONE;
}
