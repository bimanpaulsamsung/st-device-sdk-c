/* ***************************************************************************
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
#include "FreeRTOS.h"
#include "semphr.h"
#include "iot_bsp_fs.h"
#include "iot_debug.h"
#include "wdrv_mrf24wn_iwpriv.h"

typedef struct nv_item_table
{
	unsigned int hash;
	unsigned int size;
	unsigned int addr;
} nv_item_table_s;

#define MAX_NV_ITEM_CNT			19

#define STDK_NV_SECTOR_SIZE            (0x800)
/*for key and cert data, they are currently not used.
  max data length from iot_nv_data is 2048, while read/write buffer
  is 2049, with a null terminator. but we assign 2048 for them,
  null terminator could be handled separately. because nv driver for
  pic32mz support data size of write operation is 2048*/
nv_item_table_s nv_table[MAX_NV_ITEM_CNT] = {
	/* for wifi prov data */
	{0x24a05746, 65, 0},  // WifiProvStatus
	{0x25726d8, 65, 0},   // IotAPSSID
	{0x25723e0, 65, 0},   // IotAPPASS
	{0xbb39a0e, 65, 0},   // IotAPBSSID
	{0xb6bb1795, 65, 0},   // IotAPAuthType

	/* for cloud prov data */
	{0xd317a076, 65, 0},   // CloudProvStatus
	{0x2892596, 512, 0},  // ServerURL
	{0xcadbd84, 37, 0},   // ServerPort
	{0xf4e0, 37, 0},  // Lable

	{0x70012d, 129, 0},  // DeviceID

	{0x7b718c, 2048, 0},  // MiscInfo
	/* stored in stnv partition (manufacturer data) */
	{0xc96f1bc, 2048, 0},   // PrivateKey
	{0x2860e24, 2048, 0},   // PublicKey
	{0x82cac2, 2048, 0},  // RootCert
	{0x1a7aa8, 2048, 0},   // SubCert
	{0xaf0205e, 2048, 0},   // DeviceCert
	{0x4bf15, 37, 0},   // PKType
	{0x164c23, 37, 0},   // ClaimID
	{0x2887a54, 37, 0},   // SerialNum
	/* stored in stnv partition (manufacturer data) */
};

static bool initialized = false;
static SemaphoreHandle_t _flash_mutex;
static bool _data_on_page = false;

static void device_mutex_lock(void)
{
	if(_flash_mutex == NULL)
		_flash_mutex = xSemaphoreCreateMutex();

	xSemaphoreTake(_flash_mutex, portMAX_DELAY);
}

static void device_mutex_unlock(void)
{
	xSemaphoreGive(_flash_mutex);
}

static unsigned int simple_str_hash(char *s, int len)
{
	unsigned int key = 0;

	while (len--)
		key = 5 * key + *s++;

	return key;
}

static int nv_get_table_idx(unsigned int hash)
{
	int i;

	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		if (hash == nv_table[i].hash)
			return i;
	}
	return -1;
}

static void nv_data_preload(void)
{
	int i;
	unsigned int last_address = 0;

	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		if (nv_table[i].size >= STDK_NV_SECTOR_SIZE) {
			if (last_address % STDK_NV_SECTOR_SIZE) {
				nv_table[i].addr = (last_address / STDK_NV_SECTOR_SIZE + 1) * STDK_NV_SECTOR_SIZE;
			} else {
				nv_table[i].addr = last_address;
			}
			last_address = nv_table[i].addr + nv_table[i].size;
		} else {
			nv_table[i].addr = last_address;
			last_address += nv_table[i].size;
		}

		IOT_DEBUG("add storage : hash 0x%X, addr %d, size %d", nv_table[i].hash, nv_table[i].addr, nv_table[i].size);
	}
}

iot_error_t iot_bsp_fs_init(void)
{
	if (initialized)
		return 0;

	_flash_mutex = xSemaphoreCreateMutex();

	nv_data_preload();

	initialized = true;
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit(void)
{
	vSemaphoreDelete(_flash_mutex);
	_flash_mutex = NULL;
	initialized = false;
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length)
{
	unsigned int hash;
	int idx;
	int offset;
	int rlen;

	hash = simple_str_hash(handle.filename, strlen(handle.filename));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", handle.filename);
		return IOT_ERROR_FS_READ_FAIL;
	}

	IOT_INFO("[read] index %d address:0x%x, size:%d\n",idx, nv_table[idx].addr, nv_table[idx].size);

	offset = nv_table[idx].addr;
	rlen = nv_table[idx].size;
	if (rlen > *length) {
		rlen = *length;
	}

	device_mutex_lock();
	if (IOT_DataRead(buffer, rlen, offset) < 0) {
		IOT_ERROR("Drv NV read failed.");
		device_mutex_unlock();
		return IOT_ERROR_FS_READ_FAIL;
	}
	device_mutex_unlock();

	if ((nv_table[idx].size == STDK_NV_SECTOR_SIZE) && (*length == STDK_NV_SECTOR_SIZE + 1)) {
		buffer[STDK_NV_SECTOR_SIZE] = '\0'; //add null termination
	} else {
		*length = rlen;
	}
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, size_t length)
{
	unsigned int hash;
	int idx;
	int offset;
	int sector;
	char *sector_buf;
	iot_error_t ret = IOT_ERROR_FS_WRITE_FAIL;

	hash = simple_str_hash(handle.filename, strlen(handle.filename));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("invalid item %s\n", handle.filename);
		return IOT_ERROR_FS_WRITE_FAIL;
	}

	IOT_INFO("[write] address:0x%x, size:%d\n",nv_table[idx].addr, nv_table[idx].size);

	if (length == (STDK_NV_SECTOR_SIZE + 1))
		--length;

	if (length > nv_table[idx].size) {
		IOT_ERROR("%s nv table size %d is smaller than size of write buffer %d\n", handle.filename, nv_table[idx].size, length);
		return IOT_ERROR_FS_WRITE_FAIL;
	}

	sector = nv_table[idx].addr / STDK_NV_SECTOR_SIZE;
	sector_buf = (char*)malloc(STDK_NV_SECTOR_SIZE);
	if (!sector_buf) {
		IOT_ERROR("malloc failed.\n");
		return IOT_ERROR_FS_WRITE_FAIL;
	}
	memset(sector_buf, 0, STDK_NV_SECTOR_SIZE);

	device_mutex_lock();
	if (IOT_DataRead(sector_buf, STDK_NV_SECTOR_SIZE, sector * STDK_NV_SECTOR_SIZE) < 0) {
		IOT_ERROR("%s failed to read sector data\n", handle.filename);
		goto write_fail;
	}

	offset = nv_table[idx].addr % STDK_NV_SECTOR_SIZE;
	if (offset + length > STDK_NV_SECTOR_SIZE) {
		IOT_ERROR("%s data length abnormal, offset %d and data length %d\n", handle.filename, offset, length);
		goto write_fail;
	}

	memcpy(sector_buf + offset, data, length + 1);
	if (IOT_DataWrite(sector_buf, STDK_NV_SECTOR_SIZE, sector) < 0) {
		IOT_ERROR("%s failed to read sector data\n", handle.filename);
		goto write_fail;
	}

	ret = IOT_ERROR_NONE;
	_data_on_page = true;
	IOT_INFO("fs write successfully.");

write_fail:

	if (sector_buf)
		free(sector_buf);
	device_mutex_unlock();

	return ret;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	//erase the whole page (16K) for all files.
	if (_data_on_page) {
		device_mutex_lock();
		IOT_DataErase();
		device_mutex_unlock();
		/*once called, all files are removed, do not erase again
		  for other file, until fs_write is called again.*/
		_data_on_page = false;
	}
	return IOT_ERROR_NONE;
}

