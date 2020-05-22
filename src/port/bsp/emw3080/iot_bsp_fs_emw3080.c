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
#include "mico.h"
#include "mico_board.h"

typedef struct nv_item_table
{
	size_t hash;
	size_t size;
	size_t addr;
} nv_item_table_s;

#define MAX_NV_ITEM_CNT				 19

#define STDK_NV_SECTOR_SIZE            (0x1000)

nv_item_table_s nv_table[MAX_NV_ITEM_CNT] = {
	/* for wifi prov data */
	{0x24a05746, 65, NULL},  // WifiProvStatus
	{0x25726d8, 65, NULL},   // IotAPSSID
	{0x25723e0, 65, NULL},   // IotAPPASS
	{0xbb39a0e, 65, NULL},   // IotAPBSSID
	{0xb6bb1795, 65, NULL},   // IotAPAuthType

	/* for cloud prov data */
	{0xd317a076, 65, NULL},   // CloudProvStatus
	{0x2892596, 512, NULL},  // ServerURL
	{0xcadbd84, 37, NULL},   // ServerPort
	{0xc02865a, 37, NULL},  // LocationID
	{0x53a82, 37, NULL},  // RoomID
	{0xf4e0, 37, NULL},  // Lable

	{0x70012d, 129, NULL},  // DeviceID

	/* stored in stnv partition (manufacturer data) */
	{0xc96f1bc, 2049, NULL},   // PrivateKey
	{0x2860e24, 2049, NULL},   // PublicKey
	{0x4bf15, 37, NULL},   // PKType
	{0x82cac2, 2049, NULL},  // RootCert
	{0x1a7aa8, 2049, NULL},   // SubCert
	{0xaf0205e, 2049, NULL},   // DeviceCert
	{0x164c23, 37, NULL},   // ClaimID
	{0x2887a54, 37, NULL},   // SerialNum
	/* stored in stnv partition (manufacturer data) */
};
uint32_t nv_base_address;
mico_mutex_t flash_mutex;
mico_mutex_t nv_mutex;

static void device_mutex_lock(void)
{
	if(flash_mutex == NULL)
		mico_rtos_init_mutex(&flash_mutex);
	mico_rtos_lock_mutex(&flash_mutex);
}

static void device_mutex_unlock(void)
{
	mico_rtos_unlock_mutex(&flash_mutex);
}

static void nv_mutex_lock(void)
{
	if(nv_mutex == NULL)
		mico_rtos_init_mutex(&nv_mutex);
	mico_rtos_lock_mutex(&nv_mutex);
}

static void nv_mutex_unlock(void)
{
	mico_rtos_unlock_mutex(&nv_mutex);
}

static size_t simple_str_hash(const unsigned char *s, size_t len)
{
	size_t key = 0;

	while (len--)
		key = 5 * key + *s++;

	return key;
}

static int nv_get_table_idx(size_t hash)
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
	size_t last_address;

	nv_mutex_lock();
	last_address = nv_base_address;
	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		nv_table[i].addr = last_address;
		last_address += nv_table[i].size;
		IOT_DEBUG("add storage : hash %X, addr %X, size %d", nv_table[i].hash, nv_table[i].addr, nv_table[i].size);
	}
	nv_mutex_unlock();
}

static void nv_storage_init(void)
{
	mico_logic_partition_t *info;	
	static bool intitialized;

	if (intitialized)
		return;

	info = MicoFlashGetInfo(MICO_PARTITION_USER);
	nv_base_address = info->partition_start_addr;
	mico_rtos_init_mutex(&flash_mutex);
	mico_rtos_init_mutex(&nv_mutex);
	nv_data_preload();
	intitialized = true;
}

static long nv_storage_read(const char *store, uint8_t *buf, size_t size)
{
	int idx;
	size_t cmp_size, hash;
	uint8_t *tempbuf;
	uint32_t offset;

	nv_storage_init();
	IOT_INFO("read %s size %d", store, size);

	nv_mutex_lock();
	hash = simple_str_hash(store, strlen(store));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		nv_mutex_unlock();
		return -1;
	}
	nv_mutex_unlock();

	IOT_INFO("[read] address:0x%x, size:%d\n",nv_table[idx].addr, nv_table[idx].size);
	device_mutex_lock();
	offset = nv_table[idx].addr - nv_base_address;
	MicoFlashRead(MICO_PARTITION_USER, &offset , buf, size);
	device_mutex_unlock();

	cmp_size = size;
	tempbuf = malloc(cmp_size);
	if (!tempbuf) {
		IOT_ERROR("failed to malloc for tempbuf");
		return -1;
	}
	memset(tempbuf, 0xFF, cmp_size);
	if (memcmp(tempbuf, buf, cmp_size) == 0) {
		IOT_ERROR("flash was erased. write default data\n");
		size = IOT_ERROR_FS_NO_FILE;
	}
	free(tempbuf);
	return size;
}

static long nv_storage_write(const char *store, uint8_t *buf, size_t size)
{
	int idx;
	size_t hash;
	uint32_t offset, no_offset = 0;
	OSStatus err = kNoErr;
	char *full_buf = NULL;

	nv_storage_init();
	IOT_INFO("write %s , size %d", store, size);

	nv_mutex_lock();
	hash = simple_str_hash(store, strlen(store));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		nv_mutex_unlock();
		return -1;
	}
	nv_mutex_unlock();

	if (size > nv_table[idx].size) {
		IOT_ERROR("%s stored size %d is smaller than size of write buffer %d\n", store, nv_table[idx].size, size);
		return -1;
	}

	//Read all data in front, to make sure it's not overwritten in one section
	offset = nv_table[idx].addr - nv_base_address;
	full_buf = malloc(offset + size);
	if (!full_buf) {
		IOT_ERROR("failed to malloc memory for all data.");
		return -1;
	}

	device_mutex_lock();
	MicoFlashRead(MICO_PARTITION_USER, &no_offset, full_buf, offset);
	memcpy(full_buf + offset, buf, size);
	no_offset = 0; //reset offset
	err = MicoFlashWrite(MICO_PARTITION_USER, &no_offset, full_buf, offset + size);
	device_mutex_unlock();
	if (err != kNoErr) {
		IOT_ERROR("failed to write storage header");
		free(full_buf);
		return -1;
	}

	free(full_buf);
	return size;
}

static int nv_storage_erase(const char *store)
{
	int idx;
	size_t hash;
	uint32_t offset;
	OSStatus err = kNoErr;

	nv_storage_init();

	nv_mutex_lock();
	hash = simple_str_hash(store, strlen(store));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		nv_mutex_unlock();
		return -1;
	}
	nv_mutex_unlock();

	offset = nv_table[idx].addr - nv_base_address;
	device_mutex_lock();
	err = MicoFlashErase(MICO_PARTITION_USER, offset, nv_table[idx].size);
	device_mutex_unlock();
	if (err != kNoErr) {
		IOT_ERROR("failed to write storage header");
		return -1;
	}

	return 0;
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
	int ret;

	if (!buffer || *length <= 0 || *length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_READ_FAIL;

	ret = nv_storage_read(handle.filename, buffer, *length);
	IOT_ERROR_CHECK(ret == -1, IOT_ERROR_FS_READ_FAIL, "nvs read fail ");
	IOT_ERROR_CHECK(ret == IOT_ERROR_FS_NO_FILE, IOT_ERROR_FS_NO_FILE, "nvs no file");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, size_t length)
{
	int ret;

	if (!data || length <= 0 || length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_WRITE_FAIL;

	ret = nv_storage_write(handle.filename, data, length + 1);
	IOT_ERROR_CHECK(ret <= 0, IOT_ERROR_FS_WRITE_FAIL, "nvs write fail ");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	int ret;

	ret = nv_storage_erase(filename);
	IOT_ERROR_CHECK(ret != 0, IOT_ERROR_FS_WRITE_FAIL, "nvs erase fail ");
	return IOT_ERROR_NONE;
}
