/******************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
 *
 *
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

#include <stdio.h>
#include "iot_bsp_fs.h"
#include "iot_debug.h"
#include "e_eeprom_xmc4.h"

typedef struct nv_item_table
{
	const char* name;
	size_t size;
	size_t addr;
	int    is_dirty;
} nv_item_table_s;


#define FLASH_USR_STORAGE_BASE    0x0

#define OP_OK                       0
#define OP_FAIL                    -1
#define OP_NO_SUCH_FILE            -2

#define MAX_NV_ITEM_CNT            19
nv_item_table_s nv_table[MAX_NV_ITEM_CNT] = {
	/* for wifi prov data */
	{"WifiProvStatus",  128, 0, 1},   // WifiProvStatus
	{"IotAPSSID",       128, 0, 1},   // IotAPSSID
	{"IotAPPASS",       128, 0, 1},   // IotAPPASS
	{"IotAPBSSID",      128, 0, 1},   // IotAPBSSID
	{"IotAPAuthType",   128, 0, 1},   // IotAPAuthType

	/* for cloud prov data */
	{"CloudProvStatus", 128, 0, 1},   // CloudProvStatus
	{"ServerURL",       128, 0, 1},   // ServerURL
	{"ServerPort",      128, 0, 1},   // ServerPort
	{"Label",           128, 0, 1},   // Label

	{"DeviceID",        128, 0, 1},   // DeviceID
	{"MiscInfo",        128, 0, 1},   // MiscInfo

	/* stored in stnv partition (manufacturer data) */
	{"PrivateKey",      128, 0, 1},   // PrivateKey
	{"PublicKey",       128, 0, 1},   // PublicKey
	{"PKType",          128, 0, 1},   // PKType
	{"RootCert",        512, 0, 1},   // RootCert
	{"SubCert",         512, 0, 1},   // SubCert
	{"DeviceCert",      512, 0, 1},   // DeviceCert
	{"ClaimID",         128, 0, 1},   // ClaimID
	{"SerialNum",       128, 0, 1},   // SerialNum
};

static E_EEPROM_XMC4_t e_eeprom;

static int get_nv_idx(char *str_name)
{
	int i;

	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		if (0 == strcmp(str_name, nv_table[i].name))
			return i;
	}
	return OP_FAIL;
}

static int nv_data_preload(void)
{
	int i;
	size_t last_address;

	last_address = FLASH_USR_STORAGE_BASE;
	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		nv_table[i].addr = last_address;
		last_address += nv_table[i].size;
		IOT_DEBUG("Add storage : name %s, addr %X, size %d", nv_table[i].name, nv_table[i].addr, nv_table[i].size);
	}

	return (int)(last_address - FLASH_USR_STORAGE_BASE);
}

static void nv_storage_init(void)
{
	static bool intitialized;
	int nv_size_used = 0;

	if (intitialized)
		return;

	nv_size_used = nv_data_preload();
	E_EEPROM_XMC4_Init(&e_eeprom, nv_size_used);
	intitialized = true;
}

static int nv_storage_read(const char *store, uint8_t *buf, size_t *size)
{
	int idx;
	size_t read_size;

	nv_storage_init();
	IOT_INFO("read %s size %d", store, *size);

	idx = get_nv_idx(store);
	if (idx < 0 || nv_table[idx].is_dirty) {
		IOT_ERROR("The %s is not found\n", store);
		return OP_NO_SUCH_FILE;
	}
	read_size = (nv_table[idx].size > *size) ? *size : nv_table[idx].size;

	IOT_INFO("read address:0x%x, size:%d\n",nv_table[idx].addr, read_size);

	E_EEPROM_XMC4_ReadArray(nv_table[idx].addr, buf, read_size);

	read_size = strlen(buf);

	*size = (read_size < nv_table[idx].size) ? read_size : nv_table[idx].size;
	return 0;
}

static long nv_storage_write(const char *store, uint8_t *buf, size_t size)
{
	int idx;

	nv_storage_init();
	IOT_INFO("write %s size %d", store, size);

	idx = get_nv_idx(store);
	if (idx < 0) {
		IOT_ERROR("The [%s] is not found\n", store);
		return OP_NO_SUCH_FILE;
	}

	if (size > nv_table[idx].size) {
		IOT_ERROR("%s stored size %d is smaller than size of write buffer %d\n", store, nv_table[idx].size, size);
		return OP_FAIL;
	}

	E_EEPROM_XMC4_WriteArray(nv_table[idx].addr, buf, size);
	E_EEPROM_XMC4_WriteByte(nv_table[idx].addr + size - 1 , '\0');
	E_EEPROM_XMC4_UpdateFlashContents();
	nv_table[idx].is_dirty = 0;
	return size;
}

static int nv_storage_erase(const char *store)
{
	int idx = 0;

	nv_storage_init();

	idx = get_nv_idx(store);
	if (idx < 0) {
		IOT_ERROR("The [%s] is not found\n", store);
		return OP_NO_SUCH_FILE;
	}

	nv_table[idx].is_dirty = 1;

	return OP_OK;
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
	int ret = 0;
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

	if (!buffer || *length <= 0)
		return IOT_ERROR_FS_READ_FAIL;
	ret = nv_storage_read(handle.filename, buffer, length);
	IOT_ERROR_CHECK(ret == OP_NO_SUCH_FILE, IOT_ERROR_FS_NO_FILE, "nvs no file");
	IOT_ERROR_CHECK(ret == OP_FAIL, IOT_ERROR_FS_READ_FAIL, "nvs read fail");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, size_t length)
{
	int ret;

	if (!data || length <= 0)
		return IOT_ERROR_FS_WRITE_FAIL;

	ret = nv_storage_write(handle.filename, data, length + 1);
	IOT_ERROR_CHECK(ret == OP_FAIL, IOT_ERROR_FS_WRITE_FAIL, "nvs write fail");
	IOT_ERROR_CHECK(ret == OP_NO_SUCH_FILE, IOT_ERROR_FS_NO_FILE, "nvs no file");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	nv_storage_erase(filename);
	return IOT_ERROR_NONE;
}
