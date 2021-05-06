/* ***************************************************************************
 *
 * Copyright 2021 Samsung Electronics All Rights Reserved.
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

#include "iot_bsp_fs.h"
#include "lfs_qspibd.h"

static lfs_t lfs;

iot_error_t iot_bsp_fs_init()
{
	int ret = QSPI_LFS_Config();

	ret = qspi_lfs_mount(&lfs);

	// reformat if we can't mount the filesystem
	// this should only happen on the first boot
	if (ret) {
		qspi_lfs_format(&lfs);
		qspi_lfs_mount(&lfs);
	}
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	lfs_unmount(&lfs);
	BSP_QSPI_DeInit();
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{
	int ret;
	lfs_file_t *file;

	file = malloc(sizeof(lfs_file_t));
	if (!file) {
		return IOT_ERROR_MEM_ALLOC;
	}

	if (mode == FS_READWRITE) {
		ret = lfs_file_open(&lfs, file, filename, LFS_O_RDWR | LFS_O_CREAT);
	} else {
		ret = lfs_file_open(&lfs, file, filename, LFS_O_RDONLY);
	}

	if (ret < 0) {
		free(file);
		return IOT_ERROR_FS_OPEN_FAIL;
	}

	handle->lfs_file = file;
	return IOT_ERROR_NONE;

}

iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	return iot_bsp_fs_open(filename, FS_READONLY, handle);
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length)
{
	lfs_file_t *file;

	file = handle.lfs_file;
	if (!file) {
		return IOT_ERROR_FS_NO_FILE;
	}

	char *data = (char *)malloc(*length + 1);
	IOT_DEBUG_CHECK(data == NULL, IOT_ERROR_MEM_ALLOC, "Memory allocation fail");

	lfs_ssize_t size = lfs_file_read(&lfs, file, data, *length);
	IOT_DEBUG_CHECK(size < 0, IOT_ERROR_FS_READ_FAIL, "read fail [%d]", size);

	memcpy(buffer, data, size);
	if (size < *length) {
		buffer[size] = '\0';
	}

	*length = size;

	free(data);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, unsigned int length)
{
	lfs_file_t *file = handle.lfs_file;

	if (!file) {
		return IOT_ERROR_FS_NO_FILE;
	}

	lfs_ssize_t ret = lfs_file_write(&lfs, file, data, length);
	if (ret < 0) {
		return IOT_ERROR_FS_WRITE_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	int ret;
	if (!handle.lfs_file) {
		return IOT_ERROR_FS_NO_FILE;
	}

	ret = lfs_file_close(&lfs, handle.lfs_file);
	if (ret < 0) {
		return IOT_ERROR_FS_CLOSE_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	if (filename == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}

	int ret = lfs_remove(&lfs, filename);
	if (ret < 0) {
		return IOT_ERROR_FS_REMOVE_FAIL;
	}

	return IOT_ERROR_NONE;
}
