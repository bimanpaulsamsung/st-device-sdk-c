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

#include <stdio.h>
#include <string.h>
#include "iot_bsp_fs.h"
#include "iot_bsp_debug.h"

#include "mbed.h"
#include <stdio.h>
#include <errno.h>

#include "BlockDevice.h"
#include "LittleFileSystem.h"

// This will take the system's default block device
static BlockDevice *bd = BlockDevice::get_default_instance();

static LittleFileSystem fs("fs");

iot_error_t iot_bsp_fs_init()
{
	// Try to mount the filesystem
	IOT_INFO("Mounting the filesystem... ");
	fflush(stdout);
	int err = fs.mount(bd);
	IOT_INFO("%s", (err ? "Fail :(" : "OK"));
	if (err) {
		// Reformat if we can't mount the filesystem
		// this should only happen on the first boot
		IOT_INFO("No filesystem found, formatting... ");
		fflush(stdout);
		err = fs.reformat(bd);
		IOT_INFO("%s", (err ? "Fail :(" : "OK"));
		if (err) {
			IOT_ERROR("error: %s (%d)\n", strerror(-err), err);
			return IOT_ERROR_INIT_FAIL;
		}
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	IOT_INFO("Unmounting... ");
	fflush(stdout);
	int err = fs.unmount();
	IOT_INFO("%s", (err < 0 ? "Fail :(" : "OK"));
	if (err < 0) {
		IOT_ERROR("error: %s (%d)", strerror(-err), err);
		return IOT_ERROR_INIT_FAIL;
	}
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char *filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t *handle)
{
	int fd;
	int open_mode;

	if (mode == FS_READONLY) {
		open_mode = O_RDONLY;
	} else {
		open_mode = O_RDWR | O_CREAT;
	}

	fd = open(filename, open_mode, 0644);
	if (fd == -1) {
		IOT_DEBUG("file open failed [%s]", strerror(errno));
		return IOT_ERROR_FS_OPEN_FAIL;
	} else {
		handle->fd = fd;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	}
}

iot_error_t iot_bsp_fs_open_from_stnv(const char *filename, iot_bsp_fs_handle_t *handle)
{
	return iot_bsp_fs_open(filename, FS_READONLY, handle);
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char *buffer, size_t *length)
{
	int fd = handle.fd;
	if (fd == -1) {
		return IOT_ERROR_FS_NO_FILE;
	}

	char *data = (char *)malloc(*length + 1);
	IOT_DEBUG_CHECK(data == NULL, IOT_ERROR_MEM_ALLOC, "Memory allocation fail");

	ssize_t size = read(handle.fd, data, *length);
	IOT_DEBUG_CHECK(size < 0, IOT_ERROR_FS_READ_FAIL, "read fail [%s]", strerror(errno));

	memcpy(buffer, data, size);
	if (size < *length) {
		buffer[size] = '\0';
	}

	*length = size;

	free(data);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, unsigned int length)
{
	int ret;

	if (handle.fd == -1) {
		return IOT_ERROR_FS_NO_FILE;
	}

	/* write 'NULL' to file end */
	ret = write(handle.fd, data, length+1);
	if (ret == -1) {
		return IOT_ERROR_FS_WRITE_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	int ret;
	if (handle.fd == -1) {
		return IOT_ERROR_FS_NO_FILE;
	}

	ret = close(handle.fd);
	if (ret == -1) {
		return IOT_ERROR_FS_CLOSE_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char *filename)
{
	int ret;
	if (filename == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = remove(filename);
	if (ret == -1) {
		return IOT_ERROR_FS_REMOVE_FAIL;
	}
	return IOT_ERROR_NONE;
}
