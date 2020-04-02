/******************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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
#include "iot_bsp_fs.h"
#include "iot_debug.h"
#include <ti/drivers/net/wifi/simplelink.h>

#define IOT_BSP_FS_NOT_INITED   (0)
#define IOT_BSP_FS_INITED       (1)
#define MAXSIZE                 (63 * 1024) // Default max file size

static int Init = IOT_BSP_FS_NOT_INITED;  // Status of initialization

iot_error_t iot_bsp_fs_init()
{
	Init = IOT_BSP_FS_INITED;
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	Init = IOT_BSP_FS_NOT_INITED;
	IOT_DEBUG("BSP FS is deinited!");
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t *handle)
{
	if (Init == IOT_BSP_FS_NOT_INITED)
		return IOT_ERROR_UNINITIALIZED;

	if (strlen(filename) >= sizeof(handle->filename)) {
		IOT_ERROR("File name is to long");
		return IOT_ERROR_FS_OPEN_FAIL;
	}

	unsigned int mode_flg = SL_FS_CREATE_MAX_SIZE(MAXSIZE);

	if (mode == FS_READONLY) {
		IOT_DEBUG("Ready to open(read mode) a file, file name is %s", filename);
		mode_flg = SL_FS_READ;
	} else {
		IOT_DEBUG("Ready to open(write mode) a file, file name is %s", filename);
		mode_flg |= (SL_FS_CREATE | SL_FS_OVERWRITE);
		strcpy(handle->filename, filename);
	}

	handle->fd = sl_FsOpen(filename, mode_flg, NULL);
	IOT_DEBUG("Handle->fd value is %x->%d, file name is %s", handle,handle->fd, filename);
	if (handle->fd < 0) {
		switch (handle->fd) {
			case SL_ERROR_FS_FILE_IS_ALREADY_OPENED:
				IOT_ERROR("[%s] file is already opened!", filename);
				break;
			case SL_ERROR_FS_FILE_NOT_EXISTS:
				IOT_ERROR("[%s] file is NOT exist!", filename);
				return IOT_ERROR_FS_NO_FILE;
				break;
			default:
				break;
		}
		return IOT_ERROR_FS_OPEN_FAIL;
	}
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	if (Init == IOT_BSP_FS_NOT_INITED)
		return IOT_ERROR_UNINITIALIZED;

	return iot_bsp_fs_open(filename, FS_READONLY, handle);
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char *buffer, unsigned int length)
{
	if (Init == IOT_BSP_FS_NOT_INITED)
		return IOT_ERROR_UNINITIALIZED;

	int status;
	IOT_DEBUG("Handle.fd value is %d", handle.fd);
	status = sl_FsRead(handle.fd, 0, buffer, length);
	if (status < 0)
		return IOT_ERROR_FS_READ_FAIL;

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, unsigned int length)
{
	if (Init == IOT_BSP_FS_NOT_INITED)
		return IOT_ERROR_UNINITIALIZED;

	int status;
	status = sl_FsWrite(handle.fd, 0, data, length + 1);
	IOT_DEBUG("Handle.fd value is %d, file name is %s", handle.fd, handle.filename);
	if (status < 0)
		return IOT_ERROR_FS_WRITE_FAIL;

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	if (Init == IOT_BSP_FS_NOT_INITED)
		return IOT_ERROR_UNINITIALIZED;

	short int status;
	status = sl_FsClose(handle.fd, 0, 0, 0);
	IOT_DEBUG("Handle.fd value is %d, file name is %s", handle.fd, handle.filename);
	if (status < 0)
                return IOT_ERROR_FS_CLOSE_FAIL;

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	if (Init == IOT_BSP_FS_NOT_INITED)
		return IOT_ERROR_UNINITIALIZED;

	unsigned short int status;
	IOT_DEBUG("Remove file name is %s", filename);
    status = sl_FsDel(filename, 0);
    if (status < 0) {
		if (status == SL_ERROR_FS_FILE_NOT_EXISTS)
			return IOT_ERROR_FS_NO_FILE;
		return IOT_ERROR_FS_REMOVE_FAIL;
		IOT_ERROR("Remove file name failed is %s status %d", filename, status);
    }

	return IOT_ERROR_NONE;
}

typedef struct _ATCmdFile_FileListEntry_t_
{
	SlFileAttributes_t attribute;
	char fileName[SL_FS_MAX_FILE_NAME_LENGTH];
} FileListEntry_t;

#define MAX_FILES_ENTRIES (6)

iot_error_t iot_bsp_fs_list()
{
    int32_t ret = 1;
    int32_t index;
    uint8_t maxEntries;
    uint8_t maxEntryLen;
    FileListEntry_t  *entry;
    uint8_t i;
    index = -1;

    maxEntryLen = sizeof(FileListEntry_t);
	maxEntries = MAX_FILES_ENTRIES;
	entry = malloc(maxEntries * maxEntryLen);

    if (entry == NULL) {
		return -1;
    }
    /* sign the buffer entry as available */
    entry->fileName[0] = 0;
    entry->attribute.FileMaxSize = 0;
    
    /* file get file list */
    while ( ret > 0 ) {
        while ((entry->fileName[0] != 0) || (entry->attribute.FileMaxSize != 0)) {
            usleep(10);
        }
        ret = sl_FsGetFileList((_i32 *)&index, maxEntries, maxEntryLen, (uint8_t *)entry, SL_FS_GET_FILE_ATTRIBUTES);
        if (ret < 0) {
			break;
        }

        maxEntries = ret;
        for (i = 0; i < ret; i++) {
        	printf("[%d] %s \r\n", i, (entry+i)->fileName);
        }
		/* if last chunk - sign the buffer as available */
		entry->fileName[0] = 0;
		entry->attribute.FileMaxSize = 0;
    }

    if (ret == 0) {
    	printf("\r\n");
    }

	if (entry) {
		free(entry);
		entry = NULL;
	}

    return ret;
}

