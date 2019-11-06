/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_UTIL_H_
#define _IOT_UTIL_H_

#include <sys/time.h>
#include "iot_error.h"
#include "iot_main.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Contains a "url parse" data
 */
typedef struct {
	char *protocol;		/**< @brief broker url's protocol part such as "ssl", "https" */
	char *domain;		/**< @brief broker url's domain part such as "test.example.com" */
	int port;		/**< @brief broker url's port number part such as 443, 8883' */
} url_parse_t;

/**
 * @brief	parse url with protocol, domain, port number parts for st-iot-core
 * @details	This function parse give url protocol, domain, port number parts
 * @param[in]	url		null-terminated url string like "https://example.sample.com:1234"
 * @param[out]	output	parsed output with url_parse_t type
 * @return		return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_util_url_parse(char *url, url_parse_t *output);

/**
 * @brief	uuid type string to iot_uuid struct converting function for st-iot-core
 * @details	This function tries to convert from uuid type string to iot_uuid struct
 * @param[in]	str	uuid type string pointer such as 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
 * @param[in]	uuid	allocated iot_uuid struct pointer to get iot_uuid value from str
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_util_convert_str_uuid(const char* str, struct iot_uuid* uuid);

/**
 * @brief	iot_uuid struct based value to uuid type string converting function for st-iot-core
 * @details	This function tries to convert from iot_uuid struct based value to uuid type string
 * @param[in]	uuid	converting wanted iot_uuid struct value pointer
 * @param[in]	str	allocated memory pointer for converted uuid type string
 * @param[in]	max_sz	max size of allocated memory pointer
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_util_convert_uuid_str(struct iot_uuid* uuid, char* str, int max_sz);

/**
 * @brief	To get random uuid based on iot_uuid struct
 * @details	This function tries to make random iot_uuid values
 * @param[in]	uuid	allocated iot_uuid struct pointer to get random iot_uuid value
 * @return	return IOT_ERROR_NONE on success, or iot_error_t errors if it fails
 */
iot_error_t iot_util_get_random_uuid(struct iot_uuid* uuid);


/**
 * @brief	To convert WIFI mac string into iot_mac struct value
 * @details	This function tries to convert from the string to iot_mac struct value
 * @param[in]	str	WIFI mac string pointer such as 'xx:xx:xx:xx:xx:xx'
 * @param[in]	mac	allocated iot_mac struct pointer to get iot_mac value from str
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE	success
 * @retval	IOT_ERROR_INVALID_ARGS	invalid arguments
 */
iot_error_t iot_util_convert_str_mac(char* str, struct iot_mac* mac);

/**
 * @brief	To convert iot_mac value intto WIFI mac string
 * @details	This function tries to convert from the iot_mac struct value to string
 * @param[in]	mac	converting wanted iot_mac struct value pointer
 * @param[in]	str	allocated memory pointer for converted WIFI mac string
 * @param[in]	max_sz	max size of allocated memory pointer
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE	success
 * @retval	IOT_ERROR_INVALID_ARGS invalid arguments
 */
iot_error_t iot_util_convert_mac_str(struct iot_mac* mac, char* str, int max_sz);

/**
 * @brief	To convert Wi-Fi channel into frequency value
 * @details	This function tries to convert from the channel to frequency
 * @param[in]	Wi-Fi channel
 * @return	Wi-Fi frequency
 */
uint16_t iot_util_convert_channel_freq(uint8_t channel);


#define MAX_TIMEDIFF_NAME_N		10
/**
 * @brief Structure for time diff profile
 */
typedef struct timediff_profile {
	struct timeval tv_start;		/**< @brief timerecording's start time */
	bool start_flag;				/**< @brief flag for timerecording start */
	char name[MAX_TIMEDIFF_NAME_N + 1];		/**< @brief name of timerecording profile */
	long stat_avg_sec;				/**< @brief average timerecording sec */
	long stat_avg_usec;				/**< @brief average timerecording usec */
	int stat_n;						/**< @brief timerecording count */

	struct timediff_profile *next;
} timediff_profile_t;

#define IOT_TIMERECORD_START(name, want_print) iot_util_timerecord_start(name, want_print, __FUNCTION__, __LINE__)
#define IOT_TIMERECORD_END(name, want_print) iot_util_timerecord_end(name, want_print, __FUNCTION__, __LINE__)

/**
 * @brief	To start timerecording
 * @details	This function kick off timerecording
 * @param[in]	name name of timerecordig profile
 * @param[in]	want_print want to print detail information
 * @param[in]	call_func function name of calling this
 * @param[in]	line source line number of calling this
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE	success
 */
iot_error_t iot_util_timerecord_start(const char *name, bool want_print, const char *call_func, int line);

/**
 * @brief	To end timerecording
 * @details	This function end timerecordig and record timediff from start
 * @param[in]	name name of timerecordig profile
 * @param[in]	want_print want to print detail information
 * @param[in]	call_func function name of calling this
 * @param[in]	line source line number of calling this
 * @return	timediff in usec
 */
long iot_util_timerecord_end(const char *name, bool want_print, const char *call_func, int line);

/**
 * @brief	To print timerecording information
 * @details	This function print detial information of timerecording
 * @param[in]	name name of timerecordig profile
 * @return	iot_error_t
 * @retval	IOT_ERROR_NONE	success
 * @retval	IOT_ERROR_INVALID_ARGS	invalid arguments
 */
iot_error_t iot_util_timerecord_print(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_UTIL_H_ */
