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

#include <stdio.h>
#include <string.h>

#include "iot_main.h"
#include "iot_util.h"
#include "iot_debug.h"
#include "iot_bsp_random.h"

static int _isalpha(char c)
{
	if (('A' <= c) && (c <= 'Z'))
		return 1;

	if (('a' <= c) && (c <= 'z'))
		return 1;

	return 0;
}

iot_error_t iot_util_convert_str_uuid(const char* str, struct iot_uuid* uuid)
{
	const char *ref_str = "42365732-c6db-4bc9-8945-2a7ca10d6f23";
	int i, j = 0, k = 1;
	unsigned char c = 0;

	if (!uuid || !str) {
		IOT_ERROR("Invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (strlen(str) != strlen(ref_str)) {
		IOT_ERROR("Input is not a uuid string");
		return IOT_ERROR_INVALID_ARGS;
	}

	for (i = 0; i < strlen(ref_str); i++) {
		if (str[i] == '-') {
			continue;
		} else if (_isalpha(str[i])) {
			switch (str[i]) {
			case 65:
			case 97:
				c |= 0x0a;
				break;
			case 66:
			case 98:
				c |= 0x0b;
				break;
			case 67:
			case 99:
				c |= 0x0c;
				break;
			case 68:
			case 100:
				c |= 0x0d;
				break;
			case 69:
			case 101:
				c |= 0x0e;
				break;
			case 70:
			case 102:
				c |= 0x0f;
				break;
			}
		} else {
			c |= str[i] - 48;
		}

		if ((j + 1) * 2 == k) {
			uuid->id[j++] = c;
			c = 0;
		} else {
			c = c << 4;
		}

		k++;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_util_convert_uuid_str(struct iot_uuid* uuid, char* str, int max_sz)
{
	char* ref_id = "42365732-c6db-4bc9-8945-2a7ca10d6f23";
	int i, written = 0, wrt;
	char pvt ='-';

	if (!uuid || !str) {
		IOT_ERROR("Invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (max_sz < (strlen(ref_id) + 1)) {
		IOT_ERROR("Invalid max_sz");
		return IOT_ERROR_INVALID_ARGS;
	}

	/* dump random uuid */
	for (i = 0; i < 16; i++) {
		wrt = sprintf(&str[written], "%02x", (unsigned char)uuid->id[i]);
		written += wrt;

		if (ref_id[written] == pvt) {
			str[written] = pvt;
			written++;
		}
	}

	str[written] = '\0';

	return IOT_ERROR_NONE;
}

iot_error_t iot_util_get_random_uuid(struct iot_uuid* uuid)
{
	unsigned char* p;
	int i;

	if (!uuid) {
		IOT_ERROR("invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	p = (unsigned char *)uuid->id;

	for (i = 0; i < 4; i++) {
		unsigned int rand_value = iot_bsp_random();

		memcpy(&p[i * 4], (unsigned char*)&rand_value, sizeof(unsigned int));
	}

	/* From RFC 4122
	 * Set the two most significant bits of the
	 * clock_seq_hi_and_reserved (8th octect) to
	 * zero and one, respectively.
	 */
	p[8] &= 0x3f;
	p[8] |= 0x80;

	/* From RFC 4122
	 * Set the four most significant bits of the
	 * time_hi_and_version field (6th octect) to the
	 * 4-bit version number from (0 1 0 0 => type 4)
	 * Section 4.1.3.
	 */
	p[6] &= 0x0f;
	p[6] |= 0x40;

	return IOT_ERROR_NONE;
}

iot_error_t iot_util_convert_str_mac(char* str, struct iot_mac* mac)
{
	char* ref_addr = "a1:b2:c3:d4:e5:f6";
	int i, j = 0, k = 1;
	unsigned char c = 0;

	if (!mac || !str) {
		IOT_ERROR("Invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (strlen(str) != strlen(ref_addr)) {
		IOT_ERROR("Input is not a mac string");
		return IOT_ERROR_INVALID_ARGS;
	}

	for (i = 0; i < strlen(ref_addr); i++) {
		if (str[i] == ':') {
			continue;
		} else if (_isalpha(str[i])) {
			switch (str[i]) {
			case 65:
			case 97:
				c |= 0x0a;
				break;
			case 66:
			case 98:
				c |= 0x0b;
				break;
			case 67:
			case 99:
				c |= 0x0c;
				break;
			case 68:
			case 100:
				c |= 0x0d;
				break;
			case 69:
			case 101:
				c |= 0x0e;
				break;
			case 70:
			case 102:
				c |= 0x0f;
				break;
			}
		} else {
			c |= str[i] - 48;
		}

		if ((j + 1) * 2 == k) {
			mac->addr[j++] = c;
			c = 0;
		} else {
			c = c << 4;
		}

		k++;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_util_convert_mac_str(struct iot_mac* mac, char* str, int max_sz)
{
	char* ref_addr = "a1:b2:c3:d4:e5:f6";
	int i, written = 0, wrt;
	char pvt =':';

	if (!mac || !str) {
		IOT_ERROR("Invalid args");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (max_sz < (strlen(ref_addr) + 1)) {
		IOT_ERROR("Invalid max_sz");
		return IOT_ERROR_INVALID_ARGS;
	}

	/* dump random mac */
	for (i = 0; i < 6; i++) {
		wrt = sprintf(&str[written], "%02x", (unsigned char)mac->addr[i]);
		written += wrt;

		if (ref_addr[written] == pvt) {
			str[written] = pvt;
			written++;
		}
	}

	str[written] = '\0';

	return IOT_ERROR_NONE;
}

uint16_t iot_util_convert_channel_freq(uint8_t channel)
{
	if(channel < 1) return 0;

	if(channel < 14) {
		return (2412+(5*(channel - 1)));
	}
	else if(channel == 14) {
		return 2484;
	}
	else if(channel > 31 &&  channel < 174) {
		return 5160+(5*(channel - 32));
	}
	else {
		IOT_ERROR("Not supported channel = %d", channel);
	}

	return 0;
}

iot_error_t iot_util_url_parse(char *url, url_parse_t *output)
{
	char *p1 = NULL;
	char *p2 = NULL;
	char *p_domain = NULL;
	char *p_port = NULL;

	if (!url || !output)
		return IOT_ERROR_INVALID_ARGS;

	p1 = strstr(url, "://");
	if (!p1)
		return IOT_ERROR_INVALID_ARGS;

	p_domain = p1 + 3;
	p2 = strstr(p_domain, ":");
	if (!p2)
		return IOT_ERROR_INVALID_ARGS;

	p_port = p2 + 1;
	output->protocol = calloc(sizeof(char), p1 - url + 1);
	if (!output->protocol)
		return IOT_ERROR_MEM_ALLOC;
	strncpy(output->protocol, url, p1 - url);

	output->domain = calloc(sizeof(char), p2 - p_domain + 1);
	if (!output->domain) {
		free(output->protocol);
		output->protocol = NULL;
		return IOT_ERROR_MEM_ALLOC;
	}
	strncpy(output->domain, p_domain, p2 - p_domain);

	output->port = atoi(p_port);

	return IOT_ERROR_NONE;
}

static timediff_profile_t head;

iot_error_t iot_util_timerecord_start(const char *name, bool want_print, const char *call_func, int line)
{
	timediff_profile_t *td_pf = &head;
	if (name) {
		if (strlen(name) > MAX_TIMEDIFF_NAME_N || strlen(name) == 0) {
			IOT_WARN("TIME RECORD Name length error[1~%d]", MAX_TIMEDIFF_NAME_N);
			return IOT_ERROR_INVALID_ARGS;
		}
		while (td_pf->next) {
			td_pf = td_pf->next;
			if (!strncmp(name, td_pf->name, strlen(name)))
				break;
		}
		if (strncmp(name, td_pf->name, strlen(name))) {
			td_pf->next = malloc(sizeof(timediff_profile_t));
			memset(td_pf->next, '\0', sizeof(timediff_profile_t));
			td_pf = td_pf->next;
			strncpy(td_pf->name, name, strlen(name));
		}
	}

	/* TODO : Currently we record last start point.
	 * We havt to consider other scenario too.
	 */
	td_pf->start_flag = true;
	gettimeofday(&td_pf->tv_start, NULL);

	if (want_print) {
		IOT_INFO("[%s]TIME RECORD START at %s(%d)", name ? name : "default", call_func, line);
	}

	return IOT_ERROR_NONE;
}

long iot_util_timerecord_end(const char *name, bool want_print, const char *call_func, int line)
{
	struct timeval tv_end;
	long timediff_sec, timediff_usec;
	long tmp_sec, tmp_usec;
	timediff_profile_t *td_pf = &head;
	if (name) {
		if (strlen(name) > MAX_TIMEDIFF_NAME_N || strlen(name) == 0) {
			IOT_WARN("TIME RECORD Name length error[1~%d]", MAX_TIMEDIFF_NAME_N);
			return -1;
		}
		while (td_pf->next) {
			td_pf = td_pf->next;
			if (!strncmp(name, td_pf->name, strlen(name)))
				break;
		}
		if (strncmp(name, td_pf->name, strlen(name))) {
			IOT_WARN("NO TIMERECORD[TAG:%s]", name);
			return -1;
		}
	}

	if (!td_pf->start_flag) {
		IOT_WARN("NO TIMERECORD START[TAG:%s]", name ? name : "default");
		return -1;
	}
	td_pf->start_flag = false;

	gettimeofday(&tv_end, NULL);
	timediff_sec = tv_end.tv_sec - td_pf->tv_start.tv_sec;
	timediff_usec = tv_end.tv_usec - td_pf->tv_start.tv_usec;
	if (timediff_usec < 0) {
		timediff_sec -= 1;
		timediff_usec += 1000000;
	}

	tmp_usec = (td_pf->stat_avg_usec * td_pf->stat_n) + timediff_usec;
	tmp_sec = (td_pf->stat_avg_sec * td_pf->stat_n) + timediff_sec + tmp_usec / 1000000;
	tmp_usec %= 1000000;
	td_pf->stat_n++;
	td_pf->stat_avg_sec = tmp_sec / td_pf->stat_n;
	tmp_sec %= td_pf->stat_n;
	td_pf->stat_avg_usec = (tmp_sec * 1000000 + tmp_usec) / td_pf->stat_n;

	if (want_print) {
		IOT_INFO("[%s]TIME RECORD END at %s(%d) %ld.%06ld AVG STAT %ld.%06ld sec count %d",
			name ? name : "default", call_func, line, timediff_sec, timediff_usec,
			td_pf->stat_avg_sec, td_pf->stat_avg_usec, td_pf->stat_n);
	}

	return timediff_sec * 1000000 + timediff_usec;
}

iot_error_t iot_util_timerecord_print(const char *name)
{
	timediff_profile_t *td_pf = &head;
	if (name) {
		if (strlen(name) > MAX_TIMEDIFF_NAME_N || strlen(name) == 0) {
			IOT_WARN("TIME RECORD Name length error[1~%d]", MAX_TIMEDIFF_NAME_N);
			return IOT_ERROR_INVALID_ARGS;
		}
		while (td_pf->next) {
			td_pf = td_pf->next;
			if (!strncmp(name, td_pf->name, strlen(name)))
				break;
		}
		if (strncmp(name, td_pf->name, strlen(name))) {
			IOT_WARN("NO TIMERECORD[TAG:%s]", name);
			return IOT_ERROR_INVALID_ARGS;
		}
	}

	IOT_INFO("[%s]TIME RECORD AVG STAT %ld.%06ld sec count %d",
			name ? name : "default", td_pf->stat_avg_sec, td_pf->stat_avg_usec, td_pf->stat_n);

	return IOT_ERROR_NONE;
}
