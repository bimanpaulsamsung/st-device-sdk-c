/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_CAPS_HELPER_LOG_TRIGGER_
#define _IOT_CAPS_HELPER_LOG_TRIGGER_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CAP_ENUM_LOGTRIGGER_LOGSTATE_VALUE_IDLE,
    CAP_ENUM_LOGTRIGGER_LOGSTATE_VALUE_INPROGRESS,
    CAP_ENUM_LOGTRIGGER_LOGSTATE_VALUE_MAX
};

enum {
    CAP_ENUM_LOGTRIGGER_LOGREQUESTSTATE_VALUE_IDLE,
    CAP_ENUM_LOGTRIGGER_LOGREQUESTSTATE_VALUE_TRIGGERREQUIRED,
    CAP_ENUM_LOGTRIGGER_LOGREQUESTSTATE_VALUE_MAX
};

const static struct iot_caps_logTrigger {
    const char *id;
    const struct logTrigger_attr_logInfo {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
    } attr_logInfo;
    const struct logTrigger_attr_logState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOGTRIGGER_LOGSTATE_VALUE_MAX];
        const char *value_idle;
        const char *value_inProgress;
    } attr_logState;
    const struct logTrigger_attr_logRequestState {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const char *values[CAP_ENUM_LOGTRIGGER_LOGREQUESTSTATE_VALUE_MAX];
        const char *value_idle;
        const char *value_triggerRequired;
    } attr_logRequestState;
    const struct logTrigger_cmd_triggerLog { const char* name; } cmd_triggerLog;
    const struct logTrigger_cmd_triggerLogWithLogInfo { const char* name; } cmd_triggerLogWithLogInfo;
    const struct logTrigger_cmd_triggerLogWithUrl { const char* name; } cmd_triggerLogWithUrl;
} caps_helper_logTrigger = {
    .id = "logTrigger",
    .attr_logInfo = {
        .name = "logInfo",
        .property = ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_OBJECT,
    },
    .attr_logState = {
        .name = "logState",
        .property = 0,
        .valueType = VALUE_TYPE_STRING,
        .values = {"idle", "inProgress"},
        .value_idle = "idle",
        .value_inProgress = "inProgress",
    },
    .attr_logRequestState = {
        .name = "logRequestState",
        .property = 0,
        .valueType = VALUE_TYPE_STRING,
        .values = {"idle", "triggerRequired"},
        .value_idle = "idle",
        .value_triggerRequired = "triggerRequired",
    },
    .cmd_triggerLog = { .name = "triggerLog" },
    .cmd_triggerLogWithLogInfo = { .name = "triggerLogWithLogInfo" }, // arguments: logInfo(object) 
    .cmd_triggerLogWithUrl = { .name = "triggerLogWithUrl" }, // arguments: url(string) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_LOG_TRIGGER_ */
