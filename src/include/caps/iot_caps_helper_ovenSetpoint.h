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

#ifndef _IOT_CAPS_HELPER_OVEN_SETPOINT_
#define _IOT_CAPS_HELPER_OVEN_SETPOINT_

#include "iot_caps_helper.h"

#ifdef __cplusplus
extern "C" {
#endif

const static struct iot_caps_ovenSetpoint {
    const char *id;
    const struct ovenSetpoint_attr_ovenSetpoint {
        const char *name;
        const unsigned char property;
        const unsigned char valueType;
        const int min;
    } attr_ovenSetpoint;
    const struct ovenSetpoint_cmd_setOvenSetpoint { const char* name; } cmd_setOvenSetpoint;
} caps_helper_ovenSetpoint = {
    .id = "ovenSetpoint",
    .attr_ovenSetpoint = {
        .name = "ovenSetpoint",
        .property = ATTR_SET_VALUE_MIN | ATTR_SET_VALUE_REQUIRED,
        .valueType = VALUE_TYPE_INTEGER,
        .min = 0,
    },
    .cmd_setOvenSetpoint = { .name = "setOvenSetpoint" }, // arguments: setpoint(integer) 
};

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CAPS_HERLPER_OVEN_SETPOINT_ */
