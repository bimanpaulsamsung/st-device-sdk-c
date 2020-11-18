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

#ifndef _IOT_NET_PLATFORM_H_
#define _IOT_NET_PLATFORM_H_

/* FreeRTOS network include. */
#include "platform/iot_network_freertos.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iot_net_platform_context {
    IotNetworkServerInfo_t      serverInfo;
    IotNetworkCredentials_t     credentials;
    IotNetworkConnectionAfr_t  *pNetworkConnection;
    // though buffered byte is defined in _networkConnection, but it is not exposed.
    bool                        bufferedByteValid;            /**< @brief Used to determine if the buffered byte is valid. */
    uint8_t                     bufferedByte;                 /**< @brief A single byte buffered from a receive, since AFR Secure Sockets does not have poll(). */
        
} iot_net_platform_context_t;

#ifdef __cplusplus
}
#endif
#endif /* _IOT_NET_PLATFORM_H_ */
