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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "iot_main.h"
#include "iot_debug.h"

static iot_error_t _iot_net_check_interface(iot_net_interface_t *net)
{
    if (net == NULL) {
        IOT_ERROR("interface is null");
        return IOT_ERROR_NET_INVALID_INTERFACE;
    }

    return IOT_ERROR_NONE;
}

static void _iot_net_show_status(iot_net_interface_t *net)
{
    return;
}

static int _iot_net_select(iot_net_interface_t *net, unsigned int timeout_ms)
{
    int ret = 0;

    if (_iot_net_check_interface(net)) {
        return 0;
    }

    if (net->context.bufferedByteValid)
        return 1;

    iot_os_timer expiry_timer = NULL;
    IotNetworkInterface_t   *pNetIf = IOT_NETWORK_INTERFACE_AFR;
    iot_error_t iot_err = iot_os_timer_init(&expiry_timer);
    if (iot_err) {
        IOT_ERROR("fail to init timer\r\n");
        return 0;
    }
    iot_os_timer_count_ms(expiry_timer, timeout_ms);
    do {
        ret = pNetIf->receiveUpto(net->context.pNetworkConnection, &net->context.bufferedByte, 1);
    } while(!ret && !iot_os_timer_isexpired(expiry_timer));

    if (ret == 1)
        net->context.bufferedByteValid = true;

    return ret;
}

static iot_error_t _iot_net_tls_connect(iot_net_interface_t *net)
{
    iot_error_t err;
    IotNetworkServerInfo_t  *pServerInfo = &net->context.serverInfo;
    IotNetworkCredentials_t *pCredentials = &net->context.credentials;
    iot_net_connection_t    *pIoTNetConn = &net->connection;
    IotNetworkInterface_t   *pNetIf = IOT_NETWORK_INTERFACE_AFR;
    IotNetworkError_t networkStatus = IOT_NETWORK_SUCCESS;

    err = _iot_net_check_interface(net);
    if (err) {
        return err;
    }

    pServerInfo->pHostName       = pIoTNetConn->url;
    pServerInfo->port            = (uint16_t)pIoTNetConn->port;

    pCredentials->pRootCa        = pIoTNetConn->ca_cert;
    pCredentials->rootCaSize     = pIoTNetConn->ca_cert_len + 1;
    pCredentials->pClientCert    = pIoTNetConn->cert;
    pCredentials->clientCertSize = pIoTNetConn->cert_len;
    pCredentials->pPrivateKey    = pIoTNetConn->key;
    pCredentials->privateKeySize = pIoTNetConn->key_len;

    networkStatus = pNetIf->create(pServerInfo, pCredentials, &net->context.pNetworkConnection);

    if (networkStatus == IOT_NETWORK_SUCCESS) {
        IOT_INFO("tls connect ok");
        return IOT_ERROR_NONE;
    } else {
        IOT_ERROR("tls connect err");
        return IOT_ERROR_NET_CONNECT;
    }
}

static void _iot_net_tls_disconnect(iot_net_interface_t *net)
{
    IotNetworkInterface_t   *pNetIf = IOT_NETWORK_INTERFACE_AFR;
    pNetIf->close(net->context.pNetworkConnection);
    pNetIf->destroy(net->context.pNetworkConnection);
}

static int _iot_net_tls_read(iot_net_interface_t *net,
		unsigned char *buf, size_t len, iot_os_timer timer)
{
    size_t bytesReceived = 0;
    size_t ret = 0;
    IotNetworkInterface_t *pNetIf = IOT_NETWORK_INTERFACE_AFR;

    IOT_DEBUG("%d@%p", len, buf);

    if (_iot_net_check_interface(net)) {
        return 0;
    }

    if (buf == NULL || timer == NULL) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    if (net->context.bufferedByteValid) {
        *buf = net->context.bufferedByte;
        bytesReceived = 1;
        net->context.bufferedByteValid = false;
    }

    if (len > bytesReceived) {
        do {
            ret = pNetIf->receiveUpto(net->context.pNetworkConnection, buf + bytesReceived, len - bytesReceived);
        } while(!ret && !iot_os_timer_isexpired(timer));
    }

    return bytesReceived + ret;
}

static int _iot_net_tls_write(iot_net_interface_t *net,
		unsigned char *buf, int len, iot_os_timer timer)
{
    int sentLen = 0; 
    size_t ret = 0;
    IotNetworkInterface_t *pNetIf = IOT_NETWORK_INTERFACE_AFR;

    IOT_DEBUG("%d@%p", len, buf);

    if (_iot_net_check_interface(net)) {
        return 0;
    }

    do {
        ret = pNetIf->send(net->context.pNetworkConnection, buf + sentLen, len - sentLen);

        if(ret > 0) 
            sentLen += ret;
    } while (sentLen < len && !iot_os_timer_isexpired(timer));

    return sentLen;
}

iot_error_t iot_net_init(iot_net_interface_t *net)
{
    iot_error_t err;

    err = _iot_net_check_interface(net);
    if (err) {
        return err;
    }
    
    net->connect = _iot_net_tls_connect;
    net->disconnect = _iot_net_tls_disconnect;
    net->select = _iot_net_select;
    net->read = _iot_net_tls_read;
    net->write = _iot_net_tls_write;
    net->show_status =_iot_net_show_status;

    return IOT_ERROR_NONE;
}
