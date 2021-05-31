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
#include <time.h>
#include <unistd.h>
#include <iot_bsp_wifi.h>
#include "iot_os_util.h"
#include "iot_debug.h"
#include <ti/drivers/net/wifi/simplelink.h>
#include <ti/drivers/net/wifi/wlan.h>
#include <ti/net/sntp/sntp.h>


#define IOT_CC3220SF_MAX_SCAN (30)
#define IOT_CC3220SF_MAX_SCAN_TRAILS (10)
#define SL_STOP_TIMEOUT (200)
#define TIME_BASEDIFF        ((((uint32_t)70 * 365 + 17) * 24 * 3600))
#define TIME_NTP_TO_LOCAL(t) ((t) - TIME_BASEDIFF)
#define DHCP_LEASE_TIME 4096

/*  Time to wait for reply from server (seconds) */
#define NTP_REPLY_WAIT_TIME 5


/* Status bits - used to set/reset the corresponding bits in given a variable */
typedef enum
{
    /* If this bit is set: Network Processor is powered up                    */
    STATUS_BIT_NWP_INIT = 0,

    /* If this bit is set: the device is connected to the AP or client is     */
    /* connected to device (AP)                                               */
    STATUS_BIT_CONNECTION,

    /* If this bit is set: the device has leased IP to any connected client.  */
    STATUS_BIT_IP_LEASED,

    /* If this bit is set: the device has acquired an IP                      */
    STATUS_BIT_IP_ACQUIRED,

    /* If this bit is set: the SmartConfiguration process is started from     */
    /* SmartConfig app                                                        */
    STATUS_BIT_SMARTCONFIG_START,

    /* If this bit is set: the device (P2P mode) found any p2p-device in scan */
    STATUS_BIT_P2P_DEV_FOUND,

    /* If this bit is set: the device (P2P mode) found any p2p-negotiation    */
    /* request                                                                */
    STATUS_BIT_P2P_REQ_RECEIVED,

    /* If this bit is set: the device(P2P mode) connection to client (or      */
    /* reverse way) is failed                                                 */
    STATUS_BIT_CONNECTION_FAILED,

    /* If this bit is set: the device has completed the ping operation        */
    STATUS_BIT_PING_DONE,

    /* If this bit is set: the device has acquired an IPv6 address.           */
    STATUS_BIT_IPV6L_ACQUIRED,

    /* If this bit is set: the device has acquired an IPv6 address.           */
    STATUS_BIT_IPV6G_ACQUIRED,
    STATUS_BIT_AUTHENTICATION_FAILED,
    STATUS_BIT_RESET_REQUIRED,
}e_StatusBits;

#define CLR_STATUS_BIT_ALL(status_variable)  (status_variable = 0)
#define SET_STATUS_BIT(status_variable, bit) (status_variable |= (1 << (bit)))
#define CLR_STATUS_BIT(status_variable, bit) (status_variable &= ~(1 << (bit)))
#define CLR_STATUS_BIT_ALL(status_variable)  (status_variable = 0)
#define GET_STATUS_BIT(status_variable, bit) (0 != \
                                              (status_variable & (1 << (bit))))

#define IS_CONNECTED(status_variable)        GET_STATUS_BIT( \
		status_variable, \
		STATUS_BIT_CONNECTION)

#define IS_IP_ACQUIRED(status_variable)      GET_STATUS_BIT( \
		status_variable, \
		STATUS_BIT_IP_ACQUIRED)

static const char *srvList[] = {
	"pool.ntp.org",
	"1.kr.pool.ntp.org",
	"1.asia.pool.ntp.org",
	"us.pool.ntp.org",
	"1.cn.pool.ntp.org",
	"1.hk.pool.ntp.org",
	"europe.pool.ntp.org",
	"time1.google.com"
};

/* Station IP address                                                         */
unsigned long g_ulStaIp = 0;
/* Network Gateway IP address                                                 */
unsigned long g_ulGatewayIP = 0;
/* Connection SSID                                                            */
unsigned char g_ucConnectionSSID[SL_WLAN_SSID_MAX_LENGTH + 1];
/* Connection BSSID                                                           */
unsigned char g_ucConnectionBSSID[SL_WLAN_BSSID_LENGTH ];
/* SimpleLink Status                                                          */
volatile unsigned long g_ulStatus = 0;
/* Connection time delay index                                                */
volatile unsigned short g_usConnectIndex;

//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************
void SimpleLinkHttpServerEventHandler(
	SlNetAppHttpServerEvent_t *pSlHttpServerEvent,
	SlNetAppHttpServerResponse_t *
	pSlHttpServerResponse)
{
}

void SimpleLinkNetAppRequestEventHandler(SlNetAppRequest_t *pNetAppRequest,
	SlNetAppResponse_t *pNetAppResponse)
{
}

void SimpleLinkNetAppRequestMemFreeEventHandler(uint8_t *buffer)
{
}

//*****************************************************************************
//!
//! On Successful completion of Wlan Connect, This function triggers connection
//! status to be set.
//!
//! \param[in]  pSlWlanEvent    - pointer indicating Event type
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pSlWlanEvent)
{
	SlWlanEventDisconnect_t* pEventData = NULL;

	switch (pSlWlanEvent->Id) {
	case SL_WLAN_EVENT_CONNECT:
		SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);

		memcpy(g_ucConnectionSSID, pSlWlanEvent->Data.Connect.SsidName,
			pSlWlanEvent->Data.Connect.SsidLen);
		memcpy(g_ucConnectionBSSID, pSlWlanEvent->Data.Connect.Bssid,
			SL_WLAN_BSSID_LENGTH);

		IOT_INFO(
			"[WLAN EVENT] STA Connected to the AP: %s , BSSID: "
			"%x:%x:%x:%x:%x:%x", g_ucConnectionSSID,
			g_ucConnectionBSSID[0], g_ucConnectionBSSID[1],
			g_ucConnectionBSSID[2],
			g_ucConnectionBSSID[3], g_ucConnectionBSSID[4],
			g_ucConnectionBSSID[5]);
		break;
	case SL_WLAN_EVENT_DISCONNECT:
		CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
		CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_ACQUIRED);

		pEventData = &pSlWlanEvent->Data.Disconnect;

		/* If the user has initiated 'Disconnect' request, 'reason_code'  */
		/* is SL_WLAN_DISCONNECT_USER_INITIATED                           */
		if (SL_WLAN_DISCONNECT_USER_INITIATED == pEventData->ReasonCode) {
			IOT_INFO("Device disconnected from the AP on application's "
					"request");
		} else {
			IOT_INFO("Device disconnected from the AP on an ERROR..!!");
		}
	break;
	case SL_WLAN_EVENT_STA_ADDED:
		/* when device is in AP mode and any client connects to it.       */
		SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
		IOT_INFO("a device connected");
	break;
	case SL_WLAN_EVENT_STA_REMOVED:
		/* when device is in AP mode and any client disconnects from it.  */
		CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
		CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_LEASED);
		IOT_INFO("a device disconnected");
	break;
	default:
		IOT_INFO("[WLAN EVENT] Unexpected event %d", pSlWlanEvent->Id);
	break;
	}
}

//*****************************************************************************
//
//! The Function Handles the Fatal errors
//!
//! \param[in]  slFatalErrorEvent - Pointer to Fatal Error Event info
//!
//! \return     None
//!
//*****************************************************************************
void SimpleLinkFatalErrorEventHandler(SlDeviceFatal_t *slFatalErrorEvent)
{
	switch (slFatalErrorEvent->Id) {
	case SL_DEVICE_EVENT_FATAL_DEVICE_ABORT:
		IOT_INFO(
			"[ERROR] - FATAL ERROR: Abort NWP event detected: "
			"AbortType=%d, AbortData=0x%x",
			slFatalErrorEvent->Data.DeviceAssert.Code,
			slFatalErrorEvent->Data.DeviceAssert.Value);
	break;
	case SL_DEVICE_EVENT_FATAL_DRIVER_ABORT:
		IOT_INFO("[ERROR] - FATAL ERROR: Driver Abort detected.");
	break;
	case SL_DEVICE_EVENT_FATAL_NO_CMD_ACK:
		IOT_INFO(
			"[ERROR] - FATAL ERROR: No Cmd Ack detected "
			"[cmd opcode = 0x%x]",
			slFatalErrorEvent->Data.NoCmdAck.Code);
	break;
	case SL_DEVICE_EVENT_FATAL_SYNC_LOSS:
		IOT_INFO("[ERROR] - FATAL ERROR: Sync loss detected");
	break;
	case SL_DEVICE_EVENT_FATAL_CMD_TIMEOUT:
		IOT_INFO(
			"[ERROR] - FATAL ERROR: Async event timeout detected "
			"[event opcode =0x%x] ",
			slFatalErrorEvent->Data.CmdTimeout.Code);
	break;
	default:
		IOT_INFO("[ERROR] - FATAL ERROR: Unspecified error detected");
	break;
	}
}

//*****************************************************************************
//
//! This function handles network events such as IP acquisition, IP leased, IP
//! released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent)
{
	switch (pNetAppEvent->Id) {
	case SL_NETAPP_EVENT_IPV4_ACQUIRED:
	case SL_NETAPP_EVENT_IPV6_ACQUIRED:
		SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_ACQUIRED);
		IOT_INFO("[NETAPP EVENT] IP acquired by the device");

		/* Initialize SlNetSock layer with CC3x20 interface                   */
		int status = ti_net_SlNet_initConfig();
		IOT_INFO("[NETAPP EVENT] SlNet init");
		if (0 != status) {
			IOT_INFO("Failed to initialize SlNetSock");
		}
	break;
	case SL_NETAPP_EVENT_DHCPV4_LEASED:
		SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_LEASED);
		g_ulStaIp = (pNetAppEvent)->Data.IpLeased.IpAddress;

		IOT_INFO("[NETAPP EVENT] IP Leased to Client: IP=%d.%d.%d.%d , ",
			SL_IPV4_BYTE(g_ulStaIp, 3), SL_IPV4_BYTE(g_ulStaIp, 2),
			SL_IPV4_BYTE(g_ulStaIp, 1), SL_IPV4_BYTE(g_ulStaIp, 0));
	break;
	case SL_NETAPP_EVENT_DHCPV4_RELEASED:
		CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_LEASED);

		IOT_INFO("[NETAPP EVENT] IP Released for Client: "
			"IP=%d.%d.%d.%d , ", SL_IPV4_BYTE(g_ulStaIp, 3), SL_IPV4_BYTE(g_ulStaIp, 2),
			SL_IPV4_BYTE(g_ulStaIp, 1), SL_IPV4_BYTE(g_ulStaIp, 0));
	break;
	default:
		IOT_INFO("[NETAPP EVENT] Unexpected event [0x%x]", pNetAppEvent->Id);
	break;
	}
}

//*****************************************************************************
//
//! This function handles resource request
//!
//! \param[in]  pNetAppRequest  - Contains the resource requests
//! \param[in]  pNetAppResponse - Should be filled by the user with the
//!                               relevant response information
//!
//! \return     None
//!
//*****************************************************************************
void SimpleLinkNetAppRequestHandler(SlNetAppRequest_t *pNetAppRequest,
	SlNetAppResponse_t *pNetAppResponse)
{
    /* Unused in this application                                             */
}

//*****************************************************************************
//
//! This function handles HTTP server events
//!
//! \param[in]  pServerEvent     - Contains the relevant event information
//! \param[in]  pServerResponse  - Should be filled by the user with the
//!                                relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlNetAppHttpServerEvent_t *pHttpEvent,
	SlNetAppHttpServerResponse_t *pHttpResponse)
{
	/* Unused in this application                                             */
}

//*****************************************************************************
//
//! This function handles General Events
//!
//! \param[in]  pDevEvent - Pointer to General Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent)
{
	/* Most of the general errors are not FATAL. are to be handled            */
	/* appropriately by the application.                                      */
	IOT_INFO("[GENERAL EVENT] - ID=[%d] Sender=[%d]",
		pDevEvent->Data.Error.Code,
		pDevEvent->Data.Error.Source);
}

//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]  pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock)
{
	/* This application doesn't work w/ socket - Events are not expected      */
	switch (pSock->Event) {
	case SL_SOCKET_TX_FAILED_EVENT:
		switch (pSock->SocketAsyncEvent.SockTxFailData.Status) {
		case SL_ERROR_BSD_ECLOSE:
			IOT_INFO(
				"[SOCK ERROR] - close socket (%d) operation "
				"failed to transmit all queued packets",
				pSock->SocketAsyncEvent.SockTxFailData.Sd);
			break;
		default:
		IOT_INFO(
			"[SOCK ERROR] - TX FAILED  :  socket %d , "
			"reason (%d) ",
			pSock->SocketAsyncEvent.SockTxFailData.Sd,
			pSock->SocketAsyncEvent.SockTxFailData.Status);
		break;
		}
	break;
	case SL_SOCKET_ASYNC_EVENT:
		IOT_INFO("[SOCK ERROR] an event received on socket %d",
		pSock->SocketAsyncEvent.SockAsyncData.Sd);
		switch (pSock->SocketAsyncEvent.SockAsyncData.Type) {
		case SL_SSL_NOTIFICATION_CONNECTED_SECURED:
			IOT_INFO("[SOCK ERROR] SSL handshake done");
		break;
		case SL_SSL_NOTIFICATION_HANDSHAKE_FAILED:
			IOT_INFO("[SOCK ERROR] SSL handshake failed with error %d",
				pSock->SocketAsyncEvent.SockAsyncData.Val);
		break;
		case SL_SSL_ACCEPT:
			IOT_INFO(
				"[SOCK ERROR] Recoverable error occurred during "
				"the handshake %d\r\n",
				pSock->SocketAsyncEvent.SockAsyncData.Val);
		break;
		case SL_OTHER_SIDE_CLOSE_SSL_DATA_NOT_ENCRYPTED:
			IOT_INFO("[SOCK ERROR] Other peer terminated the SSL layer.");
		break;
		case SL_SSL_NOTIFICATION_WRONG_ROOT_CA:
			IOT_INFO("[SOCK ERROR] Used wrong CA to verify the peer.");
		break;
		default:
		break;
		}
	break;
	default:
		IOT_INFO("[SOCK EVENT] - Unexpected Event [%x0x]", pSock->Event);
	break;
	}
}

//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End
//*****************************************************************************

static void _obtain_time(void)
{
	struct tm *timeinfo;
	int retry = 0;
	const int retry_count = 10;
	uint64_t ntpTimeStamp;
	uint32_t currentTime;
	int32_t retval;
	time_t ts;
	SlNetSock_Timeval_t timeval;
	struct timespec tspec;

	/* Set timeout value for NTP server reply */
	timeval.tv_sec = NTP_REPLY_WAIT_TIME;
	timeval.tv_usec = 0;

	while (++retry < retry_count) {
		/* Get the time use the built in NTP server list: */
		retval = SNTP_getTime(srvList, sizeof(srvList) / sizeof(srvList[0]), &timeval, &ntpTimeStamp);
		if (!retval) {
			//set time to local
			currentTime = ntpTimeStamp >> 32;
			currentTime = TIME_NTP_TO_LOCAL(currentTime);

			tspec.tv_nsec = 0;
			tspec.tv_sec = currentTime;
			if (clock_settime(CLOCK_REALTIME, &tspec) != 0) {
				IOT_ERROR("Failed to set current time");
			}

			//print time
			ts = time(NULL);
			timeinfo = localtime(&ts);
			IOT_INFO("Current time is %d-%d-%d %d:%d:%d",
					timeinfo->tm_year + 1900,
					timeinfo->tm_mon + 1,
					timeinfo->tm_mday,
					timeinfo->tm_hour,
					timeinfo->tm_min,
					timeinfo->tm_sec
			);
			break;
		} else {
			IOT_INFO("[IOT_BSP_WIFI] Waiting for system time to be set... (%d/%d),error code %d", retry, retry_count, retval);
			IOT_DELAY(2000);
			IOT_INFO("[IOT_BSP_WIFI] _obtain_time: retrying ...");
		}
	}
}

iot_error_t iot_bsp_wifi_init()
{
	return IOT_ERROR_NONE;
}

/*These code copy from at command sample**/
iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	int32_t sl_ret_val = -1;
	time_t now;
	struct tm *timeinfo;
	int str_len = 0;
	SlWlanSecParams_t secParams;
	iot_error_t iot_ret = IOT_ERROR_NONE;

	memset(&secParams, 0 , sizeof(SlWlanSecParams_t));
	str_len = strlen(conf->pass);

	if (str_len == 0) {
		secParams.Type = SL_WLAN_SEC_TYPE_OPEN;
	} else {
		secParams.Type = SL_WLAN_SEC_TYPE_WPA_WPA2;
		secParams.Key = (char *)malloc((str_len + 1) * sizeof(char));
		if (!secParams.Key) {
			IOT_ERROR("Malloc failed");
			return IOT_ERROR_MEM_ALLOC;
		}
		memcpy(secParams.Key, conf->pass, str_len + 1);
		secParams.KeyLen = str_len;
	}

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF:
		sl_Stop(0);
		sl_Start(NULL, NULL, NULL);
	break;
	case IOT_WIFI_MODE_SCAN:
		IOT_INFO("iot_bsp_wifi_set_mode set SCAN mode");
	break;
	case IOT_WIFI_MODE_STATION:
		sl_WlanSetMode(ROLE_STA);
		sl_Stop(SL_STOP_TIMEOUT);
		sl_ret_val = sl_Start(NULL, NULL, NULL);
		if (sl_ret_val != ROLE_STA) {
			IOT_ERROR("iot_bsp_wifi_set_mode set SCAN mode failed!");
			iot_ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}

		//connect to AP
        sl_ret_val = sl_WlanConnect((const signed char *)(conf->ssid), strlen((const signed char *)(conf->ssid)), 0, &secParams, 0);
		if (sl_ret_val) {
			IOT_ERROR("Connection failed %d !", sl_ret_val);
			iot_ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}

		g_usConnectIndex = 0;
		while (g_usConnectIndex < 10){
			IOT_DELAY(1000);

			if(IS_CONNECTED(g_ulStatus) && IS_IP_ACQUIRED(g_ulStatus)) {
				break;
			}
			g_usConnectIndex++;
		}

		if (g_usConnectIndex == 10) {
			IOT_ERROR("WIFI_STA_CONNECT_BIT event Timeout");
			sl_Stop(SL_STOP_TIMEOUT);
			iot_ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}

		time(&now);
		timeinfo = localtime(&now);
		if (timeinfo->tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}
	break;
	case IOT_WIFI_MODE_SOFTAP:
		/* set SSID name */
		sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_SSID,
				strlen((const char *)(conf->ssid)),
				(unsigned char*)(conf->ssid));

		/* Set security type */
		sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_SECURITY_TYPE, 1, &secParams.Type);

		/* Set password (if needed) */
		if (secParams.Type != SL_WLAN_SEC_TYPE_OPEN) {
			sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_PASSWORD,
						strlen((const char *)(conf->pass)),
						(unsigned char*)(conf->pass));
		}

		uint8_t channel = 6;	//#define SOFTAP_CHANNEL 6
		/* Set channel number */
		sl_WlanSet(SL_WLAN_CFG_AP_ID, SL_WLAN_AP_OPT_CHANNEL,
						sizeof(channel),
						(unsigned char *)(&channel));

		sl_WlanDisconnect();
		sl_WlanSetMode(ROLE_AP);		  /* Set device role as AP */
		/* Restart the NWP so the new configuration will take affect */
		sl_Stop(SL_STOP_TIMEOUT);
		sl_ret_val = sl_Start(NULL, NULL, NULL);
		if (sl_ret_val != ROLE_AP) {
			IOT_ERROR("Unable to configure AP role");
			iot_ret = IOT_ERROR_CONN_OPERATE_FAIL;
			goto out;
		}

		SlNetCfgIpV4Args_t ipV4;
		ipV4.Ip 		 = (_u32)SL_IPV4_VAL(192, 168, 4, 1);
		ipV4.IpMask 	 = (_u32)SL_IPV4_VAL(255, 255 , 255, 0);
		ipV4.IpGateway	 = (_u32)SL_IPV4_VAL(192, 168, 4, 1);
		sl_NetCfgSet(SL_NETCFG_IPV4_AP_ADDR_MODE, SL_NETCFG_ADDR_STATIC, sizeof(SlNetCfgIpV4Args_t), (_u8 *)&ipV4);
		/* Restart the NWP so the new configuration will take affect */
		sl_Stop(0);
		sl_Start(NULL, NULL, NULL);

		//set DHCP ip region
		SlNetAppDhcpServerBasicOpt_t dhcpParams;
		_u8 outLen = sizeof(SlNetAppDhcpServerBasicOpt_t);
		dhcpParams.lease_time	   =  DHCP_LEASE_TIME;
		// lease time (in seconds) of the IP Address
		dhcpParams.ipv4_addr_start =  SL_IPV4_VAL(192, 168, 4, 2);
		// first IP Address for allocation. IP Address should be set as Hex number - i.e. 0A0B0C01 for (10.11.12.1)
		dhcpParams.ipv4_addr_last  =  SL_IPV4_VAL(192, 168, 4, 254);
		// last IP Address for allocation. IP Address should be set as Hex number - i.e. 0A0B0C01 for (10.11.12.1)
		sl_NetAppStop(SL_NETAPP_DHCP_SERVER_ID);
		// Stop DHCP server before settings
		sl_NetAppSet(SL_NETAPP_DHCP_SERVER_ID, SL_NETAPP_DHCP_SRV_BASIC_OPT, outLen, (_u8 *)&dhcpParams);
		// set parameters
		sl_NetAppStart(SL_NETAPP_DHCP_SERVER_ID);
		// Start DHCP server with new settings
		break;
	default:
		break;
	}

out:
	if (secParams.Key) {
		free(secParams.Key);
	}

	return iot_ret;
}

static SlWlanNetworkEntry_t netEntries[IOT_CC3220SF_MAX_SCAN];

static iot_wifi_auth_mode_t _cc3220sf_sec_to_auth(uint32_t sec_type)
{
	/*
	SL_WLAN_SCAN_RESULT_SEC_TYPE_BITMAP returns security code of scanned ap list
	Possible values:
		SL_WLAN_SECURITY_TYPE_BITMAP_OPEN,
		SL_WLAN_SECURITY_TYPE_BITMAP_WEP,
		SL_WLAN_SECURITY_TYPE_BITMAP_WPA,
		SL_WLAN_SECURITY_TYPE_BITMAP_WPA2,
		SL_WLAN_SECURITY_TYPE_BITMAP_WPA3,
		0x6 (mix mode) SL_WLAN_SECURITY_TYPE_BITMAP_WPA | SL_WLAN_SECURITY_TYPE_BITMAP_WPA2
	*/

	iot_wifi_auth_mode_t ret = IOT_WIFI_AUTH_MAX;

	switch (sec_type) {
	case SL_WLAN_SECURITY_TYPE_BITMAP_OPEN:
		ret = IOT_WIFI_AUTH_OPEN;
		break;
	case SL_WLAN_SECURITY_TYPE_BITMAP_WEP:
		ret = IOT_WIFI_AUTH_WEP;
		break;
	case SL_WLAN_SECURITY_TYPE_BITMAP_WPA:
		ret = IOT_WIFI_AUTH_WPA_PSK;
		break;
	case SL_WLAN_SECURITY_TYPE_BITMAP_WPA2:
		ret = IOT_WIFI_AUTH_WPA2_PSK;
		break;
	case SL_WLAN_SECURITY_TYPE_BITMAP_MIX_WPA_WPA2:
		ret = IOT_WIFI_AUTH_WPA_WPA2_PSK;
		break;
	case SL_WLAN_SECURITY_TYPE_BITMAP_WPA3:
	default:
		ret = IOT_WIFI_AUTH_MAX;
		break;
	}

	return ret;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	uint8_t i;	
	int16_t resultsCount;
	uint8_t triggeredScanTrials = 0;

	resultsCount = sl_WlanGetNetworkList(0, IOT_CC3220SF_MAX_SCAN, &netEntries[0]);

	/* If scan policy isn't set, invoking 'sl_WlanGetNetworkList()'
	 * for the first time triggers 'one shot' scan.
	 * The scan parameters would be according to the system persistent
	 * settings on enabled channels.
	 * For more information, see: <simplelink user guide, page: pr.>
	 */
	if (SL_ERROR_WLAN_GET_NETWORK_LIST_EAGAIN == resultsCount) {
		while (triggeredScanTrials < IOT_CC3220SF_MAX_SCAN_TRAILS) {
			/* We wait for one second for the NWP to complete
			the initiated scan and collect results */
			IOT_DELAY(1000);

			/* Collect results form one-shot scans.*/
			resultsCount = sl_WlanGetNetworkList(0, IOT_CC3220SF_MAX_SCAN, &netEntries[0]);
			if (resultsCount > 0) {
				break;
			} else {
				/* If NWP results aren't ready,
				try 'MAX_SCAN_TRAILS' attempts to get results */
				triggeredScanTrials++ ;
			}
		}
	}

	if (resultsCount <= 0) {
		IOT_ERROR("[scan] : Unable to retrieve the network list");
		return 0;
	}

	if (resultsCount > IOT_WIFI_MAX_SCAN_RESULT) {
		resultsCount = IOT_WIFI_MAX_SCAN_RESULT;
	}
	
	int ssid_len = 0;
	for (i = 0; i < resultsCount; i++) {
		ssid_len = strlen((char *)netEntries[i].Ssid);
		if (ssid_len >= IOT_WIFI_MAX_SSID_LEN) {
			ssid_len = IOT_WIFI_MAX_SSID_LEN - 1;
		}
		memset(scan_result[i].ssid, 0, IOT_WIFI_MAX_SSID_LEN);
		memcpy(scan_result[i].ssid, netEntries[i].Ssid, ssid_len);
		memcpy(scan_result[i].bssid, netEntries[i].Bssid, IOT_WIFI_MAX_BSSID_LEN);

		scan_result[i].rssi = netEntries[i].Rssi;
		scan_result[i].freq = iot_util_convert_channel_freq(netEntries[i].Channel);
		scan_result[i].authmode = _cc3220sf_sec_to_auth(SL_WLAN_SCAN_RESULT_SEC_TYPE_BITMAP(netEntries[i].SecurityInfo));

		IOT_DEBUG("CC3220SF ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, authmode=%d chan=%d",
				scan_result[i].ssid,
				scan_result[i].bssid[0], scan_result[i].bssid[1], scan_result[i].bssid[2],
				scan_result[i].bssid[3], scan_result[i].bssid[4], scan_result[i].bssid[5], scan_result[i].rssi,
				scan_result[i].freq, scan_result[i].authmode, netEntries[i].Channel);
	}

	return resultsCount;
}

/*Note: sample: '0' -> 0x0, '1' -> 0x1, ...'a'->0xa,  'E' -> 0xE, 'F' -> 0xF*/

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	int32_t status = -1;
	uint16_t macAddressLen = SL_MAC_ADDR_LEN;
	status = sl_NetCfgGet(SL_NETCFG_MAC_ADDRESS_GET, 0, &macAddressLen, wifi_mac);
	if (status < 0) {
		return IOT_ERROR_READ_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}

iot_error_t iot_bsp_wifi_set_keepalive(uint32_t idle, uint32_t interval, uint32_t count)
{
	return IOT_ERROR_NONE;
}
