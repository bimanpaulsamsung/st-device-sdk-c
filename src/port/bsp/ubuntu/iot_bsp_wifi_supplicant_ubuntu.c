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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>

#include <gio/gio.h>
#include <glib.h>

#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_bsp_wifi_supplicant_ubuntu.h"

#define SUPPLICANT_PROP_INTERFACE "org.freedesktop.DBus.Properties"
#define SUPPLICANT_SERVICE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH "/fi/w1/wpa_supplicant1"

#define INTERFACE_UNKNOWN_ERROR 36

#define WIRELESS_CTRL_INTF_PATH "/sys/class/net"
#define PID_DIRECTORY "/var/run"

#define DNSMASQ_LEASES_FILE "/var/lib/misc/dnsmasq.leases"

#define DHCLIENT_LEASES_FILE "/var/lib/dhcp/dhclient.leases"
#define DHCLIENT_CONF_LEN 1024
#define DHCLIENT_CONF_FILE "/etc/dhclient.conf"
#define DHCLIENT_CONF "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8; \n" \
					  "send host-name \"%s\";\n" \
					  "request subnet-mask, broadcast-address, time-offset, routers," \
					  "domain-name, domain-name-servers, domain-search, host-name," \
					  "dhcp6.name-servers, dhcp6.domain-search," \
					  "netbios-name-servers, netbios-scope, interface-mtu," \
					  "rfc3442-classless-static-routes, ntp-servers;\n"

static char *g_softap_iface;
static char *g_iface;
static char *g_network;
static GDBusConnection *g_connection;

static int supplicant_gdbus_method_call_sync(char *service,
                                             char *object_path,
                                             char *iface,
                                             char *method,
                                             GVariant *parameter,
                                             GVariant **reply)
{
	g_autoptr(GError) error = NULL;
	if (!g_connection)
		return -EINVAL;

	*reply = g_dbus_connection_call_sync(g_connection,
                                        service,
                                        object_path,
                                        iface,
                                        method,
                                        parameter,
                                        NULL,
                                        G_DBUS_CALL_FLAGS_NONE,
                                        1000,
                                        NULL,
                                        &error);
	if (error) {
		IOT_ERROR("Error while sending dbus method call %s", error->message);
		return error->code;
	}
	return 0;
}

int supplicant_get_wireless_interface(char **ctrl_ifname)
{
	struct dirent *dent;

	DIR *dir = opendir(WIRELESS_CTRL_INTF_PATH);
	if (dir) {
		while ((dent = readdir (dir)) != NULL) {
			if (dent->d_name[0] == 'w' && dent->d_name[1] == 'l') {
				*ctrl_ifname = strdup(dent->d_name);
				closedir(dir);
				return 0;
			}
		}
		closedir(dir);
	}
	return -ENOENT;
}

static int supplicant_get_interface(char *ctrl_ifname, char **iface)
{
	int ret;
	GVariant *reply;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          SUPPLICANT_PATH,
                                          SUPPLICANT_INTERFACE,
                                          "GetInterface",
                                          g_variant_new("(s)", (const gchar *)ctrl_ifname),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while sending get interface method call %d", ret);
		return ret;
	}
	g_variant_get(reply, "(&o)", iface);
	IOT_DEBUG("WPA supplicant active interface:%s", *iface);
	return 0;
}

static int supplicant_remove_interface(char *iface)
{
	int ret;
	GVariant *reply;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          SUPPLICANT_PATH,
                                          SUPPLICANT_INTERFACE,
                                          "RemoveInterface",
                                          g_variant_new("(o)", iface),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while sending remove interface method call %d", ret);
		return -1;
	}
	return 0;
}

static int supplicant_create_interface(char *ctrl_ifname, char **iface)
{
	int ret;
	GVariant *reply;
	GVariant *parameter;
	GVariantBuilder *builder;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", "Ifname", g_variant_new_string(ctrl_ifname));
	parameter = g_variant_builder_end(builder);
	g_variant_builder_unref(builder);

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          SUPPLICANT_PATH,
                                          SUPPLICANT_INTERFACE,
                                          "CreateInterface",
                                          g_variant_new_tuple(&parameter, 1),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while sending create interface method call: %d", ret);
		return -1;
	}

	g_variant_get(reply, "(&o)", iface);
	IOT_DEBUG("WPA supplicant new interface:%s", *iface);
	return 0;
}

static int supplicant_set_interface(char *iface, int ap_scan)
{
	int ret;
	GVariant *reply;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          iface,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Set",
                                          g_variant_new("(ssv)", SUPPLICANT_INTERFACE".Interface",
                                                        "ApScan", g_variant_new("u", ap_scan)),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while updating ap_scan mode of the interface %d", ret);
		return -1;
	}
	return 0;
}

static int supplicant_get_apscan_mode(char *iface, int *mode)
{
	int ret;
	GVariant *reply;
	GVariant *iter;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          iface,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE".Interface",
                                                        "ApScan"),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while fetching apscan mode of the interface %d", ret);
		return -1;
	}
	g_variant_get(reply, "(v)", &iter);
	g_variant_get(iter, "u", mode);
	return 0;
}

static int supplicant_configure_interface(char **iface, int mode)
{
	char *ctrl_ifname;
	char *temp_iface;
	int apscan_mode;
	int ret;

	ret = supplicant_get_wireless_interface(&ctrl_ifname);
	if (ret) {
		IOT_ERROR("Unable to fetch wireless interface name %d", ret);
		return -1;
	}

	ret = supplicant_get_interface(ctrl_ifname, &temp_iface);
	if (ret) {
		if (ret != INTERFACE_UNKNOWN_ERROR)
			return -1;

		ret = supplicant_create_interface(ctrl_ifname, &temp_iface);
		if (ret) {
			IOT_ERROR("unable to send create interface method call: %d", ret);
			return -1;
		}

		ret = supplicant_set_interface(temp_iface, mode);
		if (ret) {
			IOT_ERROR("unable to send set interface method call: %d", ret);
			return -1;
		}

		*iface = temp_iface;
		return 0;
	}

	supplicant_get_apscan_mode(temp_iface, &apscan_mode);
	if (apscan_mode == mode) {
		IOT_INFO("already in required mode");
		*iface = temp_iface;
		return 0;
	}

	ret = supplicant_remove_interface(temp_iface);
	if (ret) {
		IOT_ERROR("unable to send remove interface method call: %d", ret);
		return -1;
	}

	if (mode == 1)
		g_softap_iface = NULL;
	else
		g_iface = NULL;

	ret = supplicant_create_interface(ctrl_ifname, &temp_iface);
	if (ret) {
		IOT_ERROR("unable to send get interface method call: %d", ret);
		return -1;
	}

	ret = supplicant_set_interface(temp_iface, mode);
	if (ret) {
		IOT_ERROR("unable to send set interface method call: %d", ret);
		return -1;
	}

	*iface = temp_iface;
	return 0;
}

static int supplicant_get_scanned_ap_record(char *bss_path, iot_wifi_scan_result_t *ap_record)
{
	GVariant *reply;
	GVariant *prop;
	GVariantIter *iter;
	int16_t signal;
	uint8_t byt;
	int ret;
	int i;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          bss_path,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE".BSS",
                                          "BSSID"),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while getting BSSID property of BSS %d", ret);
		return -1;
	}

	g_variant_get(reply, "(v)", &prop);
	g_variant_get(prop, "ay", &iter);
	for (i = 0; g_variant_iter_loop(iter, "y", &byt) && i < IOT_WIFI_MAX_BSSID_LEN; i++) {
		ap_record->bssid[i] = byt;
	}

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          bss_path,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE".BSS",
                                          "SSID"),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while getting SSID property of BSS %d", ret);
		return -1;
	}

	g_variant_get(reply, "(v)", &prop);
	g_variant_get(prop, "ay", &iter);
	for (i = 0; g_variant_iter_loop(iter, "y", &byt) && i < IOT_WIFI_MAX_SSID_LEN; i++) {
		ap_record->ssid[i] = byt;
	}
	ap_record->ssid[i] = '\0';

	/* TODO: Set appropriate key management method value */
	ap_record->authmode = IOT_WIFI_AUTH_WPA_WPA2_PSK;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          bss_path,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE".BSS",
                                          "Frequency"),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while getting Frequency property of BSS %d", ret);
		return -1;
	}

	g_variant_get(reply, "(v)", &prop);
	g_variant_get(prop, "q", &(ap_record->freq));

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          bss_path,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE".BSS",
                                          "Signal"),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while getting Signal property of BSS %d", ret);
		return -1;
	}

	g_variant_get(reply, "(v)", &prop);
	g_variant_get(prop, "n", &signal);
	ap_record->rssi = (int8_t) signal;
	return 0;
}

static int supplicant_variant_builder(struct wpa_ssid *ssid, GVariant **parameter)
{
	GVariantBuilder *builder;
	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	if (ssid == NULL) {
		IOT_ERROR("invalid wpa_ssid parameter");
		return -EINVAL;
	}

	g_variant_builder_add(builder, "{sv}", "ssid", g_variant_new_string(strdup(ssid->ssid)));
	g_variant_builder_add(builder, "{sv}", "mode", g_variant_new("u", ssid->mode));
	g_variant_builder_add(builder, "{sv}", "key_mgmt", g_variant_new_string(ssid->key_mgmt));
	g_variant_builder_add(builder, "{sv}", "psk", g_variant_new_string(strdup(ssid->pswd)));

	*parameter = g_variant_builder_end(builder);
	g_variant_builder_unref(builder);
	return 0;
}

static int supplicant_add_network(char *iface, struct wpa_ssid *ssid)
{
	GVariant *reply;
	GVariant *parameter;
	int ret;

	supplicant_variant_builder(ssid, &parameter);
	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                           iface,
                                           SUPPLICANT_INTERFACE".Interface",
                                           "AddNetwork",
                                           g_variant_new_tuple(&parameter, 1),
                                           &reply);

	if (ret) {
		IOT_ERROR("error while sending add network method call %d", ret);
		return -1;
	}

	/* TODO: Replace sleep with other alternatives */
	sleep(2);

	g_variant_get(reply, "(&o)", &g_network);
	IOT_DEBUG("added new network %s", g_network);
	return 0;
}

static int supplicant_remove_network(char *iface)
{
	GVariant *reply;
	int ret;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                           iface,
                                           SUPPLICANT_INTERFACE".Interface",
                                           "RemoveNetwork",
                                           g_variant_new("(o)", g_network),
                                           &reply);
	if (ret) {
		IOT_ERROR("error while removing network %d", ret);
		return -1;
	}
	return 0;
}

static int supplicant_select_network(char *iface)
{
	GVariant *reply;
	GVariant *parameter;
	int ret;

	parameter = g_variant_new("o", g_network);
	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                           iface,
                                           SUPPLICANT_INTERFACE".Interface",
                                           "SelectNetwork",
                                           g_variant_new_tuple(&parameter, 1),
                                           &reply);
	if (ret) {
		IOT_ERROR("error while sending select network method call: %d", ret);
		return -1;
	}
	return 0;
}

static int supplicant_enable_network(void)
{
	GVariant *reply;
	int ret;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                           g_network,
                                           SUPPLICANT_PROP_INTERFACE,
                                           "Set",
                                           g_variant_new("(ssv)", SUPPLICANT_INTERFACE".Network",
                                                         "Enabled", g_variant_new("b", true)),
                                           &reply);
	if (ret) {
		IOT_ERROR("error while enabling the network %d", ret);
		return -1;
	}
	return 0;
}

static int supplicant_execute_command(const char *file_path, char *const args[], char *const envs[])
{
	int pid;
	int rv;
	errno = 0;

	pid = fork();
	switch (pid) {
	case -1:
		IOT_ERROR("fork failed");
		return -1;
	case 0:
		if (execve(file_path, args, envs) == -1) {
		 IOT_ERROR("failed to execute command (%s)", strerror(errno));
		 exit(1);
		 return -1;
		}
		break;
	default:
		if (waitpid(pid, &rv, 0) == -1)
		 IOT_DEBUG("wait pid (%u) rv (%d)", pid, rv);
		break;
	}
	return pid;
}

static int supplicant_fetch_pid(char *process_name)
{
	int max_pid_len = 32768;
	char line[max_pid_len];
	char command[100];

	snprintf(command, sizeof(command), "pidof %s", process_name);
	FILE *proc = popen(command, "r");
	if (fgets(line, max_pid_len, proc)) {
		pid_t pid = strtoul(line, NULL, 10);
		pclose(proc);
		return pid;
	}
	pclose(proc);
	return -1;
}

int supplicant_turn_wifi_off(void)
{
	int ret;

	IOT_DEBUG("Turning off wifi");
	ret = system("sudo nmcli radio wifi off");
	if (ret == -1 || ret == 127) {
		IOT_ERROR("system() invoke error(%d)", ret);
		return -1;
	}

	IOT_DEBUG("Unblocking wifi");
	ret = system("sudo rfkill unblock wifi");
	if (ret == -1 || ret == 127) {
		IOT_ERROR("system() invoke error(%d)", ret);
		return -1;
	}
	return 0;
}

int supplicant_turn_wifi_on(void)
{
	int ret;

	IOT_DEBUG("Turning on wifi");
	ret = system("sudo nmcli radio wifi on");
	if (ret == -1 || ret == 127) {
		IOT_ERROR("system() invoke error(%d)", ret);
		return -1;
	}
	return 0;
}

void supplicant_initialise_wifi(void)
{
	char *const args_kill_wpa[] = {"/usr/bin/killall", "wpa_supplicant", NULL};
	char *const envs[] = { NULL };
	int ret;

	ret = supplicant_execute_command(args_kill_wpa[0], &args_kill_wpa[0], envs);
	if (ret < 0)
		IOT_INFO("failed to kill wpa_supplicant (%d)", ret);

	sleep(1);

	supplicant_stop_dhcp_client();
	supplicant_stop_dhcp_server();

	supplicant_leave_network();
	supplicant_stop_station();
	supplicant_stop_softap();
}

int supplicant_is_scan_mode(void)
{
	if (g_iface || g_softap_iface)
		return 1;
	return 0;
}

int supplicant_start_scan(void)
{
	GVariant *reply;
	GVariant *parameter;
	GVariantBuilder *builder;
	int ret;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", "Type", g_variant_new_string("active"));
	parameter = g_variant_builder_end(builder);
	g_variant_builder_unref(builder);

	IOT_INFO("Triggered a scan");
	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                           g_iface ? g_iface : g_softap_iface,
                                           SUPPLICANT_INTERFACE".Interface",
                                           "Scan",
                                           g_variant_new_tuple(&parameter, 1),
                                           &reply);
	if (ret) {
		IOT_ERROR("error while sending scan method call %d", ret);
		return -1;
	}

	/* TODO: Replace sleep with other alternatives */
	sleep(4);
	return 0;
}

uint16_t supplicant_get_scanned_ap_list(iot_wifi_scan_result_t *ap_list)
{
	int ret;
	uint16_t i;
	GVariant *reply;
	GVariant *temp;
	GVariantIter *iter;
	char *bss_path;
	iot_wifi_scan_result_t ap_record;

	ret = supplicant_gdbus_method_call_sync(SUPPLICANT_SERVICE,
                                          g_iface ? g_iface : g_softap_iface,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE".Interface",
                                                        "BSSs"),
                                          &reply);
	if (ret) {
		IOT_ERROR("error while fetching apscan mode of the interface %d", ret);
		return -1;
	}

	g_variant_get(reply, "(v)", &temp);
	g_variant_get(temp, "ao", &iter);

	for (i = 0; g_variant_iter_loop(iter, "o", &bss_path) && i < IOT_WIFI_MAX_SCAN_RESULT; i++) {
		if (supplicant_get_scanned_ap_record(bss_path, &ap_record)== 0) {
			memcpy(ap_list[i].ssid, ap_record.ssid, strlen((char *)ap_record.ssid));
			memcpy(ap_list[i].bssid, ap_record.bssid, IOT_WIFI_MAX_BSSID_LEN);

			ap_list[i].rssi = ap_record.rssi;
			ap_list[i].freq = ap_record.freq;
			ap_list[i].authmode = ap_record.authmode;
		}
		else {
			i--;
		}
	}
	return i;
}

int supplicant_start_station(void)
{
	if (!g_connection) {
		g_autoptr(GError) error = NULL;
		g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (error) {
			IOT_ERROR("failed to get gdbus connection %s", error->message);
			return -1;
		}
	}

	supplicant_stop_dhcp_server();
	if (supplicant_stop_softap() == -1)
		return -1;

	if (supplicant_configure_interface(&g_iface, 1) == -1) {
		IOT_ERROR("failed to configure network while starting station mode");
		return -1;
	}
	return 0;
}

int supplicant_stop_station(void)
{
	int ret;

	if (g_iface == NULL)
		return 0;

	ret = supplicant_remove_interface(g_iface);
	if (ret) {
		IOT_ERROR("unable to send remove interface method call: %d", ret);
		return -1;
	}

	g_iface = NULL;
	return 0;
}

int supplicant_join_network(char *ssid_key, char *password)
{
	struct wpa_ssid *ssid = (struct wpa_ssid *)malloc(sizeof(struct wpa_ssid));
	snprintf(ssid->ssid, IOT_WIFI_MAX_SSID_LEN, "%s", ssid_key);
	snprintf(ssid->pswd, IOT_WIFI_MAX_PASS_LEN, "%s", password);
	ssid->mode = WPAS_MODE_INFRA;
	ssid->key_mgmt = "WPA-PSK";

	if (supplicant_add_network(g_iface, ssid) == -1) {
		IOT_ERROR("failed to add network while joining AP");
		return -1;
	}

	if (supplicant_select_network(g_iface) == -1) {
		IOT_ERROR("failed to select network while joining AP");
		return -1;
	}

	if (supplicant_enable_network() == -1) {
		IOT_ERROR("failed to enable network while joining AP");
		return -1;
	}
	return 0;
}

int supplicant_leave_network(void)
{
	if (g_iface == NULL || g_network == NULL)
		return 0;

	if (supplicant_remove_network(g_iface) == -1) {
		IOT_ERROR("failed to remove network while leaving network");
		return -1;
	}

	g_network = NULL;
	return 0;
}

int supplicant_start_softap(char *ssid_name, char *pswd)
{
	struct wpa_ssid *ssid = (struct wpa_ssid *)malloc(sizeof(struct wpa_ssid));

	if (!g_connection) {
		g_autoptr(GError) error = NULL;
		g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
		if (error) {
			IOT_ERROR("failed to get gdbus connection %s", error->message);
			return -1;
		}
	}

	supplicant_stop_dhcp_client();
	if (supplicant_leave_network() == -1)
		return -1;

	if (supplicant_configure_interface(&g_softap_iface, 2) == -1) {
		IOT_ERROR("failed to configure network while starting softAP mode");
		return -1;
	}

	snprintf(ssid->ssid, IOT_WIFI_MAX_SSID_LEN, "%s", ssid_name);
	snprintf(ssid->pswd, IOT_WIFI_MAX_PASS_LEN, "%s", pswd);
	ssid->mode = WPAS_MODE_AP;
	ssid->key_mgmt = "WPA-PSK";

	if (supplicant_add_network(g_softap_iface, ssid) == -1) {
		IOT_ERROR("failed to add network in SoftAP mode");
		return -1;
	}

	if (supplicant_select_network(g_softap_iface) == -1) {
		IOT_ERROR("failed to select network in SoftAP mode");
		return -1;
	}

	if (supplicant_enable_network() == -1) {
		IOT_ERROR("failed to enable network in SoftAP mode");
		return -1;
	}
	return 0;
}

int supplicant_stop_softap(void)
{
	int ret;

	if (g_softap_iface == NULL || g_network == NULL)
		return 0;

	ret = supplicant_remove_network(g_softap_iface);
	if (ret) {
		IOT_ERROR("failed to remove network while stopping softAP");
		return -1;
	}

	g_network = NULL;
	return 0;
}

int supplicant_start_dhcp_client(void)
{
	FILE *fp = NULL;
	char buf[DHCLIENT_CONF_LEN] = "";
	char hostname[150];
	char *ctrl_ifname;
	int ret;

	if (supplicant_get_wireless_interface(&ctrl_ifname)) {
		IOT_ERROR("unable to fetch the wireless interface");
		return -1;
	}

	char *const args[] = {"/sbin/dhclient", "-cf", "/etc/dhclient.conf", ctrl_ifname, "-v", NULL};
	char *const envs[] = { NULL };

	if (supplicant_fetch_pid("dhclient") != -1)
		supplicant_stop_dhcp_client();

	if (remove(DHCLIENT_LEASES_FILE) < 0)
		IOT_INFO("failed to remove %s", DHCLIENT_LEASES_FILE);

	fp = fopen(DHCLIENT_CONF_FILE, "w");
	if (!fp) {
		IOT_ERROR("could not create the file\n");
		return -EINVAL;
	}

	gethostname(hostname, 150);
	snprintf(buf, DHCLIENT_CONF_LEN, DHCLIENT_CONF, hostname);
	fputs(buf, fp);
	fclose(fp);

	/* run Dhclient daemon */
	ret = supplicant_execute_command(args[0], &args[0], envs);
	if (ret < 0) {
		IOT_ERROR("failed to start Dhclient %d", ret);
		return -1;
	}
	return 0;
}

void supplicant_stop_dhcp_client(void)
{
	int dhclient_pid;

	dhclient_pid = supplicant_fetch_pid("dhclient");
	if (dhclient_pid == -1) {
		IOT_INFO("dhclient is already stopped");
		return;
        }

	kill(dhclient_pid, SIGTERM);
	waitpid(dhclient_pid, NULL, 0);
	if (remove(DHCLIENT_CONF_FILE) < 0)
		IOT_INFO("Failed to remove %s", DHCLIENT_CONF_FILE);
}

int supplicant_start_dhcp_server(void)
{
	char *ctrl_ifname;
	char *const args_dns[] = {"/usr/sbin/dnsmasq", "-p0", "-F192.168.4.3,192.168.4.10", "-O3,192.168.4.1", NULL};
	char *const envs[] = { NULL };
	int ret;

	if (supplicant_get_wireless_interface(&ctrl_ifname)) {
		IOT_ERROR("unable to fetch the wireless interface");
		return -1;
	}

	/* Assigning IP address to the DHCP server host */
	char *const args_ip_flush[] = {"/sbin/ip", "addr", "flush", "dev", ctrl_ifname, NULL};
	char *const args_ip[] = {"/sbin/ip", "addr", "add", "192.168.4.1/24", "dev", ctrl_ifname, NULL};

	if (supplicant_execute_command(args_ip_flush[0], &args_ip_flush[0], envs) < 0) {
		IOT_ERROR("unable to flush already assigned IP address");
		return -1;
	}

	if (supplicant_execute_command(args_ip[0], &args_ip[0], envs) < 0) {
		IOT_ERROR("unable to assign IP address to the host");
		return -1;
	}

	if (supplicant_fetch_pid("dnsmasq") != -1)
		supplicant_stop_dhcp_server();

	if (remove(DNSMASQ_LEASES_FILE) < 0)
		IOT_ERROR("failed to remove %s", DNSMASQ_LEASES_FILE);

	ret = supplicant_execute_command(args_dns[0], &args_dns[0], envs);
	if (ret < 0) {
		IOT_ERROR("failed to start DHCP server %d", ret);
		return -1;
	}
	return 0;
}

void supplicant_stop_dhcp_server(void)
{
	int dnsmasq_pid;

	dnsmasq_pid = supplicant_fetch_pid("dnsmasq");
	if (dnsmasq_pid == -1) {
		IOT_INFO("dnsmasq is already stopped");
		return;
	}

	kill(dnsmasq_pid, SIGTERM);
	waitpid(dnsmasq_pid, NULL, 0);
}

int supplicant_activate_ntpd(void)
{
	char *const args_ntp_set[] = {"/usr/bin/timedatectl", "set-ntp", "no", NULL};
	char *const args_ntp_restart[] = {"/bin/systemctl", "restart", "ntp", NULL};
	char *const envs[] = { NULL };
	int ret;

	ret = supplicant_execute_command(args_ntp_set[0], &args_ntp_set[0], envs);
	if (ret < 0) {
		IOT_ERROR("unable to set ntp");
		return -1;
	}

	ret = supplicant_execute_command(args_ntp_restart[0], &args_ntp_restart[0], envs);
	if (ret < 0) {
		IOT_ERROR("unable to restart ntp service");
		return -1;
	}
	return 0;
}
