#
# Component configuration file
#

from usr_config import *
import os

def get_path(path_list,path):
    path_list.append(path)
    for root, dirs, files in os.walk(path):
        for d in dirs:
            path_list.append(os.path.join(root,d)+"/")

def include_path(path):
    get_path(include,path)

def include_path_single(path):
    include.append(path)

def print_path(path_list):
    for path in path_list:
        print(path)

include  = ["iot-core", "iot-core/src/", "iot-core/src/port/", "iot-core/src/port/os/", "iot-core/src/port/bsp/", "iot-core/src/port/net/", "iot-core/src/deps/", "iot-core/src/certs/", "iot-core/src/deps/json/"]
exclude  = ["iot-core/src/deps/json/cJSON/test.c","iot-core/src/deps/libsodium/libsodium/test/","iot-core/src/easysetup/http/lwip_httpd/fsdata_custom.c"]
all_path = []

get_path(all_path,'iot-core')

if "CONFIG_STDK_IOT_CORE" not in globals():
    print("MACRO \"CONFIG_STDK_IOT_CORE\" is NOT defined")
    exit()

# Core
include_path("iot-core/src/mqtt/")
include_path("iot-core/src/deps/curl/")
include_path("iot-core/src/deps/mbedtls/")
include_path("iot-core/src/include/")

# JSON
include_path_single("iot-core/src/deps/json/cJSON/")

# libsodiium
include_path("iot-core/src/deps/libsodium/")

# BSP
if "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP8266" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP8266 == 1:
    include_path("iot-core/src/port/bsp/esp8266/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32 == 1:
    include_path("iot-core/src/port/bsp/esp32/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8195" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8195 == 1:
    include_path("iot-core/src/port/bsp/rtl8195/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8720C" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8720C == 1:
    include_path("iot-core/src/port/bsp/rtl8720c/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8721C" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8721C == 1:
    include_path("iot-core/src/port/bsp/rtl8721c/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_MT7682" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_MT7682 == 1:
    include_path("iot-core/src/port/bsp/mt7682/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3166" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3166 == 1:
    include_path("iot-core/src/port/bsp/emw3166/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3080" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3080 == 1:
    include_path("iot-core/src/port/bsp/emw3080/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_CC3220SF" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_CC3220SF == 1:
    include_path("iot-core/src/port/bsp/cc3220sf/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_CY8CPROTO_062_4343W" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_CY8CPROTO_062_4343W == 1:
    include_path("iot-core/src/port/bsp/cy8cproto_062_4343w/")
elif "CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RDA5981C" in vars() and CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RDA5981C == 1:
    include_path("iot-core/src/port/bsp/rda5981c/")
else:
    include_path("iot-core/src/port/bsp/posix/")

# OS
if "CONFIG_STDK_IOT_CORE_OS_SUPPORT_MBEDOS" in vars():
    include_path("iot-core/src/port/os/mbed-os/")

# TLS
if "CONFIG_STDK_IOT_CORE_NET_MBEDTLS" in vars() and CONFIG_STDK_IOT_CORE_NET_MBEDTLS == 1:
    include_path("iot-core/src/port/net/mbedtls/")
else:
    include_path("iot-core/src/port/net/openssl/")

include_path("iot-core/src/deps/cbor/")
include_path_single("iot-core/src/security/")
include_path_single("iot-core/src/security/backend/")
include_path_single("iot-core/src/security/helper/")
include_path_single("iot-core/src/security/helper/libsodium/")

# Security
if "CONFIG_STDK_IOT_CORE_USE_MBEDTLS" in vars() and CONFIG_STDK_IOT_CORE_USE_MBEDTLS == 1:
    include_path("iot-core/src/security/helper/mbedtls/")

if "CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE" in vars() and CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE == 1:
    include_path_single("iot-core/src/security/backend/software/")
    if "CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION" in vars():
        include_path_single("iot-core/src/security/backend/software/lib/")        

elif "CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_HARDWARE" in vars() and CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_HARDWARE == 1:
    include_path("iot-core/src/security/backend/hardware/")

# Easysetup
include_path_single("iot-core/src/easysetup/")
if "CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP" in vars():
    include_path_single("iot-core/src/easysetup/http/")

if "CONFIG_STDK_IOT_CORE_EASYSETUP_POSIX_TESTING" in vars():
    include_path("iot-core/src/easysetup/posix_testing/")

if "CONFIG_STDK_IOT_CORE_EASYSETUP_X509" in vars():
    include_path("iot-core/src/easysetup/http/tls/")
else:
    include_path("iot-core/src/easysetup/http/tcp/")

ignore = [i for i in all_path if i not in include]

ignore = ignore + exclude

# Create .mbedignore file
fd = open('.mbedignore','w')
for i in ignore:
    fd.write(i)
    fd.write("\n")
fd.close()
