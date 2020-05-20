#
# Component Makefile
#

ifdef CONFIG_STDK_IOT_CORE

COMPONENT_ADD_INCLUDEDIRS += include include/bsp include/os include/mqtt include/external

COMPONENT_SRCDIRS += ./

ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP8266),y)
	COMPONENT_SRCDIRS += port/bsp/esp8266
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp8266
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_ESP32),y)
	COMPONENT_SRCDIRS += port/bsp/esp32
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/esp32
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8195),y)
	COMPONENT_SRCDIRS += port/bsp/rtl8195
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8195
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8720C),y)
        COMPONENT_SRCDIRS += port/bsp/rtl8720c
        COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8720c
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RTL8721C),y)
	COMPONENT_SRCDIRS += port/bsp/rtl8721c
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/rtl8721c
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_MT7682),y)
	COMPONENT_SRCDIRS += port/bsp/mt7682
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/mt7682
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3166),y)
	COMPONENT_SRCDIRS += port/bsp/emw3166
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/emw3166
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_EMW3080),y)
	COMPONENT_SRCDIRS += port/bsp/emw3080
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/emw3080
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_TIZENRT),y)
	COMPONENT_SRCDIRS += port/bsp/tizenrt
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/tizenrt
else ifeq ($(CONFIG_STDK_IOT_CORE_BSP_SUPPORT_CC3220SF),y)
	COMPONENT_SRCDIRS += port/bsp/cc3220sf
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/cc3220sf
else
	COMPONENT_SRCDIRS += port/bsp/posix
	COMPONENT_ADD_INCLUDEDIRS += include/bsp/posix
endif

ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_FREERTOS),y)
	COMPONENT_SRCDIRS += port/os/freertos
else ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_TIZENRT),y)
	COMPONENT_SRCDIRS += port/os/tizenrt
else ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX),y)
	COMPONENT_SRCDIRS += port/os/posix
else ifeq ($(CONFIG_STDK_IOT_CORE_OS_SUPPORT_MOCOS),y)
	COMPONENT_SRCDIRS += port/os/mocos
endif

ifeq ($(CONFIG_STDK_IOT_CORE_NET_MBEDTLS),y)
	COMPONENT_SRCDIRS += port/net/mbedtls
	COMPONENT_ADD_INCLUDEDIRS += port/net/mbedtls
else
	COMPONENT_SRCDIRS += port/net/openssl
	COMPONENT_ADD_INCLUDEDIRS += port/net/openssl
endif

COMPONENT_SRCDIRS += deps/cbor/tinycbor/src
COMPONENT_ADD_INCLUDEDIRS += deps/cbor/tinycbor/src

COMPONENT_SRCDIRS += crypto
ifdef CONFIG_STDK_IOT_CORE_USE_MBEDTLS
COMPONENT_SRCDIRS += crypto/mbedtls
endif
ifdef CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION
COMPONENT_ADD_LDFLAGS += $(COMPONENT_PATH)/crypto/ss/lib/libiot_crypto_ss.a
COMPONENT_ADD_LINKER_DEPS := $(COMPONENT_PATH)/crypto/ss/lib/libiot_crypto_ss.a
else
COMPONENT_SRCDIRS += crypto/ss
endif

ifeq ($(CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE),y)
COMPONENT_SRCDIRS += security
COMPONENT_SRCDIRS += security/backend/software
endif

COMPONENT_SRCDIRS += easysetup

ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_HTTP
COMPONENT_SRCDIRS += easysetup/http
endif
ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_POSIX_TESTING
COMPONENT_SRCDIRS += easysetup/posix_testing
endif

ifdef CONFIG_STDK_IOT_CORE_EASYSETUP_X509
COMPONENT_OBJEXCLUDE := easysetup/http/iot_easysetup_http_tcp.o
else
COMPONENT_OBJEXCLUDE := easysetup/http/iot_easysetup_http_tls.o
endif

CPPFLAGS += -include $(COMPONENT_PATH)/include/iot_common.h

COMPONENT_SRCDIRS += mqtt/client mqtt/packet mqtt/client/freertos

BILERPLATE_HEADER=$(COMPONENT_PATH)/include/certs/boilerplate.h
ROOT_CA_FILE_LIST=$(wildcard $(COMPONENT_PATH)/certs/root_ca_*.pem)
ROOT_CA_FILE=$(COMPONENT_PATH)/certs/root_ca.pem
ROOT_CA_SOURCE=$(COMPONENT_PATH)/iot_root_ca.c
ROOT_CA_BACKUP_FILE=$(ROOT_CA_SOURCE).bak
$(shell rm $(ROOT_CA_FILE) 2> /dev/null)
$(foreach file,$(ROOT_CA_FILE_LIST),$(shell cat $(file) >> $(ROOT_CA_FILE)))
result := $(shell cat $(BILERPLATE_HEADER) > $(ROOT_CA_SOURCE); echo $$?;)
ifneq ($(result),0)
	$(error)
endif
result := $(shell xxd -i $(ROOT_CA_FILE) >> $(ROOT_CA_SOURCE); echo $$?;)
ifneq ($(result),0)
	$(error)
endif
$(shell sed -i.bak 's/_.*pem/st_root_ca/g' $(ROOT_CA_SOURCE))
$(shell sed -i.bak 's/unsigned/const unsigned/g' $(ROOT_CA_SOURCE))
$(shell rm $(ROOT_CA_BACKUP_FILE))
$(shell rm $(ROOT_CA_FILE))

CFLAGS += -std=c99

else
# Disable SmartThing Device SDK support
COMPONENT_ADD_INCLUDEDIRS :=
COMPONENT_SRCDIRS :=
endif
