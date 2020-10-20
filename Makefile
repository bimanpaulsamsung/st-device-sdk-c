TOPDIR	:= $(CURDIR)

include $(TOPDIR)/make/common.mk

ifneq ($(findstring CONFIG_STDK_IOT_CORE_BSP_SUPPORT_UBUNTU, $(CFLAGS_CONFIG)),)
BSP_DIR = src/port/bsp/ubuntu
else ifneq ($(findstring CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RASPI_OS, $(CFLAGS_CONFIG)),)
BSP_DIR = src/port/bsp/raspi_os
else
include stdkconfig
BSP_DIR = src/port/bsp/posix
endif
OS_DIR = src/port/os/posix
ifneq ($(findstring CONFIG_STDK_IOT_CORE_NET_MBEDTLS, $(CFLAGS_CONFIG)),)
NET_DIR = src/port/net/mbedtls
else
NET_DIR = src/port/net/openssl
endif
CRYPTO_DIR = src/crypto
SECURITY_DIR = src/security
EASYSETUP_DIR = src/easysetup
MQTT_DIR = src/mqtt
BUILD_DIR = $(TOPDIR)/build
OUTPUT_DIR = $(TOPDIR)/output
CBOR_DIR = src/deps/cbor/tinycbor/src

CFLAGS	:= -std=c99 -D_GNU_SOURCE
CFLAGS	+= $(CFLAGS_CONFIG)
ifneq ($(findstring CONFIG_STDK_IOT_CORE_BSP_SUPPORT_UBUNTU, $(CFLAGS_CONFIG)),)
CFLAGS	+= $(shell pkg-config --cflags gio-2.0 glib-2.0)
endif

ifneq ($(findstring CONFIG_STDK_IOT_CORE_BSP_SUPPORT_RASPI_OS, $(CFLAGS_CONFIG)),)
CFLAGS	+= $(shell pkg-config --cflags gio-2.0 glib-2.0)
endif

INCS	:= -I/usr/include -Isrc/include -Isrc/include/mqtt -Isrc/include/os -Isrc/include/bsp -Isrc/include/external -I$(NET_DIR)
INCS	+= -Isrc/include/security
INCS	+= -I$(CBOR_DIR)

SRCS	:= $(wildcard src/*.c)
SRCS	+= $(wildcard $(CBOR_DIR)/*.c)
SRCS	+= $(wildcard $(BSP_DIR)/*.c)
SRCS	+= $(wildcard $(OS_DIR)/*.c)
SRCS	+= $(wildcard $(NET_DIR)/*.c)
SRCS	+= $(wildcard $(CRYPTO_DIR)/*.c)
ifneq ($(findstring, CONFIG_STDK_IOT_CORE_EASYSETUP_POSIX_TESTING, $(CFLAGS_CONFIG)),)
SRCS	+= $(EASYSETUP_DIR)/iot_easysetup_st_mqtt.c \
			$(wildcard $(EASYSETUP_DIR)/posix_testing/*.c)
else
SRCS	+= $(EASYSETUP_DIR)/iot_easysetup_st_mqtt.c \
			$(wildcard $(EASYSETUP_DIR)/http/*.c) \
			$(wildcard $(EASYSETUP_DIR)/http/tcp/*.c)
endif
SRCS	+= $(wildcard $(MQTT_DIR)/client/*.c)
SRCS	+= $(wildcard $(MQTT_DIR)/packet/*.c)
SRCS	+= $(wildcard $(SECURITY_DIR)/*.c)
ifneq ($(findstring, "CONFIG_STDK_IOT_CORE_SECURITY_BACKEND_SOFTWARE", $(CFLAGS_CONFIG)), '')
SRCS	+= $(wildcard $(SECURITY_DIR)/backend/software/*.c)
endif
SRCS	+= $(wildcard $(SECURITY_DIR)/helper/libsodium/*.c)
ifneq ($(findstring, "CONFIG_STDK_IOT_CORE_USE_MBEDTLS", $(CFLAGS_CONFIG)), '')
SRCS	+= $(wildcard $(SECURITY_DIR)/helper/mbedtls/*.c)
endif

OBJS	= $(SRCS:%.c=%.o)
TARGET	= libiotcore.a

export TOPDIR
export CFLAGS
export LOCAL_CFLAGS
export BUILD_DIR
export PREFIX

JSON_DIR = src/deps/json
LIBSODIUM_DIR = src/deps/libsodium
MBEDTLS_DIR = src/deps/mbedtls

DEPS_DIRS = $(JSON_DIR) $(LIBSODIUM_DIR) $(MBEDTLS_DIR)

result	:= $(shell git submodule update --init $(JSON_DIR))
result	:= $(shell git submodule update --init $(LIBSODIUM_DIR))
result	:= $(shell git submodule update --init $(MBEDTLS_DIR))

INCS	+= -I$(JSON_DIR)/cJSON
INCS	+= -I$(MBEDTLS_DIR)/mbedtls/include
INCS	+= -I$(LIBSODIUM_DIR)/libsodium/src/libsodium/include -I$(LIBSODIUM_DIR)/libsodium/src/libsodium/include/sodium -I$(LIBSODIUM_DIR)/port/include

LOCAL_CFLAGS := $(INCS)
PREFIX := stdk_

BILERPLATE_HEADER = src/include/certs/boilerplate.h
ROOT_CA_FILE_LIST = $(wildcard src/certs/root_ca_*.pem)
ROOT_CA_FILE = src/certs/root_ca.pem
ROOT_CA_SOURCE = src/iot_root_ca.c
SRCS	+= $(ROOT_CA_SOURCE)

.PHONY: all clean
all: prepare subdir $(TARGET)

prepare:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(OUTPUT_DIR)

subdir:
	@for dir in $(DEPS_DIRS); do \
		$(MAKE) -C $$dir; \
		if [ $$? != 0 ]; then \
			exit 1; \
		fi; \
	done

$(ROOT_CA_SOURCE):
	@if [ -e $(ROOT_CA_FILE) ]; then \
		rm $(ROOT_CA_FILE); \
	fi
	@cat $(ROOT_CA_FILE_LIST) >> $(ROOT_CA_FILE)
	@if [ $$? != 0 ]; then \
		exit 1; \
	fi
	@cat $(BILERPLATE_HEADER) > $(ROOT_CA_SOURCE)
	@if [ $$? != 0 ]; then \
		exit 1; \
	fi
	@xxd -i $(ROOT_CA_FILE) >> $(ROOT_CA_SOURCE)
	@if [ $$? != 0 ]; then \
		exit 1; \
	fi
	@sed -i.bak 's/src.*pem/st_root_ca/g' $(ROOT_CA_SOURCE)
	@sed -i.bak 's/unsigned/const unsigned/g' $(ROOT_CA_SOURCE)
	@rm -f $(ROOT_CA_SOURCE).bak
	@rm -f $(ROOT_CA_FILE)

clean:
	@for dir in $(DEPS_DIRS); do \
		$(MAKE) -C $$dir clean; \
	done
	@rm -f $(ROOT_CA_SOURCE)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(OUTPUT_DIR)

$(TARGET): $(OBJS) $(ROOT_CA_SOURCE)
	@echo "  AR    $(BUILD_DIR)/$@"
	@$(AR) -rcs $(BUILD_DIR)/$@ $(BUILD_DIR)/*.o
	@$(MV) -f $(BUILD_DIR)/$(TARGET) $(OUTPUT_DIR)
	@echo "================================"
	@echo "=             DONE             ="
	@echo "================================"
