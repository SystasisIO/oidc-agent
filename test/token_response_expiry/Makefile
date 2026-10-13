# Focused Linux/ELF Check suite; no agent process, credentials or issuer needed.
ROOT ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
BUILD_DIR ?= $(ROOT)/test/bin/token_response_expiry
PKG_CONFIG ?= pkg-config

CPPFLAGS += -I$(ROOT)/src -I$(ROOT)/lib -DVERSION=\"5.3.8-systasis.1\"
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags check libcurl libmicrohttpd)
CFLAGS += -g -O0 -std=c99 -Wall -Wextra -ffunction-sections -fdata-sections
CFLAGS += $(SANITIZE)
LDFLAGS += -Wl,--gc-sections -Wl,--wrap=time -Wl,--wrap=_secFree
LDFLAGS += -Wl,--wrap=ipc_vwrite -Wl,--wrap=ipc_communicateThroughPipe
LDFLAGS += $(SANITIZE)
LDLIBS += $(shell $(PKG_CONFIG) --libs check libcurl) -lm

SOURCES = test/token_response_expiry/test.c \
          src/oidc-agent/oidc/flows/oidc.c \
          src/oidc-agent/oidc/flows/refresh.c \
          src/oidc-agent/oidc/flows/access_token_handler.c \
          src/oidc-agent/oidcd/oidcd_handler.c \
          src/account/setandget.c src/account/issuer.c \
          src/ipc/pipe.c src/ipc/ipc.c \
          src/utils/json.c src/utils/listUtils.c src/utils/memory.c src/utils/oidc_error.c \
          src/utils/errorUtils.c src/utils/string/stringUtils.c \
          src/utils/oidc/oidcUtils.c \
          lib/cJSON/cJSON.c lib/list/list.c \
          lib/list/list_iterator.c lib/list/list_node.c
OBJECTS = $(addprefix $(BUILD_DIR)/,$(SOURCES:.c=.o))
HEADERS = $(shell find $(ROOT)/src $(ROOT)/lib -name '*.h')
TARGET = $(BUILD_DIR)/token_response_expiry_tests

.PHONY: test
test: $(TARGET)
	$(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: $(ROOT)/%.c $(HEADERS)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
