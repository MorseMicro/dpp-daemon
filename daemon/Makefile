#
# Copyright 2023 - 2024 Morse Micro
#

CC = gcc

CFLAGS += -g -Wall -Werror -Iinclude -I.
LIBS += -lpthread -lm -lmicrohttpd -lssl -lcrypto -lavahi-core -lavahi-common -lwpa_client_s1g

NAME = dppd

# ARCH is expected to be passed on the command line. No default is required.

BUILD_DIR = build
TARGET_DIR = $(BUILD_DIR)/$(ARCH)
OUTPUT = $(TARGET_DIR)/$(NAME)

SRC_DIR = .
SRCS = $(shell find $(SRC_DIR)/ -name \*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(TARGET_DIR)/%.o, $(SRCS))

# Build "all" by default
all: $(OUTPUT)

# Build verbosity, quiet by default.
V ?= 0
ECHO = echo

ifeq ($(V),0)
Q = @
QQ = @
else
QQ = @:
endif

# Compile and link
$(OUTPUT): $(OBJS)
	$(QQ) $(ECHO) Linking $@
	$(Q) mkdir -p $(dir $@)
	$(Q) $(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

$(TARGET_DIR)/%.o: $(SRC_DIR)/%.c
	$(QQ) $(ECHO) Compiling $@ ...
	$(Q) mkdir -p $(dir $@)
	$(Q) $(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) -rf $(TARGET_DIR)

distclean:
	$(RM) -rf $(BUILD_DIR)
