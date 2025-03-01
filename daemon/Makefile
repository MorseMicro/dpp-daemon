CC = gcc
CFLAGS  ?= -g -Wall -Werror -I/usr/include/libnl3 -Iinclude -I. -Ibackend/wpa_ctrl/utils -Ibackend/wpa_ctrl -DHOSTAPD -DHOSTAPD_DUMP_STATE -DCONFIG_CTRL_IFACE_UNIX -DCONFIG_CTRL_IFACE -DCONFIG_RSN_PREAUTH  -DCONFIG_DRIVER_HOSTAP  -DCONFIG_DRIVER_NL80211 -DCONFIG_ERP -DEAP_SERVER_MD5 -DEAP_SERVER_TLS -DEAP_SERVER_PEAP -DEAP_SERVER_TTLS -DEAP_SERVER_MSCHAPV2 -DEAP_SERVER_GTC -DEAP_SERVER_IDENTITY -DEAP_SERVER -DPKCS12_FUNCS -DEAP_TLS_FUNCS -DTLS_DEFAULT_CIPHERS=\""DEFAULT:!EXP:!LOW"\" -DCONFIG_DES -DCONFIG_SHA256 -DCONFIG_IPV6 -DNEED_AP_MLME
LIBS ?= -lpthread -lnl-3 -lnl-genl-3 -lm -lmicrohttpd -lssl -lcrypto -lavahi-core -lavahi-common

NAME = dppd

SRC_DIR = .
OUTPUT_DIR = build

OUTPUT = $(OUTPUT_DIR)/$(NAME)

SRCS = $(shell find $(SRC_DIR)/ -name \*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OUTPUT_DIR)/%.o, $(SRCS))

default: $(OUTPUT)

$(OUTPUT): $(OBJS)
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

$(OUTPUT_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJS) $(OUTPUT)
	$(RM) -rf $(OUTPUT_DIR)
