#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

CFLAGS = $(CMD_C) -Wall
LDFLAGS = $(CMD_LD) ../libcsuit/libcsuit.a ../t_cose/libt_cose.a ../QCBOR/libqcbor.a -lm
LDWRAP = \
	-Xlinker --wrap=suit_fetch_callback \
	-Xlinker --wrap=suit_store_callback \
	-Xlinker --wrap=suit_invoke_callback \
	-Xlinker --wrap=suit_condition_callback

INC = $(CMD_INC) -I./inc -I./examples/inc -I../libcsuit/inc -I../t_cose/inc -I../QCBOR/inc
TARGET = ./suit_manifest_process
SRCS = \
	suit_examples_common.c \
	suit_manifest_process_main.c
OBJS = $(patsubst %.c,%.o,$(SRCS))

WORKDIR := ./tmp

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBCSUIT_PSA_CRYPTO_C=1
    LDFLAGS += -lmbedcrypto
else
    # use OpenSSL
    LDFLAGS += -lcrypto
endif

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDWRAP) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INC) $(CMD_LINE) -o $@ -c $<

.PHONY: test
test: $(TARGET) $(MANIFEST)
	$(TARGET) $(MANIFEST)

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TARGET)

