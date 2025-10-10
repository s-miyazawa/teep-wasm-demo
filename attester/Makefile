#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#


CFLAGS = -Wall -g
LDFLAGS = $(CMD_LD) -lcsuit -lt_cose -lqcbor -lcurl -lm -lteep
INC = $(CMD_INC) -I ./src/inc -I/usr/local/include
TARGET = /usr/bin/teep_wasm_get
SRCS = \
	src/teep_http_client_main.c \
	src/teep_examples_common.c \
	src/teep_examples_cose.c \
	src/teep_create_evidence.c \
	src/teep_http_client.c \
	src/suit_examples_common.c \
	src/suit_manifest_process.c \
	

LDWRAP = \
	-Xlinker --wrap=suit_store_callback \
	-Xlinker --wrap=suit_condition_callback

OBJDIR = ./obj
OBJS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(SRCS)))

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
    LDFLAGS +=-lmbedcrypto
else
    # use OpenSSL
    MBEDTLS=0
    LDFLAGS += -lcrypto
endif

ifdef debug
    CFLAGS += -DALLOW_CBOR_WITHOUT_SIGN1 -DSEND_CBOR_WITHOUT_SIGN1
endif

.PHONY: all debug clean

all: $(TARGET)

include third_party/libteep/Makefile.common

$(TARGET): $(OBJS)
	$(CC) $(LDWRAP) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: %.c | $(OBJDIR) $(OBJDIR)/src
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

.PHONY: run
run: $(TARGET)
	$(TARGET)

clean:
	$(RM) $(OBJS) $(TARGET)
