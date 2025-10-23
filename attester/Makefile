# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

BUILDDIR   := ./build
OBJDIR     := $(BUILDDIR)/obj
BINDIR_BIN := $(BUILDDIR)/bin
LIBDIR     := $(BUILDDIR)/lib
THIRD_PARTY_STAMP := $(LIBDIR)/.third_party_built

CFLAGS = -Wall -g
LDFLAGS = -L$(LIBDIR) -lteep -lcsuit -lt_cose -lqcbor -lcurl -lm
INC = \
	-I./src/inc \
	-I./third_party/QCBOR/inc \
	-I./third_party/t_cose/inc \
	-I./third_party/libteep/inc \
	-I./third_party/libcsuit/inc

TARGET = teep_wasm_get
SRCS = \
	src/teep_http_client_main.c \
	src/teep_examples_common.c \
	src/teep_examples_cose.c \
	src/teep_create_evidence.c \
	src/teep_http_client.c \
	src/suit_examples_common.c \
	src/suit_manifest_process.c

LDWRAP = \
	-Xlinker --wrap=suit_store_callback \
	-Xlinker --wrap=suit_condition_callback

BIN  := $(BINDIR_BIN)/$(TARGET)
OBJS := $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(SRCS)))

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
    LDFLAGS += -lmbedcrypto
else
    # use OpenSSL
    MBEDTLS=0
    LDFLAGS += -lcrypto
endif

ifeq ($(DEBUG),1)
CFLAGS += -g -DDEBUG
endif

.PHONY: all build clean install uninstall run third_party

all: build

build: $(BIN)

$(BIN): $(THIRD_PARTY_STAMP) $(OBJS) | $(BINDIR_BIN)
	$(CC) $(LDWRAP) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: %.c | $(OBJDIR) $(OBJDIR)/src
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

$(OBJDIR):
	mkdir -p $@

$(OBJDIR)/src:
	mkdir -p $@

$(BINDIR_BIN):
	mkdir -p $@

$(LIBDIR):
	mkdir -p $@

third_party: $(THIRD_PARTY_STAMP)

$(THIRD_PARTY_STAMP): | $(LIBDIR)
	@./scripts/build_third_party.sh
	touch $@

run: $(BIN)
	$(BIN) $(ARGS)

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	$(RM) $(OBJS)
	$(RM) $(BIN)
	$(RM) -r $(BUILDDIR)
