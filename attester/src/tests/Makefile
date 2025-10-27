CC ?= cc

BUILD_ROOT := ../../build/tests
OBJDIR := $(BUILD_ROOT)/obj
BINDIR := $(BUILD_ROOT)/bin
TARGET := $(BINDIR)/teep_generate_key_pair_test

SRCS := teep_generate_key_pair_test.c ../teep_generate_key_pair.c
OBJS := $(OBJDIR)/teep_generate_key_pair_test.o $(OBJDIR)/teep_generate_key_pair.o

CFLAGS ?= -Wall -Wextra -g
CPPFLAGS += \
	-I../inc \
	-I../../third_party/QCBOR/inc \
	-I../../third_party/t_cose/inc \
	-I../../third_party/libteep/inc \
	-I../../third_party/libcsuit/inc

LDFLAGS += -L../../build/lib
LDLIBS += -lteep -lcsuit -lt_cose -lqcbor -lm

ifeq ($(MBEDTLS),1)
CPPFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
LDLIBS += -lmbedcrypto
else
LDLIBS += -lcrypto
endif

THIRD_PARTY_STAMP := ../../build/lib/.third_party_built

.PHONY: all run clean third_party

all: $(TARGET)

run: $(TARGET)
	$(TARGET) $(ARGS)

$(TARGET): $(THIRD_PARTY_STAMP) $(OBJS) | $(BINDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/teep_generate_key_pair_test.o: teep_generate_key_pair_test.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(OBJDIR)/teep_generate_key_pair.o: ../teep_generate_key_pair.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $@

$(BINDIR):
	mkdir -p $@

$(THIRD_PARTY_STAMP):
	$(MAKE) -C ../.. third_party

third_party: $(THIRD_PARTY_STAMP)

clean:
	$(RM) -r $(BUILD_ROOT)
