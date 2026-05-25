#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

TEEP_SGX_QUOTE3_BUNDLE := sgx-quote3-teep-bundle

.PHONY: all
all: $(TEEP_SGX_QUOTE3_BUNDLE).cbor

# set cddl file
CDDL_FILE=./sgx-quote3-teep-bundle.cddl

# load generic rules
include ../../scripts/common.mk

quote.dat.bin.hdiag: quote.dat

$(TEEP_SGX_QUOTE3_BUNDLE).gdiag: quote.dat.bin.hdiag

.PHONY: test
test: $(TEEP_SGX_QUOTE3_BUNDLE).cbor $(CDDL_FILE)
	echo $(TEST_COMMAND) $$EAT_CBOR
	if $(TEST_COMMAND) $$EAT_CBOR; then
		echo "[SUCCESS] Generated EAT Evidence binary $$EAT_CBOR matches to the CDDL of EAT Evidence.";
	else
		echo "[FAIL] Generated EAT Evidence binary $$EAT_CBOR doesn't match to the CDDL of EAT Evidence."; exit 1;
	fi

.PHONY: clean
clean: common-clean

