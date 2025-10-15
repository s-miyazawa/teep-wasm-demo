#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

CORIM_CBOR=corim-generic-eat.cbor
.PRECIOUS: $(CORIM_CBOR)

.PHONY: all
all: $(CORIM_CBOR)

# set cddl file
CDDL_FILE=../../cddl/corim.cddl

# load generic rules
include ../../scripts/common.mk

# do not deterministically encode referring to the veraison/services/end-to-end/input/psa-evidence.cbor
psa_token_evidence.gdiag: psa_token_evidence.rediag
	RUBYOPT="-W0" CBOR_DIAG_CDDL=$(CDDL_FILE) diag2diag.rb -e -aref -ae -adt $< > $@

.PHONY: test
test: $(CORIM_CBOR) $(CDDL_FILE)
	@echo $(TEST_COMMAND) $<
	@if $(TEST_COMMAND) $<; then \
		echo "[SUCCESS] Generated CoRIM binary $< matches to the CDDL of CoRIM."; \
	else \
		echo "[FAIL] Generated CoRIM binary $< doesn't match to the CDDL of CoRIM."; exit 1; \
	fi

.PHONY: clean
clean: common-clean
