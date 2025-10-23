#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

PSA_TOKEN_EVIDENCE_CBOR=psa_token_evidence.cbor
PSA_TOKEN_EVIDENCE=$(PSA_TOKEN_EVIDENCE_CBOR:.cbor=.attester.es256.cose)
.PRECIOUS: $(PSA_TOKEN_EVIDENCE_CBOR)

.PHONY: all
all: $(PSA_TOKEN_EVIDENCE)

# set cddl file
CDDL_FILE=../../cddl/psa-token.cddl

# load generic rules
include ../../scripts/common.mk

# do not deterministically encode referring to the veraison/services/end-to-end/input/psa-evidence.cbor
psa_token_evidence.gdiag: psa_token_evidence.rediag
	RUBYOPT="-W0" CBOR_DIAG_CDDL=$(CDDL_FILE) diag2diag.rb -e -aref -ae -adt $< > $@

.PHONY: test
test: $(PSA_TOKEN_EVIDENCE_CBOR) $(CDDL_FILE)
	@echo $(TEST_COMMAND) $<
	@if $(TEST_COMMAND) $<; then \
		echo "[SUCCESS] Generated PSA Token binary $< matches to the CDDL of PSA Token."; \
	else \
		echo "[FAIL] Generated PSA Token binary $< doesn't match to the CDDL of PSA Token."; exit 1; \
	fi

.PHONY: clean
clean: common-clean
