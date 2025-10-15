#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

EAT_EVIDENCE_CBOR=eat_evidence.cbor
EAT_EVIDENCE=$(EAT_EVIDENCE_CBOR:.cbor=.attester.es256.cose)
.PRECIOUS: $(EAT_EVIDENCE_CBOR)

.PHONY: all
all: $(EAT_EVIDENCE)

# set cddl file
CDDL_FILE=../../cddl/eat-payload.cddl

# load generic rules
include ../../scripts/common.mk

.PHONY: test
test: $(EAT_EVIDENCE_CBOR) $(CDDL_FILE)
	@echo $(TEST_COMMAND) $<
	@if $(TEST_COMMAND) $<; then \
		echo "[SUCCESS] Generated EAT Evidence binary $< matches to the CDDL of EAT Evidence."; \
	else \
		echo "[FAIL] Generated EAT Evidence binary $< doesn't match to the CDDL of EAT Evidence."; exit 1; \
	fi

.PHONY: clean
clean: common-clean
