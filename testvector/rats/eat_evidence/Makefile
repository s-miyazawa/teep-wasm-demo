#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

EAT_EVIDENCE_CBORS := eat_evidence.cbor
EAT_EVIDENCE_CBORS += eat_evidence_measurements.cbor

EAT_EVIDENCE=$(EAT_EVIDENCE_CBORS:.cbor=.attester.es256.cose)
.PRECIOUS: $(EAT_EVIDENCE_CBORS)

.PHONY: all
all: $(EAT_EVIDENCE)

# set cddl file
CDDL_FILE=../../cddl/eat-payload.cddl

# load generic rules
include ../../scripts/common.mk

.PHONY: test
test: $(EAT_EVIDENCE_CBORS) $(CDDL_FILE)
	@for EAT_CBOR in $(EAT_EVIDENCE_CBORS); do \
		echo $(TEST_COMMAND) $$EAT_CBOR; \
		if $(TEST_COMMAND) $$EAT_CBOR; then \
			echo "[SUCCESS] Generated EAT Evidence binary $$EAT_CBOR matches to the CDDL of EAT Evidence."; \
		else \
			echo "[FAIL] Generated EAT Evidence binary $$EAT_CBOR doesn't match to the CDDL of EAT Evidence."; exit 1; \
		fi; \
	done

.PHONY: clean
clean: common-clean
