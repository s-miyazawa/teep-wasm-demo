#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

CORIM_CBORS := corim-generic-eat.cbor
CORIM_CBORS += corim-generic-eat-measurements.cbor
.PRECIOUS: $(CORIM_CBORS)

.PHONY: all
all: $(CORIM_CBORS)

# set cddl file
CDDL_FILE=../../cddl/corim.cddl

# load generic rules
include ../../scripts/common.mk

# do not deterministically encode referring to the veraison/services/end-to-end/input/psa-evidence.cbor
psa_token_evidence.gdiag: psa_token_evidence.rediag
	RUBYOPT="-W0" CBOR_DIAG_CDDL=$(CDDL_FILE) diag2diag.rb -e -aref -ae -adt $< > $@

.PHONY: test
test: $(CORIM_CBORS) $(CDDL_FILE)
	@for CORIM_CBOR in $(CORIM_CBORS); do \
		echo $(TEST_COMMAND) $$CORIM_CBOR; \
		if $(TEST_COMMAND) $$CORIM_CBOR; then \
			echo "[SUCCESS] Generated CoRIM binary $$CORIM_CBOR matches to the CDDL of CoRIM."; \
		else \
			echo "[FAIL] Generated CoRIM binary $$CORIM_CBOR doesn't match to the CDDL of CoRIM."; exit 1; \
		fi; \
	done

.PHONY: clean
clean: common-clean
