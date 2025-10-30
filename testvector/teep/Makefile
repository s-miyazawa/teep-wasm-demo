#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

QUERY_REQUEST=query_request
QUERY_REQUEST_CBOR=$(QUERY_REQUEST).cbor
QUERY_REQUEST_COSE=$(QUERY_REQUEST).tam.esp256.cose
QUERY_RESPONSE=query_response
QUERY_RESPONSE_CBOR=$(QUERY_RESPONSE).cbor
QUERY_RESPONSE_COSE=$(QUERY_RESPONSE).agent.esp256.cose
UPDATE=update
UPDATE_CBOR=$(UPDATE).cbor
UPDATE_COSE=$(UPDATE).tam.esp256.cose

TARGET_CBORS=$(QUERY_REQUEST_CBOR) $(QUERY_RESPONSE_CBOR) $(UPDATE_CBOR)
TARGET_COSES=$(QUERY_REQUEST_COSE) $(QUERY_RESPONSE_COSE) $(UPDATE_COSE)

.PRECIOUS: $(TARGET_CBORS)

.PHONY: all
all: $(TARGET_COSES)

# set cddl file
CDDL_FILE=../cddl/teep-protocol.cddl

# load generic rules
include ../scripts/common.mk

# list dependencies as prerequisites here
#
# NOTE: %.hdiag files and %.size.gdiag files are special: order sensitive
#       You need to start from the direct source
#       because the common.mk cannot automatically detect the
#       first input ($<) file to be used in the recipies

# set dependency
../rats/psa_token_evidence.attester.es256.cose:
	$(MAKE) -C ../rats/ psa_token_evidence.attester.es256.cose

psa_token_evidence.attester.es256.cose.bin.hdiag: ../rats/psa_token_evidence.attester.es256.cose

$(QUERY_RESPONSE_CBOR): psa_token_evidence.attester.es256.cose.bin.hdiag

../manifest/app.wasm.envelope.cbor:
	$(MAKE) -C ../manifest/ app.wasm.envelope.cbor

app.wasm.envelope.cbor.bin.hdiag: ../manifest/app.wasm.envelope.cbor

$(UPDATE_CBOR): app.wasm.envelope.cbor.bin.hdiag

.PHONY: test
test: $(TARGET_CBORS) $(CDDL_FILE)
	@for TARGET in $(TARGET_CBORS); do \
		echo $(TEST_COMMAND) $$TARGET; \
		if $(TEST_COMMAND) $$TARGET; then \
			echo "[SUCCESS] Generated TEEP Protocol message binary $$TARGET matches to the CDDL of TEEP Protocol messages."; \
		else \
			echo "[FAIL] Generated TEEP Protocol message binary $$TARGET doesn't match to the CDDL of TEEP Protocol messages."; exit 1; \
		fi; \
	done

.PHONY: clean
clean: common-clean
