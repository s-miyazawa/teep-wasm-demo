#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

QUERY_REQUEST=query_request
QUERY_REQUEST_CBOR=$(QUERY_REQUEST).cbor
QUERY_REQUEST_COSE=$(QUERY_REQUEST).tam.esp256.cose

QUERY_RESPONSE_PSA=query_response_psa
QUERY_RESPONSE_PSA_CBOR=$(QUERY_RESPONSE_PSA).cbor
QUERY_RESPONSE_PSA_COSE=$(QUERY_RESPONSE_PSA).agent.esp256.cose

QUERY_RESPONSE_EAT=query_response_eat
QUERY_RESPONSE_EAT_CBOR=$(QUERY_RESPONSE_EAT).cbor
QUERY_RESPONSE_EAT_COSE=$(QUERY_RESPONSE_EAT).agent.esp256.cose

UPDATE0=update0
UPDATE0_CBOR=$(UPDATE0).cbor
UPDATE0_COSE=$(UPDATE0).tam.esp256.cose

UPDATE1=update1
UPDATE1_CBOR=$(UPDATE1).cbor
UPDATE1_COSE=$(UPDATE1).tam.esp256.cose

TEEP_SUCCESS=teep_success
TEEP_SUCCESS_CBOR=$(TEEP_SUCCESS).cbor
TEEP_SUCCESS_COSE=$(TEEP_SUCCESS).agent.esp256.cose

TEEP_ERROR=teep_error
TEEP_ERROR_CBOR=$(TEEP_ERROR).cbor
TEEP_ERROR_COSE=$(TEEP_ERROR).agent.esp256.cose

TARGET_CBORS=$(QUERY_REQUEST_CBOR) $(QUERY_RESPONSE_PSA_CBOR) $(QUERY_RESPONSE_EAT_CBOR) $(UPDATE0_CBOR) $(UPDATE1_CBOR) $(TEEP_SUCCESS_CBOR) $(TEEP_ERROR_CBOR)
TARGET_COSES=$(QUERY_REQUEST_COSE) $(QUERY_RESPONSE_PSA_COSE) $(QUERY_RESPONSE_EAT_COSE) $(UPDATE0_COSE) $(UPDATE1_COSE) $(TEEP_SUCCESS_COSE) $(TEEP_ERROR_COSE)

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
../rats/psa/psa_token_evidence.attester.es256.cose:
	$(MAKE) -C ../rats/psa/ psa_token_evidence.attester.es256.cose

psa_token_evidence.attester.es256.cose.bin.hdiag: ../rats/psa/psa_token_evidence.attester.es256.cose

$(QUERY_RESPONSE_PSA_CBOR): psa_token_evidence.attester.es256.cose.bin.hdiag

../rats/eat_evidence/eat_evidence_measurements.attester.es256.cose:
	$(MAKE) -C ../rats/eat_evidence/ eat_evidence_measurements.attester.es256.cose

eat_evidence_measurements.attester.es256.cose.bin.hdiag: ../rats/eat_evidence/eat_evidence_measurements.attester.es256.cose

$(QUERY_RESPONSE_EAT_CBOR): eat_evidence_measurements.attester.es256.cose.bin.hdiag

../manifest/text0/text.0.envelope.cbor:
	$(MAKE) -C ../manifest/text0/ text.0.envelope.cbor

text.0.envelope.cbor.bin.hdiag: ../manifest/text0/text.0.envelope.cbor

$(UPDATE0_CBOR): text.0.envelope.cbor.bin.hdiag

../manifest/text1/text.1.envelope.cbor:
	$(MAKE) -C ../manifest/text1/ text.1.envelope.cbor

text.1.envelope.cbor.bin.hdiag: ../manifest/text1/text.1.envelope.cbor

$(UPDATE1_CBOR): text.1.envelope.cbor.bin.hdiag

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

.PHONY: install
install: test
	@for TARGET in $(TARGET_COSES); do \
		echo cp $$TARGET ../prebuilt/; \
		cp $$TARGET ../prebuilt/; \
	done
