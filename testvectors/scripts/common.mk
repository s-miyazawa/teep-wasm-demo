#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

# define generic rules

ifeq ($(CDDL_FILE),)
    $(error The variable `CDDL_FILE` is not set. Please define it before including this file.)
endif

SCRIPTS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

RUBYDEBUG=RUBYOPT="-W0"
DIAG2CBOR=$(RUBYDEBUG) diag2cbor.rb
# embedded + deterministic + edn-ref + edn-e + edn-dt
DIAG2DIAG=$(RUBYDEBUG) CBOR_DIAG_CDDL=$(CDDL_FILE) diag2diag.rb -e -d -aref -ae -adt
# embedded + deterministic
CBOR2DIAG=$(RUBYDEBUG) cbor2diag.rb -e -d
TEST_COMMAND=$(RUBYDEBUG) cddl $(CDDL_FILE) validate

TC_SIGNER_ESP256_SIGN_KEY=${SCRIPTS_DIR}/tc-signer-esp256-priv.jwk
TAM_ESP256_SIGN_KEY=${SCRIPTS_DIR}/tam-esp256-priv.jwk
AGENT_ESP256_SIGN_KEY=${SCRIPTS_DIR}/agent-esp256-priv.jwk
ATTESTER_ES256_SIGN_KEY=${SCRIPTS_DIR}/attester-es256-priv.jwk

# generate the cddl file
.PHONY: cddl
cddl: $(CDDL_FILE)
$(CDDL_FILE):
	$(MAKE) -C ../cddl $(CDDL_FILE)


# generate cbor file from generated diag file
%.cbor: %.gdiag
	$(DIAG2CBOR) < $< > $@

# generate diag file from COSE file
%.cose.gdiag: %.cose
	$(CBOR2DIAG) < $< > $@

# generate diag file from EDN+ref+e file
%.gdiag: %.rediag
	$(DIAG2DIAG) < $< > $@

# store file size as an integer
%.size.gdiag:
	stat --format=%s $< > $@

# store sha256 hash as a byte string
%.digest.hdiag:
	sha256sum $< | awk '{printf "h'\''%s'\''",$$1}' > $@

# generate COSE_Sign1 binary
%.tc-signer.esp256.cose: %.cbor
	python3 ${SCRIPTS_DIR}/cwt-mac-or-sign.py $< ${TC_SIGNER_ESP256_SIGN_KEY} $@ --detached

%.tam.esp256.cose: %.cbor
	python3 ${SCRIPTS_DIR}/cwt-mac-or-sign.py $< ${TAM_ESP256_SIGN_KEY} $@ --no-detached

%.agent.esp256.cose: %.cbor 
	python3 ${SCRIPTS_DIR}/cwt-mac-or-sign.py $< ${AGENT_ESP256_SIGN_KEY} $@ --no-detached

%.attester.es256.cose: %.cbor
	python3 ${SCRIPTS_DIR}/cwt-mac-or-sign.py $< ${ATTESTER_ES256_SIGN_KEY} $@ --no-detached

# generate byte string diag from a binary
%.bin.hdiag:
	python3 ${SCRIPTS_DIR}/bin2hdiag.py $< > $@

.PHONY: common-clean
common-clean:
	$(RM) *.gdiag *.hdiag *.cbor *.cose
