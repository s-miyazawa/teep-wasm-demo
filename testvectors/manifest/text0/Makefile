#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

TARGET=text.0.envelope.cbor
TEXT=hello.txt
.PHONY: all
all: $(TARGET)

# set cddl file
CDDL_FILE=../../cddl/suit-manifest.cddl

# load generic rules
include ../../scripts/common.mk

# list dependencies as prerequisites here
#
# NOTE: %.hdiag files and %.size.gdiag files are special: order sensitive
#       You need to start from the direct source
#       because the common.mk cannot automatically detect the
#       first input ($<) file to be used in the recipies

# generate SUIT_Envelope_Tagged cbor binary
text.0.envelope.cbor: \
	text.0.envelope.rediag \
	text.0.manifest.rediag \
	text.0.manifest.digest.rediag

# generate SUIT_Envelope_Tagged
text.0.envelope.gdiag: \
	text.0.envelope.rediag \
	text.0.manifest.digest.gdiag \
	text.0.manifest.digest.tc-signer.esp256.cose.gdiag \
	text.0.manifest.gdiag \
	text.0.bin.hdiag

# generate SUIT_Manifest
text.0.manifest.gdiag: \
	text.0.manifest.rediag \
	text.0.digest.hdiag \
	text.0.size.gdiag

# generate SUIT_Digest of SUIT_Manifest
text.0.manifest.digest.gdiag: text.0.manifest.digest.hdiag
text.0.manifest.digest.hdiag: text.0.manifest.cbor

# generate hex file for integrated payload
text.0.bin.hdiag: $(TEXT)

# generate parameters for the app.wasm world app
text.0.size.gdiag: $(TEXT)
text.0.digest.hdiag: $(TEXT)


.PHONY: test
test: all $(SUIT_MANIFEST_CDDL)
	@echo ${TEST_COMMAND} ${TARGET}
	@if ${TEST_COMMAND} ${TARGET}; then \
		echo "[SUCCESS] Generated SUIT Manifest binary 'text.envelope.cbor' matches to the CDDL of SUIT Manifest."; \
	else \
		echo "[FAIL] Generated SUIT Manifest binary 'text.envelope.cbor' doesn't match to the CDDL of SUIT Manifest."; exit 1; \
	fi

.PHONY: install
install: test
	cp ${TARGET} ../../prebuilt/

.PHONY: clean
clean: common-clean

