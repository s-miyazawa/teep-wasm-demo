#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

TARGET=text.1.envelope.cbor
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
text.1.envelope.cbor: \
	text.1.envelope.rediag \
	text.1.manifest.rediag \
	text.1.manifest.digest.rediag

# generate SUIT_Envelope_Tagged
text.1.envelope.gdiag: \
	text.1.envelope.rediag \
	text.1.manifest.digest.gdiag \
	text.1.manifest.digest.tc-signer.esp256.cose.gdiag \
	text.1.manifest.gdiag \
	text.1.bin.hdiag

# generate SUIT_Manifest
text.1.manifest.gdiag: \
	text.1.manifest.rediag \
	text.1.digest.hdiag \
	text.1.size.gdiag

# generate SUIT_Digest of SUIT_Manifest
text.1.manifest.digest.gdiag: text.1.manifest.digest.hdiag
text.1.manifest.digest.hdiag: text.1.manifest.cbor

# generate hex file for integrated payload
text.1.bin.hdiag: $(TEXT)

# generate parameters for the app.wasm world app
text.1.size.gdiag: $(TEXT)
text.1.digest.hdiag: $(TEXT)


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

