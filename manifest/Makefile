#
# Copyright (c) 2024 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

TARGET=app.wasm.envelope.cbor
APP_WASM=hello-wasi/target/wasm32-wasip1/release/hello-wasi.wasm
.PHONY: all
all: $(TARGET)

# load generic rules
include ../scripts/common.mk

# list dependencies as prerequisites here
#
# NOTE: %.hdiag files and %.size.gdiag files are special: order sensitive
#       You need to start from the direct source
#       because the common.mk cannot automatically detect the
#       first input ($<) file to be used in the recipies

# generate SUIT_Envelope_Tagged cbor binary
app.wasm.envelope.cbor: \
	app.wasm.envelope.rediag \
	app.wasm.manifest.rediag \
	app.wasm.manifest.digest.rediag \
	hello-wasi/src/main.rs

# generate SUIT_Envelope_Tagged
app.wasm.envelope.gdiag: \
	app.wasm.envelope.rediag \
	app.wasm.manifest.digest.gdiag \
	app.wasm.manifest.digest.esp256.cose.gdiag \
	app.wasm.manifest.gdiag \
	app.wasm.bin.hdiag

# generate SUIT_Manifest
app.wasm.manifest.gdiag: \
	app.wasm.manifest.rediag \
	app.wasm.digest.hdiag \
	app.wasm.size.gdiag

# generate SUIT_Digest of SUIT_Manifest
app.wasm.manifest.digest.gdiag: app.wasm.manifest.digest.hdiag
app.wasm.manifest.digest.hdiag: app.wasm.manifest.cbor

# generate hex file for integrated payload
app.wasm.bin.hdiag: $(APP_WASM)

# generate parameters for the app.wasm world app
app.wasm.size.gdiag: $(APP_WASM)
app.wasm.digest.hdiag: $(APP_WASM)

# compile the app.wasm world app
$(APP_WASM): hello-wasi/src/main.rs
	cd hello-wasi && cargo build --target wasm32-wasip1 --release


.PHONY: test
test: all $(SUIT_MANIFEST_CDDL)
	@echo ${TEST_COMMAND} ${TARGET}
	@if ${TEST_COMMAND} ${TARGET}; then \
		echo "[SUCCESS] Generated SUIT Manifest binary 'app.wasm.envelope.cbor' matches to the CDDL of SUIT Manifest."; \
	else \
		echo "[FAIL] Generated SUIT Manifest binary 'app.wasm.envelope.cbor' doesn't match to the CDDL of SUIT Manifest."; exit 1; \
	fi

.PHONY: clean
clean: common-clean
	cd hello-wasi && cargo clean

