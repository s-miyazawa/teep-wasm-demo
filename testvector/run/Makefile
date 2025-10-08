SUIT_MANIFEST_PROCESSOR = ../process/suit_manifest_process
MANIFEST = ../manifest/app.wasm.envelope.cbor
STORED_MANIFEST = manifest.app.wasm.0.suit
WASM_APP = app.wasm
WASM_RUNTIME ?= iwasm

.PHONY: all
all: $(SUIT_MANIFEST_PROCESSOR) $(MANIFEST)
	$(SUIT_MANIFEST_PROCESSOR) $(MANIFEST)
	ls -la
	$(WASM_RUNTIME) $(WASM_APP)

$(SUIT_MANIFEST_PROCESSOR):
	make -C ../process

$(MANIFEST):
	make -C ../manifest

.PHONY: clean
clean:
	$(RM) $(WASM_APP) $(STORED_MANIFEST)
