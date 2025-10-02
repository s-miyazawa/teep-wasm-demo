#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

QUERY_REQUEST=query_request.tam.esp256.cose
QUERY_RESPONSE=query_response.agent.esp256.cose
UPDATE=update.tam.esp256.cose
TAM_MESSAGES=$(QUERY_REQUEST) $(UPDATE)
AGENT_MESSAGES=$(QUERY_RESPONSE)

.PHONY: all
all: $(TAM_MESSAGES) $(AGENT_MESSAGES)

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
app.wasm.envelope.cbor.bin.hdiag: ../manifest/app.wasm.envelope.cbor

../manifest/app.wasm.envelope.cbor:
	$(MAKE) -C ../manifest/ app.wasm.envelope.cbor

$(UPDATE): app.wasm.envelope.cbor.bin.hdiag

.PHONY: clean
clean: common-clean
