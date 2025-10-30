#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

SUIT_MANIFEST_PROCESSOR = ../process/suit_manifest_process

.PHONY: all
all: composition.svg

%.svg: %.aasvg
	aasvg --backdrop --spaces=0 < $< > $@
