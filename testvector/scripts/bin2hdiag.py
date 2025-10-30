#!/usr/bin/env python3

#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

import sys
if len(sys.argv) != 2:
    sys.exit(-1)
with open(sys.argv[1], "rb") as f:
    print(f"h'{f.read().hex()}'")

