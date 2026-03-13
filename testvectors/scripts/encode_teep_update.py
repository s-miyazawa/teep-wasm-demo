#!/usr/bin/env python3

#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

import argparse
from cbor2 import dumps

parser = argparse.ArgumentParser(description="Encode TEEP Protocol Update message")
parser.add_argument("manifest", help="input SUIT Manifest filename")
parser.add_argument("output", help="output filename")

args = parser.parse_args()

with open(args.manifest, "rb") as f:
    manifest_bin = f.read()

update_message = dumps([
    3, # update
    {
        19: bytes.fromhex("0011223344556677"), # token
        9: [manifest_bin] # manifest-list
    }
])

with open(args.output, "wb") as f:
    f.write(update_message)
