#!/usr/bin/env python3

#
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

import argparse
from cbor2 import load, dump

parser = argparse.ArgumentParser(description="Embed a payload to integrated-payload part")
parser.add_argument("input", help="input SUIT Manifest filename")
parser.add_argument("key", help="the uri of integrated-payload used as a key")
parser.add_argument("payload", help="input payload filename")

args = parser.parse_args()

with open(args.input, "rb") as f:
    manifest_obj = load(f)

with open(args.payload, "rb") as f:
    payload_bin = f.read()

manifest_obj[args.key] = payload_bin

with open(args.input, "wb") as f:
    dump(manifest_obj, f)
