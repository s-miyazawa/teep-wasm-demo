#--------------------------------------------------
# Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
# 
# SPDX-License-Identifier: BSD-2-Clause
#--------------------------------------------------

#!/bin/bash
set -e

cd "$(dirname "$0")/../third_party"
mkdir -p ../build/lib

echo "[INFO] Building QCBOR..."
make -C QCBOR -B libqcbor.a
mv QCBOR/libqcbor.a ../build/lib/

echo "[INFO] Building t_cose..."
make -C t_cose -B -f Makefile.ossl libt_cose.a QCBOR_INC='-I ../QCBOR/inc' 
mv t_cose/libt_cose.a ../build/lib/

echo "[INFO] Building libcsuit..."
make -C libcsuit -B -f Makefile libcsuit.a LOCAL_CFLAGS='$(WARNING_CFLAGS) -fPIC -I /usr/local/include -I ./inc -I ../QCBOR/inc -I ../t_cose/inc'
mv libcsuit/libcsuit.a ../build/lib/

echo "[INFO] Building libteep..."
make -C libteep -B -f Makefile libteep.a INC='-I./inc -I../QCBOR/inc -I../t_cose/inc'
mv libteep/libteep.a ../build/lib/