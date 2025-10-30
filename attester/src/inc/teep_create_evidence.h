/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// create_evidence.h
#ifndef CREATE_EVIDENCE_H
#define CREATE_EVIDENCE_H

#include <stdint.h>                 // uint32_t を使うなら安全のため
#include "teep/teep_message_data.h" // create_evidence の引数型
#include "teep/teep_common.h"       // UsefulBuf, UsefulBufC, teep_err_t


teep_err_t create_evidence_psa(const teep_query_request_t *query_request,
                           UsefulBuf buf,
                           UsefulBufC *ret);
                    
teep_err_t create_evidence_generic(const teep_query_request_t *query_request,
                           UsefulBuf buf,
                           UsefulBufC *ret);


#endif /* CREATE_EVIDENCE_H */
