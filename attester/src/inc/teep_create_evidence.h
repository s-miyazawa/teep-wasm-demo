/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// create_evidence.h
#ifndef CREATE_EVIDENCE_H
#define CREATE_EVIDENCE_H

#include <stdint.h>                 
#include "teep/teep_message_data.h" 
#include "teep/teep_common.h"       


teep_err_t create_evidence_psa(const teep_query_request_t *query_request,
                           UsefulBuf buf,
                           UsefulBufC *ret);
                    
teep_err_t create_evidence_generic(const teep_query_request_t *query_request,
                           UsefulBuf buf,
                           teep_key_t *key_pair,
                           UsefulBufC *ret);


#endif /* CREATE_EVIDENCE_H */
