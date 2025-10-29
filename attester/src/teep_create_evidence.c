/*
 * Copyright (c) 2025 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <teep/teep_message_print.h>
#include "teep_create_evidence.h"

#include "attester_es256_cose_key_private.h"
#include "trust_anchor_es256_key_for_psa.h"



enum{
    /* common */
    EAT_PROFILE = 265,
    MEASUREMENT_VALUE = 2,

    /* psa-eat */
    PSA_CLIENT_ID = 2394,
    PSA_SECURITY_LIFECYCLE = 2395,
    PSA_IMPLEMENTATION_ID = 2396,
    PSA_BOOT_SEED = 2397,
    PSA_SOFTWARE_COMPONENTS = 2399,

    MEASUREMENT_TYPE = 1,

    VERSION = 4,
    SIGNER_ID = 5,
    PSA_NONCE = 10,
    PSA_INSTANCE_ID = 256,
    PSA_VERIFICATION_SERVICE_INDICATOR = 2400,

    /* generic-eat */
    CNF = 8,
    COSE_KEY = 1,
    KEY_TYPE = 1,
    CURVE = -1,
    X_COORDINATE = -2,
    Y_COORDINATE = -3,
    KEY_ID = 3,
    EAT_NONCE = 10,
    UEID = 256,
    OEMID = 258,
    HWMODEL = 259,
    HWVERSION = 260,
    MEASUREMENTS =273,
    CONTENT_TYPE = 600,
    ID = 1,
    ALGORITHM = 1
};

/*!
    \brief      Create evidence with RATS EAT.

    \param[in]      query_request   Received teep-query-request message from the TAM.
    \param[in]      buf          Allocated buffer.
    \param[out]     ret             Pointer of the output struct.

    \return     This returns TEEP_AGENT_SUCCESS or TEEP_AGENT_ERR_FAILED_TO_CREATE_EVIDENCE.
*/
teep_err_t create_evidence_psa(const teep_query_request_t *query_request,
                                 UsefulBuf buf,
                                 UsefulBufC *ret)
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;

    QCBOREncodeContext context;

    /* Initialize for signing */
    teep_mechanism_t mechanism_sign;
    teep_err_t          result;
    result = teep_key_init_es256_key_pair(trust_anchor_es256_private_key, trust_anchor_es256_public_key, NULLUsefulBufC, &mechanism_sign.key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to create t_cose key pair. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, mechanism_sign.key.cose_key, mechanism_sign.key.kid);
    
    
    QCBOREncode_Init(&context, buf);

    /* encode the header */
    
    enum t_cose_err_t t_cose_result = t_cose_sign1_encode_parameters(&sign_ctx, &context);
    if (t_cose_result != T_COSE_SUCCESS) {
        return TEEP_ERR_SIGNING_FAILED;
    }
    
    /* encoding payload start */
    QCBOREncode_OpenMap(&context);

    /* eat-profile */
    QCBOREncode_AddTextToMapN(&context, EAT_PROFILE, UsefulBuf_FROM_SZ_LITERAL("http://arm.com/psa/2.0.0"));

    /*psa-client-id*/
    QCBOREncode_AddInt64ToMapN(&context, PSA_CLIENT_ID, 1);

    /*psa-security-lifecycle*/
    QCBOREncode_AddInt64ToMapN(&context, PSA_SECURITY_LIFECYCLE, 12288);

    /*psa-implementation-id*/
    uint8_t impl_id[]={97, 99, 109, 101, 45, 105, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 45, 105, 100, 45, 48, 48, 48, 48, 48, 48, 48, 48, 49};
    QCBOREncode_AddBytesToMapN(&context, PSA_IMPLEMENTATION_ID, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(impl_id));


    /* psa-boot-seed */
    uint8_t boot_seed[]={222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239};
    QCBOREncode_AddBytesToMapN(&context, PSA_BOOT_SEED, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(boot_seed));

    /* psa-software-components*/
    QCBOREncode_OpenArrayInMapN(&context, PSA_SOFTWARE_COMPONENTS);

    uint8_t BL_measurement_value[]={135, 66, 143, 197, 34, 128, 61, 49, 6, 94, 123, 206, 60, 240, 63, 228, 117, 9, 102, 49, 229, 224, 123, 189, 122, 15, 222, 96, 196, 207, 37, 199};
    uint8_t signer_id[]={172, 187, 17, 199, 228, 218, 33, 114, 5, 82, 60, 228, 206, 26, 36, 90, 225, 162, 57, 174, 60, 107, 253, 158, 120, 113, 247, 229, 216, 186, 232, 107};

    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddTextToMapN(&context, MEASUREMENT_TYPE , UsefulBuf_FROM_SZ_LITERAL("BL"));
    QCBOREncode_AddBytesToMapN(&context, MEASUREMENT_VALUE, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(BL_measurement_value));
    QCBOREncode_AddTextToMapN(&context, VERSION, UsefulBuf_FROM_SZ_LITERAL("2.1.0"));
    QCBOREncode_AddBytesToMapN(&context, SIGNER_ID, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(signer_id));
    QCBOREncode_CloseMap(&context);
    
    uint8_t PRoT_measurement_value[]={2, 99, 130, 153, 137, 182, 253, 149, 79, 114, 186, 175, 47, 198, 75, 194, 226, 240, 29, 105, 45, 77, 231, 41, 134, 234, 128, 143, 110, 153, 129, 63};
    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddTextToMapN(&context, MEASUREMENT_TYPE, UsefulBuf_FROM_SZ_LITERAL("PRoT"));
    QCBOREncode_AddBytesToMapN(&context, MEASUREMENT_VALUE, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(PRoT_measurement_value));
    QCBOREncode_AddTextToMapN(&context, VERSION, UsefulBuf_FROM_SZ_LITERAL("1.3.5"));
    QCBOREncode_AddBytesToMapN(&context, SIGNER_ID, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(signer_id));
    QCBOREncode_CloseMap(&context);
  

    uint8_t ARoT_measurement_value[]={163, 165, 231, 21, 240, 204, 87, 74, 115, 195, 249, 190, 187, 107, 194, 79, 50, 255, 213, 182, 123, 56, 114, 68, 194, 201, 9, 218, 119, 154, 20, 120};
    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddTextToMapN(&context, MEASUREMENT_TYPE, UsefulBuf_FROM_SZ_LITERAL("ARoT"));
    QCBOREncode_AddBytesToMapN(&context, MEASUREMENT_VALUE, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(ARoT_measurement_value));
    QCBOREncode_AddTextToMapN(&context, VERSION, UsefulBuf_FROM_SZ_LITERAL("0.1.4"));
    QCBOREncode_AddBytesToMapN(&context, SIGNER_ID, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(signer_id));
    QCBOREncode_CloseMap(&context);

    QCBOREncode_CloseArray(&context);

    /* psa-nonce */
    uint8_t nonce[]={65, 74, 124, 23, 65, 65, 179, 208, 233, 161, 210, 138, 243, 21, 32, 240, 212, 34, 153, 254, 172, 64, 7, 222, 216, 157, 104, 174, 108, 217, 47, 25};
    QCBOREncode_AddBytesToMapN(&context, PSA_NONCE, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(nonce));

    /* psa-instance-id */
    uint8_t instance_id[]={1, 206, 235, 174, 123, 137, 39, 163, 34, 126, 83, 3, 207, 94, 15, 31, 123, 52, 187, 84, 42, 215, 37, 10, 192, 63, 188, 222, 54, 236, 47, 21, 8};
    QCBOREncode_AddBytesToMapN(&context, PSA_INSTANCE_ID, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(instance_id));

    /* psa-verification-service-indicator */
    //"psa-verification-service-indicator" /2400  : "https://psa-verifier.org",
    QCBOREncode_AddTextToMapN(&context, PSA_VERIFICATION_SERVICE_INDICATOR, UsefulBuf_FROM_SZ_LITERAL("https://psa-verifier.org"));

    QCBOREncode_CloseMap(&context);

    /* sign */
    cose_result = t_cose_sign1_encode_signature(&sign_ctx, &context);
    if (cose_result != T_COSE_SUCCESS) {
        return TEEP_ERR_SIGNING_FAILED;
    }

    /* complete CBOR Encoding */
    QCBORError error = QCBOREncode_Finish(&context, ret);
    if (error != QCBOR_SUCCESS) {
        printf("QCBOREncode_Finish() = %d\n", error);
        return TEEP_ERR_UNEXPECTED_ERROR;
    }

    return TEEP_SUCCESS;
}


/*!
    \brief      Create evidence with RATS EAT.

    \param[in]      query_request   Received teep-query-request message from the TAM.
    \param[in]      buf          Allocated buffer.
    \param[in]      teep_agent_key_pair The Evidence includes the TEEP Agent’s public key.
    \param[out]     ret             Pointer of the output struct.

    \return     This returns TEEP_AGENT_SUCCESS or TEEP_AGENT_ERR_FAILED_TO_CREATE_EVIDENCE.
*/
teep_err_t create_evidence_generic(const teep_query_request_t *query_request,
                                 UsefulBuf buf,
                                 teep_key_t *key_pair,
                                 UsefulBufC *ret)
{

    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;

    QCBOREncodeContext context;

    /* Initialize for signing */
    teep_err_t          result;
    teep_mechanism_t mechanism_sign;
    result = teep_key_init_es256_key_pair(trust_anchor_es256_private_key, trust_anchor_es256_public_key, NULLUsefulBufC, &mechanism_sign.key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to create t_cose key pair. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, mechanism_sign.key.cose_key, mechanism_sign.key.kid);
    
    /* encode the header */
    QCBOREncode_Init(&context, buf);
    enum t_cose_err_t t_cose_result = t_cose_sign1_encode_parameters(&sign_ctx, &context);
    if (t_cose_result != T_COSE_SUCCESS) {
        return TEEP_ERR_SIGNING_FAILED;
    }


    /* encoding payload start */
    QCBOREncode_OpenMap(&context);

    /* confirmation */
    //cnf/8: {/ COSE_Key /1:{/kty/1:2, /crv/-1:1, /x/-2:h'...', /y/-3:h'...'},/kid/3:h'...'}
    int64_t kty = 2; // EC2
    int64_t crv = 1; // P-256
    unsigned char public_key_x[32];
    unsigned char public_key_y[32];
    memcpy(public_key_x, key_pair->public_key+1, 32);
    memcpy(public_key_y, key_pair->public_key+33, 32);


    QCBOREncode_OpenMapInMapN(&context, CNF); // open cnf map
    QCBOREncode_OpenMapInMapN(&context, COSE_KEY); // open cose_key map
    QCBOREncode_AddInt64ToMapN(&context, KEY_TYPE, kty); // key type
    QCBOREncode_AddInt64ToMapN(&context, CURVE, crv); //curve
    QCBOREncode_AddBytesToMapN(&context, X_COORDINATE, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(public_key_x)); // x
    QCBOREncode_AddBytesToMapN(&context, Y_COORDINATE, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(public_key_y)); // y 
    QCBOREncode_CloseMap(&context); // close cose_key map
    QCBOREncode_AddBytesToMapN(&context, KEY_ID, key_pair->kid); // kid       
    QCBOREncode_CloseMap(&context); // close cnf map
    
    /* eat_nonce */
    const uint8_t eat_nonce[] = {0x94, 0x8F, 0x88, 0x60, 0xD1, 0x3A, 0x46, 0x3E, 0x8E};
    QCBOREncode_AddBytesToMapN(&context, EAT_NONCE, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(eat_nonce));

    /* ueid */
    uint8_t ueid[] = {0x01, 0x98, 0xf5, 0x0a, 0x4f, 0xf6, 0xc0, 0x58, 0x61, 0xc8, 0x86, 0x0d, 0x13, 0xa6, 0x38, 0xea};
    QCBOREncode_AddBytesToMapN(&context, UEID, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(ueid));

    /* oemid */
    uint8_t oemid[] = {0x89, 0x48, 0x23};
    QCBOREncode_AddBytesToMapN(&context, OEMID, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(oemid));

    /* hwmodel */
    uint8_t hwmodel[] = {0x54, 0x9d, 0xce, 0xcc, 0x8b, 0x98, 0x7c, 0x73, 0x7b, 0x44, 0xe4, 0x0f, 0x7c, 0x63, 0x5c, 0xe8};
    QCBOREncode_AddBytesToMapN(&context, HWMODEL, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(hwmodel));

    /* hwversion */
    QCBOREncode_OpenArrayInMapN(&context, HWVERSION);
    QCBOREncode_AddText(&context, UsefulBuf_FROM_SZ_LITERAL("1.3.4"));
    QCBOREncode_AddInt64(&context, 1);
    QCBOREncode_CloseArray(&context);

    /* eat_profile */
    QCBOREncode_AddTextToMapN(&context, EAT_PROFILE, UsefulBuf_FROM_SZ_LITERAL("urn:ietf:rfc:rfc9711"));

    /* measurements */
    static const uint8_t deadbeef_bytes[] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
    };

    QCBOREncode_OpenArrayInMapN(&context, MEASUREMENTS); // open measurements array
    QCBOREncode_OpenArray(&context);  // open measurements inner array

    QCBOREncode_AddInt64(&context, CONTENT_TYPE); //content-type
    QCBOREncode_BstrWrap(&context); // open bstr wrap
    QCBOREncode_OpenMap(&context); // open content-format map
    QCBOREncode_OpenArrayInMapN(&context, ID); // open id array
    QCBOREncode_AddText(&context, UsefulBuf_FROM_SZ_LITERAL("TEEP Agent")); //name
    QCBOREncode_OpenArray(&context); // open version array
    QCBOREncode_AddText(&context, UsefulBuf_FROM_SZ_LITERAL("1.3.4"));
    QCBOREncode_AddInt64(&context, 1);
    QCBOREncode_CloseArray(&context); // close version array
    QCBOREncode_CloseArray(&context); // close id array
    QCBOREncode_OpenArrayInMapN(&context, MEASUREMENT_VALUE); // open measurement array
    QCBOREncode_AddInt64(&context, ALGORITHM); //alg
    QCBOREncode_AddBytes(&context, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(deadbeef_bytes)); //value
    QCBOREncode_CloseArray(&context); // close measurement array
    QCBOREncode_CloseMap(&context); // close content-format map
    QCBOREncode_CloseBstrWrap(&context, NULL); // close bstr wrap

    QCBOREncode_CloseArray(&context); // close measurements inner array
    QCBOREncode_CloseArray(&context); // close measurements array


    /* encoding payload end */
    QCBOREncode_CloseMap(&context);

    
    /* sign */
    cose_result = t_cose_sign1_encode_signature(&sign_ctx, &context);
    if (cose_result != T_COSE_SUCCESS) {
        return TEEP_ERR_SIGNING_FAILED;
    }
    
    /* complete CBOR Encoding */
    QCBORError error = QCBOREncode_Finish(&context, ret);
    if (error != QCBOR_SUCCESS) {
        printf("QCBOREncode_Finish() = %d\n", error);
        return TEEP_ERR_UNEXPECTED_ERROR;
    }

    teep_free_key(&mechanism_sign.key);
    return TEEP_SUCCESS;
}







