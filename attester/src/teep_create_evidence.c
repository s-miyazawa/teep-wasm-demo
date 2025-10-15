#include <stdio.h>
#include "teep_create_evidence.h"

//#include "teep_agent_es256_private_key.h"
//#include "teep_agent_es256_public_key.h"
const unsigned char teep_agent_hardware_es256_private_key[] = {
    0xf3, 0xbd, 0x0c, 0x07, 0xa8, 0x1f, 0xb9, 0x32, 
    0x78, 0x1e, 0xd5, 0x27, 0x52, 0xf6, 0x0c, 0xc8,
    0x9a, 0x6b, 0xe5, 0xe5, 0x19, 0x34, 0xfe, 0x01, 
    0x93, 0x8d, 0xdb, 0x55, 0xd8, 0xf7, 0x78, 0x01
};
const unsigned char teep_agent_hardware_es256_evidence_public_key[] = {
    0x04 /* POINT_CONVERSION_UNCOMPRESSED */,
    0x30, 0xa0, 0x42, 0x4c, 0xd2, 0x1c, 0x29, 0x44,
    0x83, 0x8a, 0x2d, 0x75, 0xc9, 0x2b, 0x37, 0xe7,
    0x6e, 0xa2, 0x0d, 0x9f, 0x00, 0x89, 0x3a, 0x3b,
    0x4e, 0xee, 0x8a, 0x3c, 0x0a, 0xaf, 0xec, 0x3e,  
    0xe0, 0x4b, 0x65, 0xe9, 0x24, 0x56, 0xd9, 0x88,
    0x8b, 0x52, 0xb3, 0x79, 0xbd, 0xfb, 0xd5, 0x1e,
    0xe8, 0x69, 0xef, 0x1f, 0x0f, 0xc6, 0x5b, 0x66,
    0x59, 0x69, 0x5b, 0x6c, 0xce, 0x08, 0x17, 0x23
};



/*!
    \brief      Create evidence with RATS EAT.

    \param[in]      query_request   Received teep-query-request message from the TAM.
    \param[in]      buf          Allocated buffer.
    \param[out]     ret             Pointer of the output struct.

    \return     This returns TEEP_AGENT_SUCCESS or TEEP_AGENT_ERR_FAILED_TO_CREATE_EVIDENCE.
*/
teep_err_t create_evidence(const teep_query_request_t *query_request,
                                 UsefulBuf buf,
                                 UsefulBufC *ret)
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;

    QCBOREncodeContext context;

    /* Initialize for signing */
    teep_mechanism_t mechanism_sign;
    teep_err_t          result;
    result = teep_key_init_es256_key_pair(teep_agent_hardware_es256_private_key, teep_agent_hardware_es256_evidence_public_key, NULLUsefulBufC, &mechanism_sign.key);
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
    // eat-profile / 265 : "http://arm.com/psa/2.0.0"
    QCBOREncode_AddTextToMapN(&context, 265, UsefulBuf_FROM_SZ_LITERAL("http://arm.com/psa/2.0.0"));

    /*psa-client-id*/
    // psa-client-id / 2394 : 1
    QCBOREncode_AddInt64ToMapN(&context, 2394, 1);

    /*psa-security-lifecycle*/
    // psa-security-lifecycle /2395 : 12288
    QCBOREncode_AddInt64ToMapN(&context, 2395, 12288);


    /*psa-implementation-id*/
    // psa-implementation-id /2396  : "YWNtZS1pbXBsZW1lbnRhdGlvbi1pZC0wMDAwMDAwMDE="
    uint8_t impl_id[]={97, 99, 109, 101, 45, 105, 109, 112, 108, 101, 109, 101, 110, 116, 97, 116, 105, 111, 110, 45, 105, 100, 45, 48, 48, 48, 48, 48, 48, 48, 48, 49};
    QCBOREncode_AddBytesToMapN(&context, 2396, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(impl_id));


    /* psa-boot-seed */
    // psa-boot-seed /2397: "3q2+796tvu/erb7v3q2+796tvu/erb7v3q2+796tvu8="
    uint8_t boot_seed[]={222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239};
    QCBOREncode_AddBytesToMapN(&context, 2397, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(boot_seed));

    /* psa-hardware-version */
    //psa-hardware-version /???? : "1234567890123"
    //QCBOREncode_AddTextToMapN(&context, ????, UsefulBuf_FROM_SZ_LITERAL("1234567890123"));


    /* "psa-software-components" /2399 : [    */
    QCBOREncode_OpenArrayInMapN(&context, 2399);

    /*
    {
      "measurement-type"/1: "BL",
      "measurement-value"/2:  "h0KPxSKAPTEGXnvOPPA/5HUJZjHl4Hu9eg/eYMTPJcc=",
      "version"/4 : "2.1.0"
      "signer-id"/5 : "rLsRx+TaIXIFUjzkzhokWuGiOa48a/2eeHH35di66Gs=",
    } 
    */ 
    uint8_t BL_measurement_value[]={135, 66, 143, 197, 34, 128, 61, 49, 6, 94, 123, 206, 60, 240, 63, 228, 117, 9, 102, 49, 229, 224, 123, 189, 122, 15, 222, 96, 196, 207, 37, 199};
    uint8_t signer_id[]={172, 187, 17, 199, 228, 218, 33, 114, 5, 82, 60, 228, 206, 26, 36, 90, 225, 162, 57, 174, 60, 107, 253, 158, 120, 113, 247, 229, 216, 186, 232, 107};

    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddTextToMapN(&context, 1, UsefulBuf_FROM_SZ_LITERAL("BL"));
    QCBOREncode_AddBytesToMapN(&context, 2, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(BL_measurement_value));
    QCBOREncode_AddTextToMapN(&context, 4, UsefulBuf_FROM_SZ_LITERAL("2.1.0"));
    QCBOREncode_AddBytesToMapN(&context, 5, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(signer_id));
    QCBOREncode_CloseMap(&context);
    
    /*
    {
      "measurement-type":/1 "PRoT",
      "measurement-value"/2: "AmOCmYm2/ZVPcrqvL8ZLwuLwHWktTecphuqAj26ZgT8=",
      "version"/4: "1.3.5"
      "signer-id"/5: "rLsRx+TaIXIFUjzkzhokWuGiOa48a/2eeHH35di66Gs=",
    }
      */
    uint8_t PRoT_measurement_value[]={2, 99, 130, 153, 137, 182, 253, 149, 79, 114, 186, 175, 47, 198, 75, 194, 226, 240, 29, 105, 45, 77, 231, 41, 134, 234, 128, 143, 110, 153, 129, 63};

    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddTextToMapN(&context, 1, UsefulBuf_FROM_SZ_LITERAL("PRoT"));
    QCBOREncode_AddBytesToMapN(&context, 2, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(PRoT_measurement_value));
    QCBOREncode_AddTextToMapN(&context, 4, UsefulBuf_FROM_SZ_LITERAL("1.3.5"));
    QCBOREncode_AddBytesToMapN(&context, 5, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(signer_id));
    QCBOREncode_CloseMap(&context);
  
    /*
    {
      "measurement-type"/1: "ARoT",
      "measurement-value"/2: "o6XnFfDMV0pzw/m+u2vCTzL/1bZ7OHJEwskJ2neaFHg=",
      "version"/4: "0.1.4"
      "signer-id"/5: "rLsRx+TaIXIFUjzkzhokWuGiOa48a/2eeHH35di66Gs=",
    }
    */
    uint8_t ARoT_measurement_value[]={163, 165, 231, 21, 240, 204, 87, 74, 115, 195, 249, 190, 187, 107, 194, 79, 50, 255, 213, 182, 123, 56, 114, 68, 194, 201, 9, 218, 119, 154, 20, 120};

    QCBOREncode_OpenMap(&context);
    QCBOREncode_AddTextToMapN(&context, 1, UsefulBuf_FROM_SZ_LITERAL("ARoT"));
    QCBOREncode_AddBytesToMapN(&context, 2, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(ARoT_measurement_value));
    QCBOREncode_AddTextToMapN(&context, 4, UsefulBuf_FROM_SZ_LITERAL("0.1.4"));
    QCBOREncode_AddBytesToMapN(&context, 5, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(signer_id));
    QCBOREncode_CloseMap(&context);

    QCBOREncode_CloseArray(&context);

    /* psa-nonce */
    //"psa-nonce" /10 : "QUp8F0FBs9DpodKK8xUg8NQimf6sQAfe2J1ormzZLxk="
    uint8_t nonce[]={65, 74, 124, 23, 65, 65, 179, 208, 233, 161, 210, 138, 243, 21, 32, 240, 212, 34, 153, 254, 172, 64, 7, 222, 216, 157, 104, 174, 108, 217, 47, 25};
    QCBOREncode_AddBytesToMapN(&context, 10, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(nonce));

    /* psa-instance-id */
    // psa-instance-id /256: "Ac7rrnuJJ6MiflMDz14PH3s0u1Qq1yUKwD+83jbsLxUI"
    uint8_t instance_id[]={1, 206, 235, 174, 123, 137, 39, 163, 34, 126, 83, 3, 207, 94, 15, 31, 123, 52, 187, 84, 42, 215, 37, 10, 192, 63, 188, 222, 54, 236, 47, 21, 8};
    QCBOREncode_AddBytesToMapN(&context, 256, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(instance_id));

    /* psa-verification-service-indicator */
    //"psa-verification-service-indicator" /2400  : "https://psa-verifier.org",
    QCBOREncode_AddTextToMapN(&context, 2400, UsefulBuf_FROM_SZ_LITERAL("https://psa-verifier.org"));

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




