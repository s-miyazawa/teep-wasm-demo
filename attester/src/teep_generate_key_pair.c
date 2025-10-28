#include "teep_generate_key_pair.h"

#define COSE_KEY_THUMBPRINT_BUFFER_SIZE (11+66+66)

/*!
    \brief      Genearte a KID and store it in key_pair->kid

    \param[in,out]  key_pair         key pair.

    \return     This returns one of error codes defined by \ref teep_err_t;
 */
teep_err_t teep_genearte_kid(teep_key_t *key_pair){
    
    teep_err_t          result;
    QCBOREncodeContext encode_context;
    UsefulBufC cose_key_bytes;
   
    UsefulBuf_MAKE_STACK_UB(buf, COSE_KEY_THUMBPRINT_BUFFER_SIZE);

    QCBOREncode_Init(&encode_context, buf);
    QCBOREncode_OpenMap(&encode_context);
    QCBOREncode_AddInt64ToMapN(&encode_context, TEEP_COSE_KTY, TEEP_COSE_KTY_EC2);
    QCBOREncode_AddInt64ToMapN(&encode_context, TEEP_COSE_CRV, TEEP_COSE_CRV_P256);
    QCBOREncode_AddBytesToMapN(&encode_context, TEEP_COSE_X, (UsefulBufC){.ptr = key_pair->public_key+1, .len = 32});
    QCBOREncode_AddBytesToMapN(&encode_context, TEEP_COSE_Y, (UsefulBufC){.ptr = key_pair->public_key+33, .len = 32});
    QCBOREncode_CloseMap(&encode_context);
    QCBOREncode_Finish(&encode_context, &cose_key_bytes);

    key_pair->kid.len = SHA256_DIGEST_LENGTH;
    key_pair->kid.ptr  = malloc(SHA256_DIGEST_LENGTH);
    result = teep_generate_sha256(cose_key_bytes, key_pair->kid);
    if (result != TEEP_SUCCESS) {
        printf("create_evidence_generic : Failed to calc cose key thumbprint. %s(%d)\n", teep_err_to_str(result), result);
        return result;
    }

    return result;
}



/*!
    \brief      Generate key pair and set them to pair_key.

    \param[in,out]  key_pair         key pair.

    \return     This returns one of error codes defined by \ref teep_err_t;
 */
teep_err_t teep_generate_es256_key_pair(teep_mechanism_t *key_pair) {
    teep_err_t ret = TEEP_ERR_UNEXPECTED_ERROR;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    const EC_POINT *pub_point = NULL;
    const BIGNUM *priv_bn = NULL;
    const EC_GROUP *group = NULL;

    unsigned char priv_bytes[32];
    unsigned char pub_bytes[65]; // 0x04 + X(32) + Y(32)
    size_t pub_len = sizeof(pub_bytes);

    memset(priv_bytes, 0, sizeof(priv_bytes));
    memset(pub_bytes, 0, sizeof(pub_bytes));

    /* generate key pair */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) goto err;

    if (EVP_PKEY_keygen_init(pctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) goto err;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto err;

    ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) goto err;
    group = EC_KEY_get0_group(ec_key);
    pub_point = EC_KEY_get0_public_key(ec_key);
    priv_bn = EC_KEY_get0_private_key(ec_key);

    /* convert bignum to byte */
    BN_bn2binpad(priv_bn, priv_bytes, 32);

    /* fetch public key */
    pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                pub_bytes, sizeof(pub_bytes), NULL);


    /* set the public key to key pair */
    ret = teep_key_init_es256_key_pair(priv_bytes, pub_bytes, NULLUsefulBufC, &key_pair->key);
    if(ret != TEEP_SUCCESS){
        printf("create_evidence_generic : Failed to create cose key. %s(%d)\n", teep_err_to_str(ret), ret);
        return ret;
    }

    key_pair->key.private_key = malloc(SECP384R1_PRIVATE_KEY_LENGTH);
    memcpy(key_pair->key.private_key, priv_bytes,SECP384R1_PRIVATE_KEY_LENGTH);
    key_pair->key.private_key_len = SECP384R1_PRIVATE_KEY_LENGTH;
    key_pair->key.public_key = malloc(PRIME256V1_PUBLIC_KEY_LENGTH);
    memcpy(key_pair->key.public_key, pub_bytes, PRIME256V1_PUBLIC_KEY_LENGTH);
    key_pair->key.public_key_len = PRIME256V1_PUBLIC_KEY_LENGTH;

    ret = teep_genearte_kid(&key_pair->key);
    if(ret != TEEP_SUCCESS){
        printf("create_evidence_generic : Failed to calc cose key thumbprint. %s(%d)\n", teep_err_to_str(ret), ret);
        return ret;
    }

    
    ret = TEEP_SUCCESS;

err:
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}
