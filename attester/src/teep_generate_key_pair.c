#include "teep_generate_key_pair.h"



teep_err_t teep_generate_es256_key_pair(teep_key_t *key_pair, UsefulBufC kid) {
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

    ret = teep_key_init_es256_key_pair(priv_bytes, pub_bytes, kid, key_pair);
    
    if (ret != TEEP_SUCCESS) {
        printf("create_evidence_generic : Failed to init es256 key pair. %s(%d)\n", teep_err_to_str(ret), ret);
        return ret;
    }



    UsefulBuf thumbprint={.ptr = NULL, .len = SHA256_DIGEST_LENGTH};
    thumbprint.ptr = malloc(thumbprint.len);
    ret = teep_calc_cose_key_thumbprint((UsefulBufC){.ptr = key_pair->cose_key.key.ptr, .len = NULL}  , thumbprint);
    if (ret != TEEP_SUCCESS) {
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
