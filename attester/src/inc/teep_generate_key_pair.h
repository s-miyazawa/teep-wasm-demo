

#ifndef TEEP_GENERATE_KEY_PAIR.H
#define TEEP_GENERATE_KEY_PAIR.H

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "teep/teep_common.h"
#include "teep/teep_cose.h"

#include "qcbor/UsefulBuf.h"

teep_err_t teep_generate_es256_key_pair(teep_key_t *key_pair);
teep_err_t teep_genearte_kid(teep_key_t *key_pair);

#endif




