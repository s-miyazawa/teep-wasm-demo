/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "getopt.h"

#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include "teep_examples_common.h"
#include "teep_http_client.h"
#include "teep_create_evidence.h"
#include "teep_generate_key_pair.h"
#include "debug_print.h"

#include "csuit/suit_manifest_process.h"
#include "csuit/suit_manifest_print.h"
#include "csuit/suit_cose.h"
#include "csuit/suit_digest.h"
#include "suit_examples_common.h"
#include "suit_manifest_process.h"

#include "trust_anchor_prime256v1_cose_key_public.h"

#include "teep_agent_es256_private_key.h"
#include "teep_agent_es256_public_key.h"

#include "tam_es256_public_key.h"

const char DEFAULT_TAM_URL[] =          "http://localhost:8080/tam";
const char DEFAULT_PROFILE[] =          "psa-eat";
const char DEFAULT_TEEP_AGENT_KEYGEN[] = "no";
#define MAX_RECEIVE_BUFFER_SIZE         1024*100 // 100KB
#define MAX_SEND_BUFFER_SIZE            1024*2
#define MAX_FILE_BUFFER_SIZE            512
#define MAX_APP_NAME_SIZE              64

#define SUPPORTED_VERSION               0
#define SUPPORTED_CIPHER_SUITES_LEN     1
#define ERR_MSG_BUF_LEN                 32
#define MSG_BUF_LEN                 1024
const teep_cipher_suite_t supported_teep_cipher_suites[SUPPORTED_CIPHER_SUITES_LEN] = {
    {
        .mechanisms[0] = {
            .cose_tag = CBOR_TAG_COSE_SIGN1,
            .algorithm_id = T_COSE_ALGORITHM_ES256,
        },
        .mechanisms[1] = {
            0
        }
    }
};


void useful_buf_strncpy(const char *err_msg,
                        const size_t len,
                        UsefulBuf *dst)
{
    strncpy(dst->ptr, err_msg, len); // '\0' may not be appended at the last
    dst->len = strnlen(dst->ptr, len);
}

/*!
    \brief      Create teep-error message.

    \param[in]  token       Bstr token in sent message from the TAM.
    \param[in]  err_code    Integer err-code message set by caller.
    \param[in]  msg_buf Tstr err-msg set by caller.
    \param[out] message     Pointer of returned struct.

    \return     This returns only TEEP_SUCCESS;
 */
teep_err_t create_error(teep_buf_t token,
                        uint64_t err_code,
                        UsefulBuf msg_buf,
                        teep_message_t *message)
{
    teep_error_t *error = (teep_error_t *)message;
    error->type = TEEP_TYPE_TEEP_ERROR;
    error->contains = 0;

    if (token.ptr != NULL && 8 <= token.len && token.len <= 64) {
        error->token = token;
        error->contains |= TEEP_MESSAGE_CONTAINS_TOKEN;
    }
    if (msg_buf.len > 0) {
        error->err_msg = (teep_buf_t){.ptr = msg_buf.ptr, .len = msg_buf.len};
        error->contains |= TEEP_MESSAGE_CONTAINS_ERR_MSG;
    }

    if (err_code == TEEP_ERR_CODE_PERMANENT_ERROR) {
        if (token.ptr == NULL || token.len < 8 || 64 < token.len) {
            /* the token is incorrect */
            error->err_code = TEEP_ERR_CODE_PERMANENT_ERROR;
        }
    }
    else if (err_code == TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION) {
        error->versions.len = 1;
        error->versions.items[0] = SUPPORTED_VERSION;
        error->contains = TEEP_MESSAGE_CONTAINS_VERSIONS;
        error->err_code = TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION;
    }
    else if (err_code == TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES) {
        error->supported_teep_cipher_suites.len = SUPPORTED_CIPHER_SUITES_LEN;
        for (size_t i = 0; i < SUPPORTED_CIPHER_SUITES_LEN; i++) {
            error->supported_teep_cipher_suites.items[i] = supported_teep_cipher_suites[i];
        }
        error->contains |= TEEP_MESSAGE_CONTAINS_SUPPORTED_TEEP_CIPHER_SUITES;
        error->err_code = TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES;
    }
    return TEEP_SUCCESS;
}

/*!
    \brief      Create teep-success or teep-error message as a response to the teep-update message.

    \param[in]  update      Received teep-update message from the TAM.
    \param[in]  msg_buf Tstr err-msg buffer allocated by caller.
    \param[out] message     Pointer of returned struct.

    \return     This returns only TEEP_SUCCESS;
 */
teep_err_t create_success_or_error(const teep_update_t *update,
                                   UsefulBuf msg_buf,
                                   teep_message_t *message)
{
    printf("[TEEP Agent] parsed TEEP Update message\n");
    if (!(update->contains & TEEP_MESSAGE_CONTAINS_TOKEN) ||
        update->token.len < 8 || 64 < update->token.len) {
        useful_buf_strncpy("INVALID TOKEN", ERR_MSG_BUF_LEN, &msg_buf);
        return create_error(update->token, TEEP_ERR_CODE_PERMANENT_ERROR, msg_buf, message);
    }

    
    suit_err_t result = 0;

    int num_key = 0;
    #define NUM_PUBLIC_KEYS_FOR_ECDSA       1
    UsefulBufC public_keys_for_ecdsa[NUM_PUBLIC_KEYS_FOR_ECDSA] = {
        trust_anchor_prime256v1_cose_key_public,
    };
    
    suit_inputs_t *suit_inputs = calloc(1, sizeof(suit_inputs_t) + SUIT_MAX_DATA_SIZE);
    if (suit_inputs == NULL) {
        printf("create_success_or_error : Failed to allocate memory for suit_inputs\n");
        return EXIT_FAILURE;
    }
    suit_inputs->left_len = SUIT_MAX_DATA_SIZE;
    suit_inputs->ptr = suit_inputs->buf;

    for (int i = 0; i < NUM_PUBLIC_KEYS_FOR_ECDSA; i++) {
        suit_inputs->mechanisms[num_key].key.cose_algorithm_id = T_COSE_ALGORITHM_ES256;
        result = suit_set_suit_key_from_cose_key(public_keys_for_ecdsa[i], &suit_inputs->mechanisms[num_key].key);
        if (result != SUIT_SUCCESS) {
            printf("\ncreate_success_or_error : Failed to initialize public key. %s(%d)\n", suit_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        suit_inputs->mechanisms[num_key].use = true;
        suit_inputs->mechanisms[num_key].cose_tag = CBOR_TAG_COSE_SIGN1;
        num_key++;
    }
    
    suit_inputs->key_len = num_key;

    // Read manifest.
    printf("[TEEP Agent] process SUIT Manifest\n");
    suit_inputs->manifest.ptr = update->manifest_list.items[0].ptr;
    suit_inputs->manifest.len = update->manifest_list.items[0].len; 

    if (suit_inputs->manifest.len <= 0) {
        printf("create_success_or_error : Failed to read Manifest. \n");
        return EXIT_FAILURE;
    }

    // Process manifest.
    suit_inputs->process_flags.all = UINT16_MAX;
    suit_inputs->process_flags.uninstall = 0;
    result = suit_process_envelope(suit_inputs);
    if (result != SUIT_SUCCESS) {
        printf("create_success_or_error : Failed to install and invoke a Manifest.\n");
        return EXIT_FAILURE;
    }

    free(suit_inputs);

    // create SUCCESS message
    teep_success_t *success = (teep_success_t *)message;
    success->type = TEEP_TYPE_TEEP_SUCCESS;
    success->contains = TEEP_MESSAGE_CONTAINS_TOKEN;
    success->token = update->token;
    return TEEP_SUCCESS;
}



/*!
    \brief      Create teep-query-response or teep-error message as a response to the teep-query-request message.

    \param[in]  update      Received teep-query-request message from the TAM.
    \param[in]  msg_buf Tstr err-msg buffer allocated by caller.
    \param[in]  app_name    Application filename to be requested.
    \param[in]  profile_arg Profile name string from command line argument.
    \param[in]  teep_agent_key_pair The Evidence includes the TEEP Agent’s public key.
    \param[out] message     Pointer of returned struct.

    \return     This returns only TEEP_SUCCESS;
 */
teep_err_t create_query_response_or_error(const teep_query_request_t *query_request,
                                          UsefulBuf msg_buf,
                                          const char *app_name,
                                          const char *profile_arg,
                                          teep_key_t *key_pair,
                                          teep_message_t *message)
{
    size_t i;
    uint64_t err_code_contains = 0;
    int32_t version = -1;
    teep_cipher_suite_t cipher_suite = TEEP_CIPHER_SUITE_INVALID;
    UsefulBufC eat = NULLUsefulBufC; /* CWT */
    teep_err_t          result;
    UsefulBuf tmp = msg_buf;

    printf("[TEEP Agent] parsed TEEP QueryRequest message\n");
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_VERSIONS) {
        for (i = 0; i < query_request->versions.len; i++) {
            if (query_request->versions.items[i] == SUPPORTED_VERSION) {
                /* supported version is found */
                version = SUPPORTED_VERSION;
                break;
            }
        }
    }
    else {
        /* means version=0 is supported */
        version = 0;
    }

    if (version != SUPPORTED_VERSION) {
        err_code_contains |= TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION;
        goto error;
    }

    if (!(query_request->contains & TEEP_MESSAGE_CONTAINS_SUPPORTED_TEEP_CIPHER_SUITES)) {
        cipher_suite = supported_teep_cipher_suites[0];
    }
    for (i = 0; i < query_request->supported_teep_cipher_suites.len; i++) {
        for (size_t j = 0; j < SUPPORTED_CIPHER_SUITES_LEN; j++) {
            if (teep_cipher_suite_is_same(query_request->supported_teep_cipher_suites.items[i], supported_teep_cipher_suites[j])) {
                /* supported cipher suite is found */
                cipher_suite = supported_teep_cipher_suites[j];
                goto out;
            }
        }
    }
out:
    if (teep_cipher_suite_is_same(cipher_suite, TEEP_CIPHER_SUITE_INVALID)) {
        err_code_contains |= TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES;
        goto error;
    }
    
    if (query_request->data_item_requested.attestation) {
        if (strcmp(profile_arg, "psa-eat") == 0) {
            printf("[TEEP Agent] generate PSA EAT Evidence\n");
            result = create_evidence_psa(query_request, msg_buf, &eat);
        }else if (strcmp(profile_arg, "generic-eat") == 0) {
            printf("[TEEP Agent] generate Generic EAT Evidence\n");
            result = create_evidence_generic(query_request, msg_buf, key_pair, &eat);
        } else {
            printf("create_query_response_or_error : Unsupported profile '%s'\n", profile_arg);
            err_code_contains |= TEEP_ERR_CODE_PERMANENT_ERROR;
            goto error;
        }
        if (result != TEEP_SUCCESS) {
            goto error;
        }
        tmp = UsefulBuf_SliceTail(msg_buf, eat);
        result = TEEP_SUCCESS;  
    }


error: /* would be unneeded if the err-code becomes bit field */
    if (err_code_contains != 0) {
        return create_error(query_request->token, err_code_contains, msg_buf, message);
    }

    /* generate the query_response */
    printf("[TEEP Agent] generate QueryResponse\n");

    teep_query_response_t *query_response = (teep_query_response_t*)message;
    memset(query_response, 0, sizeof(teep_query_response_t));
    
    //   / type: / 2 / TEEP-TYPE-query-response /
    //   / options: /
    //   {
    //     / attestation-payload / 7 : h'' / empty only for example purpose /,
    query_response->type = TEEP_TYPE_QUERY_RESPONSE;
    if(query_request->data_item_requested.attestation){
        query_response->attestation_payload = (teep_buf_t){.ptr = eat.ptr, .len = eat.len};
        query_response->contains |= TEEP_MESSAGE_CONTAINS_ATTESTATION_PAYLOAD;
    }

    //   / requested-tc-list / 14 : 
    int8_t manifest[1024]; 
    QCBOREncodeContext context;

    UsefulBuf app_buf=UsefulBuf_FROM_BYTE_ARRAY(manifest);
    UsefulBufC requesting_manifest;
    UsefulBufC bytes = (UsefulBufC){ .ptr = app_name, .len = strlen(app_name) };

    QCBOREncode_Init(&context, app_buf);
    QCBOREncode_AddBytes(&context, bytes);  
    result = QCBOREncode_Finish(&context, &requesting_manifest);    
    if (result != TEEP_SUCCESS) {
        err_code_contains |= TEEP_ERR_CODE_PERMANENT_ERROR;
        return create_error(query_request->token, err_code_contains, UsefulBuf_Unconst(UsefulBuf_FROM_SZ_LITERAL("INTERNAL ERROR")), message);
    }    

    UsefulBufC encoded_manifest_component_id;
    QCBOREncode_Init(&context, tmp);
    QCBOREncode_OpenArray(&context);
    QCBOREncode_AddBytes(&context, requesting_manifest);
    QCBOREncode_CloseArray(&context);
    result = QCBOREncode_Finish(&context, &encoded_manifest_component_id);
    if (result != TEEP_SUCCESS) {
        err_code_contains |= TEEP_ERR_CODE_PERMANENT_ERROR;
        return create_error(query_request->token, err_code_contains, UsefulBuf_Unconst(UsefulBuf_FROM_SZ_LITERAL("INTERNAL ERROR")), message);
    }    

    query_response->contains |= TEEP_MESSAGE_CONTAINS_REQUESTED_TC_LIST;
    query_response->requested_tc_list.len = 1;
    query_response->requested_tc_list.items[0] = (teep_requested_tc_info_t) {
        .component_id = (teep_buf_t){.ptr = encoded_manifest_component_id.ptr, .len = encoded_manifest_component_id.len},
        .tc_manifest_sequence_number = 1,
        .have_binary = false
    };

    TEEP_DEBUG_QUERY_RESPONSE(query_response, 2, 2);

    return TEEP_SUCCESS;
}

/*!
    \brief      POST a teep-message and receive response teep-messsage.

    \param[in]  tam_url         Pointer to URI front-end of the TAM.
    \param[in]  send_buf        CBOR buffer to be sent.
    \param[in]  verifying_key   A verifycation key.
    \param[out] recv_buf        CBOR buffer to be used for received message.
    \param[out] message         Pointer of returned struct.

    \return     This returns one of error codes defined by \ref teep_err_t;
 */
teep_err_t get_teep_message(const char *tam_url,
                            UsefulBufC send_buf,
                            teep_mechanism_t *verifying_key,
                            UsefulBuf recv_buf,
                            teep_message_t *message)
{
    teep_err_t result;

    // Send TEEP/HTTP POST request.
    result = teep_send_http_post(tam_url, send_buf, &recv_buf);
    if (result != TEEP_SUCCESS) {
        return result;
    }

    // Verify and print QueryRequest cose.
    UsefulBufC payload;
    verifying_key->cose_tag = CBOR_TAG_COSE_SIGN1;
    result = teep_verify_cose_sign1(UsefulBuf_Const(recv_buf), verifying_key, &payload);
    if (result != TEEP_SUCCESS) {
        verifying_key->cose_tag = CBOR_TAG_COSE_SIGN;
        result = teep_verify_cose_sign(UsefulBuf_Const(recv_buf), verifying_key, 1, &payload);
    }
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to verify TEEP message. %s(%d)\n", teep_err_to_str(result), result);
        return result;
    }

    return teep_set_message_from_bytes(payload.ptr, payload.len, message);
}



void usage(const char *progname) {
    fprintf(stderr, "Usage: %s install <app_name> [--url <url> | -u <url>] [--profile <profile> | -p <profile>]\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char * const argv[])
{
    teep_err_t          result;
    typedef enum teep_agent_status {
        WAITING_QUERY_REQUEST,
        WAITING_UPDATE_OR_QUERY_REQUEST,
    } teep_agent_status_t;
    teep_agent_status_t status = WAITING_QUERY_REQUEST;
    const char *tam_url = NULL;
    const char *profile_arg = NULL;
    const char *teep_agent_keygen = NULL;
    char app_name[MAX_APP_NAME_SIZE];
    const char *command = NULL;


    if (argc < 3) {
        usage(argv[0]);
    }
    command = argv[1];
    if (strcmp(command, "install") != 0) {
        fprintf(stderr, "Error: unknown command '%s'\n", command);
        usage(argv[0]);
    }
    if (strlen(argv[2]) >= MAX_APP_NAME_SIZE) {
        printf("Application name is too long. max %d\n", MAX_APP_NAME_SIZE - 1);
        return 1;
    }
    snprintf(app_name, MAX_APP_NAME_SIZE, "%s", argv[2]);
    
    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"url", required_argument, 0, 'u'},
        {"profile", required_argument, 0, 'p'},
        {"teep_agent_keygen", required_argument, 0, 't'},
        {0, 0, 0, 0}
    };
    optind = 3;
    while ((opt = getopt_long(argc, argv, "u:p:t:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'u':
                tam_url = optarg;
                break;
            case 'p':
                profile_arg = optarg;
                break;
            case 't':
                teep_agent_keygen = optarg;
                break;
            case '?':
            default:
                usage(argv[0]);
        }
    }
    if (tam_url == NULL) {
        tam_url = getenv("TAM_URL");
        if (tam_url == NULL) {
            tam_url = DEFAULT_TAM_URL; 
        }
    }
    if (profile_arg == NULL) {
        profile_arg = getenv("PROFILE");
        if (profile_arg == NULL) {
            profile_arg = DEFAULT_PROFILE;
        }
    }
    if (teep_agent_keygen == NULL){
        teep_agent_keygen = getenv("TEEP_AGENT_KEYGEN");
        if (teep_agent_keygen == NULL){
            teep_agent_keygen = DEFAULT_TEEP_AGENT_KEYGEN;
        }
    }


    UsefulBuf_MAKE_STACK_UB(cbor_recv_buf, MAX_RECEIVE_BUFFER_SIZE);
    UsefulBuf_MAKE_STACK_UB(cbor_send_buf, MAX_SEND_BUFFER_SIZE);
    UsefulBuf_MAKE_STACK_UB(cose_send_buf, MAX_SEND_BUFFER_SIZE);

    // Create signing and verification keys.
    teep_mechanism_t mechanism_sign;

    if (strcmp(teep_agent_keygen, "yes") == 0){
        result = teep_generate_es256_key_pair(&mechanism_sign);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to create key pair. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
    }else if (strcmp(teep_agent_keygen, "no") == 0)
    {
        result = teep_key_init_es256_key_pair(teep_agent_es256_private_key, teep_agent_es256_public_key, NULLUsefulBufC, &mechanism_sign.key);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to set key pair. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        result = teep_genearte_kid(&mechanism_sign.key);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to create kid. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }

    }else{
        printf("mail: teep_agent_keygen option is incorrect.");
        return EXIT_FAILURE;   
    }



    //setting tam_es256_public_key
    teep_mechanism_t mechanism_verify;
    result = teep_key_init_es256_public_key(tam_es256_public_key, NULLUsefulBufC, &mechanism_verify.key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to parse t_cose public key. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    mechanism_verify.cose_tag = CBOR_TAG_COSE_SIGN1;

    teep_message_t send_message;
    teep_message_t recv_message;
    UsefulBuf_MAKE_STACK_UB(msg_buf, MSG_BUF_LEN);
    msg_buf.len = MSG_BUF_LEN; /* the user have to aware this buffer length */

    /* the first message is NULL on teep over http */
    cose_send_buf.len = 0;

    while (1) {
        result = get_teep_message(tam_url, UsefulBuf_Const(cose_send_buf), &mechanism_verify, cbor_recv_buf, &recv_message);
        if (result != TEEP_SUCCESS) {
            if (result == TEEP_ERR_ABORT) {
                /* just the TAM terminated the connection */
                result = TEEP_SUCCESS;
                printf("[TEEP Broker] The TAM terminated the connection\n");
                break;
            }
            else if (result == TEEP_ERR_VERIFICATION_FAILED) {
                /* could not authenticate the TAM's message, ignore */
                printf("main : Could not authenticate the TAM's message.\n");
                goto interval;
            }
            printf("main : Failed to parse received message. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }

        switch (recv_message.teep_message.type) {
        case TEEP_TYPE_QUERY_REQUEST:
            printf("[TEEP Broker] < Received QueryRequest.\n");
            TEEP_DEBUG_QUERY((const teep_query_request_t *)&recv_message, 2, 2);
            result = create_query_response_or_error((const teep_query_request_t *)&recv_message, msg_buf, app_name, profile_arg, &mechanism_sign.key, &send_message);
            break;
        case TEEP_TYPE_UPDATE:
            printf("[TEEP Broker] < Received UpdateMessage.\n");
            TEEP_DEBUG_UPDATE((const teep_update_t *)&recv_message, 2, 2,tam_es256_public_key); 
            if (status == WAITING_QUERY_REQUEST) {
                printf("main : Received Update message without QueryRequest.\n");
                goto interval;
            }
            result = create_success_or_error((const teep_update_t *)&recv_message, msg_buf, &send_message);
            break;
        default:
            printf("main : Unexpected message type %d\n.", recv_message.teep_message.type);
            return EXIT_FAILURE;
        }
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to create teep message. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }

        if (status == WAITING_QUERY_REQUEST &&
            send_message.teep_message.type == TEEP_TYPE_QUERY_RESPONSE) {
            status = WAITING_UPDATE_OR_QUERY_REQUEST;
        }
        else if (status == WAITING_UPDATE_OR_QUERY_REQUEST &&
            send_message.teep_message.type == TEEP_TYPE_TEEP_SUCCESS) {
            status = WAITING_QUERY_REQUEST;
        }

        // Convert send_message to CBOR and sign it
        cbor_send_buf.len = MAX_SEND_BUFFER_SIZE;
        result = teep_encode_message(&send_message, &cbor_send_buf.ptr, &cbor_send_buf.len);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to encode query_response message. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        
        cose_send_buf.len = MAX_SEND_BUFFER_SIZE;
        mechanism_sign.cose_tag = CBOR_TAG_COSE_SIGN1;
        result = teep_sign_cose_sign1(UsefulBuf_Const(cbor_send_buf), &mechanism_sign, &cose_send_buf);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to sign to query_response message. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        
interval:
        sleep(1);
    }

    teep_free_key(&mechanism_verify.key);
    teep_free_key(&mechanism_sign.key);
    return EXIT_SUCCESS;
}
