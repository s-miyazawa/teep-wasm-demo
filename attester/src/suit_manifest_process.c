/*!
    \file   suit_manifest_process_main.c

    \brief  A sample to use libcsuit processing
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> // pid_t
#include <sys/wait.h> // waitpid
#include <unistd.h> // fork, getopt, optarg
#include <fcntl.h> // AT_FDCWD
#include "csuit/suit_manifest_process.h"
#include "csuit/suit_manifest_print.h"
#include "csuit/suit_cose.h"
#include "csuit/suit_digest.h"
#include "suit_examples_common.h"

/*
 * Device identifiers, to be checked with suit-parameter-vendor-identifier, etc.
 */
uint8_t vendor_identifier_raw[] = {
    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
    0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe
};
uint8_t class_identifier_raw[] = {
    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
    0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45
};

char *g_prefix = "./";
ssize_t suit_prefix_filename(char *buf, size_t buf_len)
{
    size_t len = strlen(g_prefix);
    if (buf_len < len + 1 || SUIT_MAX_NAME_LENGTH < len + 1) {
        return -1;
    }
    memcpy(buf, g_prefix, len);
    buf[len] = '\0';
    return len;
}

suit_err_t suit_condition_image_match(const suit_component_identifier_t *dst,
                                      const suit_digest_t *image_digest,
                                      const uint64_t image_size,
                                      bool condition_match)
{
    char filename[SUIT_MAX_NAME_LENGTH];
    ssize_t len = suit_prefix_filename(filename, sizeof(filename));
    if (len < 0) {
        return SUIT_ERR_NO_MEMORY;
    }
    char *tmp_filename = &filename[len];
    suit_err_t result = suit_component_identifier_to_filename(dst, SUIT_MAX_NAME_LENGTH, tmp_filename);
    if (result != SUIT_SUCCESS) {
        return result;
    }

    suit_buf_t buf;
    if (image_size == 0) {
        buf.ptr = malloc(SUIT_MAX_DATA_SIZE);
        if (buf.ptr == NULL) {
            return SUIT_ERR_NO_MEMORY;
        }
        buf.len = suit_read_from_file(filename, buf.ptr, SUIT_MAX_DATA_SIZE);
    }
    else {
        buf.ptr = malloc(image_size + 1);
        if (buf.ptr == NULL) {
            return SUIT_ERR_NO_MEMORY;
        }
        buf.len = suit_read_from_file(filename, buf.ptr, image_size + 1);
        if (buf.len != image_size) {
            return SUIT_ERR_CONDITION_MISMATCH;
        }
    }
    result = suit_verify_digest(&buf, image_digest);
    free(buf.ptr);
    if (result == SUIT_ERR_FAILED_TO_VERIFY) {
        result = SUIT_ERR_CONDITION_MISMATCH;
    }
    return result;
}

suit_err_t __wrap_suit_condition_callback(suit_condition_args_t condition_args)
{
    suit_err_t result = SUIT_SUCCESS;

    bool match = true;
    switch (condition_args.condition) {
    /* bstr */
    case SUIT_CONDITION_VENDOR_IDENTIFIER:
        result = UsefulBuf_Compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(vendor_identifier_raw), condition_args.expected.str) ? SUIT_ERR_CONDITION_MISMATCH : SUIT_SUCCESS;
        break;
    case SUIT_CONDITION_CLASS_IDENTIFIER:
        result = UsefulBuf_Compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(class_identifier_raw), condition_args.expected.str) ? SUIT_ERR_CONDITION_MISMATCH : SUIT_SUCCESS;
        break;

    /* SUIT_Digest */
    case SUIT_CONDITION_IMAGE_NOT_MATCH:
        match = false;
    case SUIT_CONDITION_IMAGE_MATCH:
        result = suit_condition_image_match(&condition_args.dst, &condition_args.expected.image_digest, condition_args.expected.image_size, match);
        break;

    case SUIT_CONDITION_CHECK_CONTENT:
    case SUIT_CONDITION_DEVICE_IDENTIFIER:
    case SUIT_CONDITION_COMPONENT_SLOT:
    case SUIT_CONDITION_ABORT:
    case SUIT_CONDITION_DEPENDENCY_INTEGRITY:
    case SUIT_CONDITION_IS_DEPENDENCY:
    case SUIT_CONDITION_USE_BEFORE:
    case SUIT_CONDITION_MINIMUM_BATTERY:
    case SUIT_CONDITION_UPDATE_AUTHORIZED:
    case SUIT_CONDITION_VERSION:
    default:
        result = SUIT_ERR_NOT_IMPLEMENTED;
    }

    if (result != SUIT_SUCCESS) {
        printf("callback : error = %s(%d)\n", suit_err_to_str(result), result);
        printf("callback : suppress it for testing.\n\n");
        result = SUIT_SUCCESS;
    }
    
    return result;
}

suit_err_t store_component(const char *dst,
                           UsefulBufC src,
                           UsefulBufC encryption_info,
                           suit_mechanism_t mechanisms[],
                           const suit_component_metadata_t *component_metadata)
{
    suit_err_t result = SUIT_SUCCESS;
    UsefulBuf decrypted_payload_buf = NULLUsefulBuf;

#if !defined(LIBCSUIT_DISABLE_PARAMETER_ENCRYPTION_INFO)
    if (!UsefulBuf_IsNULLOrEmptyC(encryption_info)) {
        decrypted_payload_buf.ptr = malloc(SUIT_MAX_DATA_SIZE);
        decrypted_payload_buf.len = SUIT_MAX_DATA_SIZE;
        UsefulBufC tmp = NULLUsefulBufC;
        for (size_t i = 0; i < SUIT_MAX_KEY_NUM; i++) {
            result = suit_decrypt_cose_encrypt(src, encryption_info, decrypted_payload_buf, &mechanisms[i], &tmp);
            if (result == SUIT_SUCCESS) {
                break;
            }
        }
        if (result != SUIT_SUCCESS || UsefulBuf_IsNULLOrEmptyC(tmp)) {
            result = SUIT_ERR_FAILED_TO_DECRYPT;
            goto out;
        }
        src = tmp;
    }
#endif /* LIBCSUIT_DISABLE_PARAMETER_ENCRYPTION_INFO */

#if !defined(LIBCSUIT_DISABLE_PARAMETER_COMPONENT_METADATA)
    ssize_t len = write_to_file_component_metadata(dst, src.ptr, src.len, component_metadata);
#else
    ssize_t len = suit_write_to_file(dst, src.ptr, src.len);
#endif
    if (len != src.len) {
        result = SUIT_ERR_FATAL;
        goto out;
    }
out:
    if (decrypted_payload_buf.ptr != NULL) {
        free(decrypted_payload_buf.ptr);
    }
    return result;
}

suit_err_t copy_component(const char *dst,
                          const char *src,
                          UsefulBufC encryption_info,
                          suit_mechanism_t mechanisms[],
                          suit_component_metadata_t *component_metadata)
{
    UsefulBuf buf;
    buf.ptr = malloc(SUIT_MAX_DATA_SIZE);
    if (buf.ptr == NULL) {
        return SUIT_ERR_NO_MEMORY;
    }
    buf.len = SUIT_MAX_DATA_SIZE;
    size_t len = suit_read_from_file(src, buf.ptr, buf.len);
    if (len >= buf.len) {
        return SUIT_ERR_NO_MEMORY;
    }
    buf.len = len;
    suit_err_t result = store_component(dst, UsefulBuf_Const(buf), encryption_info, mechanisms, component_metadata);
    free(buf.ptr);
    return result;
}

suit_err_t swap_component(const char *dst,
                          const char *src)
{
    char tmp[SUIT_MAX_NAME_LENGTH];
    size_t len = snprintf(tmp, SUIT_MAX_NAME_LENGTH, "%s.tmp", dst);
    if (len == SUIT_MAX_NAME_LENGTH) {
        return SUIT_ERR_NO_MEMORY;
    }
    if (rename(tmp, dst) != 0 || rename(dst, src) != 0 || rename(src, tmp)) {
        return SUIT_ERR_FATAL;
    }
    return SUIT_SUCCESS;
}

suit_err_t __wrap_suit_store_callback(suit_store_args_t store_args)
{
    suit_err_t result = SUIT_SUCCESS;

    char dst[SUIT_MAX_NAME_LENGTH];
    ssize_t len = suit_prefix_filename(dst, sizeof(dst));
    if (len < 0) {
        return SUIT_ERR_NO_MEMORY;
    }
    char *tmp_filename = &dst[len];
    result = suit_component_identifier_to_filename(&store_args.dst, SUIT_MAX_NAME_LENGTH, tmp_filename);
    if (result != SUIT_SUCCESS) {
        return result;
    }
    switch (store_args.operation) {
    case SUIT_STORE:
        result = store_component(dst, store_args.src_buf, store_args.encryption_info, store_args.mechanisms, &store_args.component_metadata);
        break;
    case SUIT_COPY:
    case SUIT_SWAP:
    case SUIT_UNLINK:
    default:
        result = SUIT_ERR_NOT_IMPLEMENTED;
        break;
    }
    if (result != SUIT_SUCCESS) {
        printf("callback : error = %s(%d)\n", suit_err_to_str(result), result);
    }
    
    return result;
}
