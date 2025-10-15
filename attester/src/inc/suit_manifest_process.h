#ifndef SUIT_CONDITION_CALLBACK_H_
#define SUIT_CONDITION_CALLBACK_H_


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "csuit/suit_common.h"


ssize_t suit_prefix_filename(char *buf, size_t buf_len);
suit_err_t suit_condition_image_match(const suit_component_identifier_t *dst,
                                      const suit_digest_t *image_digest,
                                      const uint64_t image_size,
                                      bool condition_match);
suit_err_t __real_suit_condition_callback(suit_condition_args_t condition_args);
suit_err_t __wrap_suit_condition_callback(suit_condition_args_t condition_args);

suit_err_t store_component(const char *dst,
                           UsefulBufC src,
                           UsefulBufC encryption_info,
                           suit_mechanism_t mechanisms[],
                           const suit_component_metadata_t *component_metadata);

suit_err_t copy_component(const char *dst,
                          const char *src,
                          UsefulBufC encryption_info,
                          suit_mechanism_t mechanisms[],
                          suit_component_metadata_t *component_metadata);

suit_err_t swap_component(const char *dst,
                          const char *src);
                          
suit_err_t __real_suit_store_callback(suit_store_args_t store_args);
suit_err_t __wrap_suit_store_callback(suit_store_args_t store_args);



#endif  /* SUIT_CONDITION_CALLBACK_H_ */


