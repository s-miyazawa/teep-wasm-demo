/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef SUIT_EXAMPLES_COMMON_H
#define SUIT_EXAMPLES_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "csuit/suit_common.h"

ssize_t suit_read_from_file(const char *file_path, uint8_t *buf, const size_t buf_len);
ssize_t suit_write_to_file(const char *file_path, const void *buf, const size_t buf_len);
ssize_t write_to_file_component_metadata(const char *file_path,
                                         const void *buf,
                                         const size_t buf_len,
                                         const suit_component_metadata_t *component_metadata);

#endif  /* SUIT_EXAMPLES_COMMON_H */