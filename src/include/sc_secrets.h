/*
 * sc_secrets.h
 *
 * Copyright (C) 2023 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */
#pragma once

#include "sc_socket.h"

#include <stdint.h>

uint8_t*
sc_parse_json(const char* json_buf, size_t* size_r);

char*
sc_request_secret(sc_socket* sock, const char* rsrc_sub, uint32_t rsrc_sub_len, const char* secret_key, uint32_t secret_key_len, int timeout_ms);
