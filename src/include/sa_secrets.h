/*
 * Copyright 2008-2023 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#pragma once

#include "sa_error.h"
#include "sa_socket.h"

#include <stdint.h>

uint8_t* sa_parse_json(const char* json_buf, size_t* size_r);

sa_err sa_request_secret(char** resp, sa_socket* sock, const char* rsrc_sub, uint32_t rsrc_sub_len, const char* secret_key, uint32_t secret_key_len, int timeout_ms);
