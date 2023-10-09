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

#include "sc_socket.h"

void sc_init_openssl();

// return of < 0 == failure
int sc_wrap_socket(sc_socket* sock);

// return of < 0 == failure
int sc_tls_connect(sc_socket* sock, int timeout_ms);

// return of < 0 == failure
int sc_tls_read_n_bytes(sc_socket* sock, void* buf, size_t len, int timeout_ms);

// return of < 0 == failure
int sc_tls_write(sc_socket* sock, void* bufp, size_t len, int timeout_ms);