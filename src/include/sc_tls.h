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

#include "sc_error.h"
#include "sc_socket.h"

void sc_init_openssl();

/*
 * sc_wrap_socket creates an SSL context
 * for the sc_socket
 * SUCCESS: 0 is returned.
 * FAILURE: A value other than 0 is returned.
*/
int sc_wrap_socket(sc_socket* sock);

/*
 * sc_tls_connect attempts to perform a tls
 * connection over sock for timeout_ms milliseconds.
*/
sc_err sc_tls_connect(sc_socket* sock, int timeout_ms);

/*
 * sc_tls_read_n_bytes reads n bytes from
 * tls connected socket.
*/
sc_err sc_tls_read_n_bytes(sc_socket* sock, size_t len, void* buf, int timeout_ms);

/*
 * sc_tls_write_n_bytes reads n bytes from
 * tls connected socket.
*/
sc_err sc_tls_write_n_bytes(sc_socket* sock, size_t len, void* buf, int timeout_ms);