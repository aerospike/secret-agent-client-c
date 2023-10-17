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

#include <stdbool.h>

#include <openssl/ssl.h>

typedef struct sc_tls_cfg_s {
	char* ca_string;
	bool enabled;
} sc_tls_cfg;

typedef struct sc_socket_s {
	int fd;
	SSL* ssl;
	sc_tls_cfg* tls_cfg;
} sc_socket;

// destroys ssl and frees sock, does not close the socket
// associated with fd or destroy tls_cfg
void sc_socket_destroy(sc_socket* sock);

sc_err sc_connect_addr_port(sc_socket** sockp, const char* addr, const char* port, sc_tls_cfg* tls_cfg, int timeout_ms);

// This assumes buffer is at least n bytes long.
sc_err sc_read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);

// This assumes buffer is at least n bytes long.
sc_err sc_write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);

/*
 * sc_socket_wait waits for a socket to be
 * ready to read or write.
*/
sc_err sc_socket_wait(sc_socket* sock, int timeout_ms, bool read, short* poll_res);

sc_tls_cfg* sc_tls_cfg_init(sc_tls_cfg* cfg);

sc_tls_cfg* sc_tls_cfg_new();