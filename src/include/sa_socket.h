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

#include <stdbool.h>

#include <openssl/ssl.h>

typedef struct sa_tls_cfg_s {
	char* ca_string;
	bool enabled;
} sa_tls_cfg;

typedef struct sa_socket_s {
	int fd;
	SSL* ssl;
	sa_tls_cfg* tls_cfg;
} sa_socket;

// destroys ssl and frees sock, does not close the socket
// associated with fd or destroy tls_cfg
void sa_socket_destroy(sa_socket* sock);

sa_err sa_connect_addr_port(sa_socket** sockp, const char* addr, const char* port, sa_tls_cfg* tls_cfg, int timeout_ms);

// This assumes buffer is at least n bytes long.
sa_err sa_read_n_bytes(sa_socket* sock, unsigned int n, void* buffer, int timeout_ms);

// This assumes buffer is at least n bytes long.
sa_err sa_write_n_bytes(sa_socket* sock, unsigned int n, void* buffer, int timeout_ms);

/*
 * sa_socket_wait waits for a socket to be
 * ready to read or write.
*/
sa_err sa_socket_wait(sa_socket* sock, int timeout_ms, bool read, short* poll_res);

sa_tls_cfg* sa_tls_cfg_init(sa_tls_cfg* cfg);

sa_tls_cfg* sa_tls_cfg_new();