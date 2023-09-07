/*
 * tls.h
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

void init_openssl();

// return of < 0 == failure
int wrap_socket(sc_socket* sock);

// return of < 0 == failure
int tls_connect(sc_socket* sock, int timeout_ms);

// return of < 0 == failure
int tls_read_n_bytes(sc_socket* sock, void* buf, size_t len, int timeout_ms);

// return of < 0 == failure
int tls_write(sc_socket* sock, void* bufp, size_t len, int timeout_ms);