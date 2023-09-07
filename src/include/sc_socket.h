/*
 * sc_socket.h
 *
 * Copyright (C) 2023 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */
#pragma once

#include <stdbool.h>

#include <openssl/ssl.h>

typedef struct sc_tls_cfg_s {
    const char* ca_string;
} sc_tls_cfg;

typedef struct sc_socket_s {
    int fd;
    SSL* ssl;
    const sc_tls_cfg* tls_cfg;
} sc_socket;

sc_socket* connect_addr_port(const char* addr, const char* port, const sc_tls_cfg* tls_cfg, int timeout_ms);

int read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);

// This assumes buffer is at least n bytes long,
int write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);

// return of <= 0 == failure
int socket_wait(sc_socket* sock, int timeout_ms, bool read, short* poll_res);