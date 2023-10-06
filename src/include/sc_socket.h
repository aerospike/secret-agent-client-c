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

sc_socket* connect_addr_port(const char* addr, const char* port, sc_tls_cfg* tls_cfg, int timeout_ms);

int read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);

// This assumes buffer is at least n bytes long,
int write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);

// return of <= 0 == failure
int socket_wait(sc_socket* sock, int timeout_ms, bool read, short* poll_res);

sc_tls_cfg* sc_tls_cfg_init(sc_tls_cfg* cfg);

sc_tls_cfg* sc_tls_cfg_new();