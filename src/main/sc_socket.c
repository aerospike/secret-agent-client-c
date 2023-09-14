/*
 * secrets.c
 *
 * Copyright (C) 2023 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

#include "sc_socket.h"
#include "sc_tls.h"
#include "sc_logging.h"

#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>

//==========================================================
// Forward Declarations.
//

int _read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);
int _write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);

//==========================================================
// Public API.
//

int read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    if (sock->tls_cfg->enabled) {
        return tls_read_n_bytes(sock, buffer, n, timeout_ms);
    }
    else {
        return _read_n_bytes(sock, n, buffer, timeout_ms);
    }
}

// This assumes buffer is at least n bytes long
int write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    if (sock->tls_cfg->enabled) {
        return tls_write(sock, buffer, n, timeout_ms);
    }
    else {
        int res = _write_n_bytes(sock, n, buffer, timeout_ms);
        if (res == 0) {
            return -1;
        }
        return res;
    }
}

sc_socket* 
connect_addr_port(const char* addr, const char* port, const sc_tls_cfg* tls_cfg, int timeout_ms)
{
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0)
	{
		sc_g_log_function("ERR: could not create socket returned: %d", sock_fd);
		return NULL;
	}

    int fcntl_res = fcntl(sock_fd, F_SETFL, O_NONBLOCK);
    if (fcntl_res < 0) {
        sc_g_log_function("ERR: could not set socket to non-blocking: %d", fcntl_res);
        return NULL;
    }

    struct sockaddr_in sc_addr = { 0 };

    long port_num = strtol(port, NULL, 10);
    // this assumes in_port_t is unsigned
    if (port_num > (in_port_t) -1) {
		sc_g_log_function("ERR: port: %d is larger than max in_port_t", port_num);
        close(sock_fd);
		return NULL;
    }

    in_port_t sin_port = (in_port_t) port_num;
    if (sin_port < 1 || sin_port > 65535) {
		sc_g_log_function("ERR: port: %d is outside the valid port range 1 - 65535", sin_port);
        close(sock_fd);
		return NULL;
    }

    sin_port = htons(sin_port);
    sc_addr.sin_port = sin_port;

	sc_addr.sin_family = AF_INET;

	if (inet_pton(AF_INET, addr, &sc_addr.sin_addr)<=0) {
		sc_g_log_function("ERR: address: %s:%s is an invalid AF_INET address", addr, port);
        close(sock_fd);
		return NULL;
	}

    // must be freed by caller
    sc_socket* sock = (sc_socket*) malloc(sizeof(sc_socket));
    sock->fd = sock_fd;

    int connect_res = connect(sock_fd, (struct sockaddr *)&sc_addr, sizeof(sc_addr));

    // connect may return -1 because the socket is non blocking and the connection is not finished
    // if errno == EINPROGRESS, this is the case, and the socket should be ready for use later
    if (connect_res < 0 && errno != EINPROGRESS) {
		sc_g_log_function("ERR: connect failed: %d, errno: %d", connect_res, errno);
        close(sock_fd);
        free(sock);
		return NULL;
    }

    sock->tls_cfg = tls_cfg;
    if (tls_cfg->enabled) {
        init_openssl();
        wrap_socket(sock);
        connect_res = tls_connect(sock, timeout_ms);

        if (connect_res < 0) {
            sc_g_log_function("ERR: tls connection failed: %d", connect_res);
            close(sock_fd);
            free(sock);
            return NULL;
        }
    }

	return sock; 
}

// return of <= 0 == failure
int
socket_wait(sc_socket* sock, int timeout_ms, bool read, short* poll_res)
{
	int rv;
    short events = POLLOUT;

    if (read) {
        events = POLLIN;
    }

    struct pollfd pfd = {
        .fd = sock->fd,
        .events = events
    };

    rv = poll(&pfd, 1, (int)timeout_ms);

	if (rv == 0) {
		sc_g_log_function("ERR: socket poll timed out");
		return rv;
	}
	else if (rv < 0) {
		sc_g_log_function("ERR: socket poll err: %d, errno: %d", rv, errno);
		return rv;
	}

    *poll_res = pfd.revents;

	int socket_ready = 0;
	if (read) {
		socket_ready = *poll_res & POLLIN;
	}
	else {
		socket_ready = *poll_res & POLLOUT;
	}

    if (!socket_ready) {
		sc_g_log_function("ERR: no sockets ready, revent: %d", pfd.revents);
        rv = -1;
    }

    return rv;
}

sc_tls_cfg*
sc_tls_cfg_init(sc_tls_cfg* cfg) {
    cfg->ca_string = NULL;
    cfg->enabled = false;
    return cfg;
}

sc_tls_cfg*
sc_tls_cfg_new() {
    sc_tls_cfg* cfg = (sc_tls_cfg*) malloc(sizeof(sc_tls_cfg));
    sc_tls_cfg_init(cfg);
    return cfg;
}

//==========================================================
// Private Helpers.
//

int _read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    int bytes_read = 0;
    int result = 0;
    short poll_res = 0;
    while (true)
    {
        result = socket_wait(sock, timeout_ms, true, &poll_res);
        if (result <= 0) {
            sc_g_log_function("ERR: socket poll failed on read, return value: %d, revent: %d, errno: %d", result, poll_res, errno);
            return result;
        }

        result = read(sock->fd, buffer + bytes_read, n - bytes_read);
        if (result < 0 ) {
            sc_g_log_function("ERR: socket read failed, return value: %d, errno: %d", result, errno);
            return result;
        }

        if (result == 0) {
            // end of transmission
            return result;
        }

        bytes_read += result;
        if (bytes_read >= n) {
            return result;
        }
    }
}

int _write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    int bytes_written = 0;
    int result = 0;
    short poll_res = 0;
    while (true)
    {
        result = socket_wait(sock, timeout_ms, false, &poll_res);
        if (result <= 0) {
            sc_g_log_function("ERR: socket poll failed on write, return value: %d, revent: %d, errno: %d", result, poll_res, errno);
            return result;
        }

        result = write(sock->fd, buffer + bytes_written, n - bytes_written);
        if (result < 0 )
        {
            sc_g_log_function("ERR: socket write failed, return value: %d, errno: %d", result, errno);
            return result;
        }

        bytes_written += result;
        if (bytes_written >= n) {
            return result;
        }
    }
}