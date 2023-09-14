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

#include "sc_secrets.h"
#include "sc_socket.h"
#include "sc_logging.h"
#include "sc_client.h"
#include "sc_error.h"

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

#include "jansson.h"

//==========================================================
// Public API.
//

sc_client*
sc_client_init(sc_client* c, sc_cfg* cfg) {
	c->cfg = cfg;
	return c;
}

sc_client*
sc_client_new(sc_cfg* cfg) {
	sc_client* c = (sc_client*) malloc(sizeof(sc_client));
	return sc_client_init(c, cfg);
}

sc_err
sc_secret_get_bytes(const sc_client* c, const char* path, uint8_t** r, size_t* size_r) {
	sc_err err = { 0 };
    sc_cfg* cfg = c->cfg;

	// path format will be "secrets[:resource_substring]:key"
	const char* suffix = path + sizeof(SC_SECRETS_PATH_REFIX) - 1;
	uint32_t suffix_len = (uint32_t)strlen(suffix);

	if (suffix_len == 0) {
		sc_g_log_function("ERR: empty secret key");
		err.code = SC_FAILED_INTERNAL;
		return err;
	}

	const char* res = NULL;
	uint32_t res_len = 0;
	const char* key = strrchr(suffix, ':');

	if (key == NULL) {
		// no resource name
		key = suffix;
	}
	else {
		res = suffix;
		res_len = (uint32_t)(key - suffix);
		key++;
	}

    sc_socket* sock = connect_addr_port(cfg->addr, cfg->port, &cfg->tls, cfg->timeout);

	if (sock == NULL) {
		sc_g_log_function("ERR: failed to create socket");
		err.code = SC_FAILED_INTERNAL;
		return err;
	}

	uint32_t key_len = (uint32_t)strlen(key);
    char* json_buf = sc_request_secret(sock, res, res_len, key, key_len, cfg->timeout);

	close(sock->fd);
	free(sock);

	if (json_buf == NULL) {
		sc_g_log_function("ERR: empty secret json response");
		err.code = SC_FAILED_REQUEST;
		return err;
	}

	uint8_t* buf = sc_parse_json(json_buf, size_r);
	free(json_buf);

	if (buf == NULL) {
		sc_g_log_function("ERR: unable to fetch secret");
		err.code = SC_FAILED_REQUEST;
		return err;
	}

	*r = buf;
	return err;
}

sc_cfg*
sc_cfg_init(sc_cfg* cfg) {
	cfg->addr = NULL;
	cfg->port = NULL;
	cfg->timeout = 1000;
	sc_tls_cfg_init(&cfg->tls);
	return cfg;
}

sc_cfg*
sc_cfg_new() {
	sc_cfg* cfg = (sc_cfg*) malloc(sizeof(sc_cfg));
	return sc_cfg_init(cfg);
}