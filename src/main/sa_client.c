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

//==========================================================
// Includes.
//

#include "sa_secrets.h"
#include "sa_socket.h"
#include "sa_logging.h"
#include "sa_client.h"
#include "sa_error.h"

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

sa_client*
sa_client_init(sa_client* c, sa_cfg* cfg) {
	c->cfg = cfg;
	return c;
}

sa_client*
sa_client_new(sa_cfg* cfg) {
	sa_client* c = (sa_client*) malloc(sizeof(sa_client));
	return sa_client_init(c, cfg);
}

sa_err
sa_secret_get_bytes(const sa_client* c, const char* path, uint8_t** r, size_t* size_r) {
	sa_err err;
	err.code = SA_OK;

	sa_cfg* cfg = c->cfg;

	// path format will be "secrets[:resource_substring]:key"
	const char* secret_request = path + sizeof(SA_SECRETS_PATH_REFIX) - 1;
	uint32_t secret_request_len = (uint32_t)strlen(secret_request);

	if (secret_request_len == 0) {
		sa_g_log_function("ERR: empty secret key");
		err.code = SA_FAILED_BAD_REQUEST;
		return err;
	}

	const char* res = NULL;
	uint32_t res_len = 0;
	const char* key = strrchr(secret_request, ':');

	if (key == NULL) {
		// no resource name
		key = secret_request;
	}
	else {
		res = secret_request;
		res_len = (uint32_t)(key - secret_request);
		key++;
	}

	sa_socket* sock = NULL;
	err = sa_connect_addr_port(&sock, cfg->addr, cfg->port, &cfg->tls, cfg->timeout);
	if (err.code != SA_OK) {
		sa_g_log_function("ERR: failed to create socket");
		return err;
	}

	uint32_t key_len = (uint32_t)strlen(key);
	char* json_buf = NULL;
	err = sa_request_secret(&json_buf, sock, res, res_len, key, key_len, cfg->timeout);

	close(sock->fd);
	sa_socket_destroy(sock);

	if (err.code != SA_OK) {
		sa_g_log_function("ERR: empty secret json response");
		return err;
	}

	uint8_t* buf = sa_parse_json(json_buf, size_r);
	free(json_buf);

	if (buf == NULL) {
		sa_g_log_function("ERR: unable to fetch secret");
		err.code = SA_FAILED_BAD_REQUEST;
		return err;
	}

	*r = buf;
	return err;
}

sa_cfg*
sa_cfg_init(sa_cfg* cfg) {
	cfg->addr = NULL;
	cfg->port = NULL;
	cfg->timeout = 1000;
	sa_tls_cfg_init(&cfg->tls);
	return cfg;
}

sa_cfg*
sa_cfg_new() {
	sa_cfg* cfg = (sa_cfg*) malloc(sizeof(sa_cfg));
	return sa_cfg_init(cfg);
}