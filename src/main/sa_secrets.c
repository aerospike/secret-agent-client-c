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

#include "sa_b64.h"
#include "sa_error.h"
#include "sa_secrets.h"
#include "sa_socket.h"
#include "sa_logging.h"

#include <assert.h>
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
// Typedefs & constants.
//

#define SA_HEADER_SIZE 8
#define SA_MAGIC 0x51dec1cc // "sidekick" in hexspeak
#define SA_MAX_RECV_JSON_SIZE (100 * 1024) // 100KB

//==========================================================
// Globals.
//

static const char TRAILING_WHITESPACE[] = " \t\n\r\f\v";

//==========================================================
// Public API.
//

sa_err
sa_request_secret(char** resp, sa_socket* sock, const char* rsrc_substr, uint32_t rsrc_substr_len,
		const char* secret_key, uint32_t secret_key_len, int timeout_ms)
{
	sa_err err;
	err.code = SA_OK;

	char req[100 + rsrc_substr_len + secret_key_len];
	char* json = &req[SA_HEADER_SIZE]; // json starts after 8 byte header

	if (rsrc_substr_len == 0) {
		sprintf(json, "{\"SecretKey\":\"%.*s\"}", secret_key_len, secret_key);
	}
	else {
		sprintf(json,
				"{\"Resource\":\"%.*s\",\"SecretKey\":\"%.*s\"}",
				rsrc_substr_len, rsrc_substr, secret_key_len, secret_key);
	}

	uint32_t json_sz = (uint32_t)strlen(json);

	assert(SA_HEADER_SIZE + json_sz <= sizeof(req));

	*(uint32_t*)&req[0] = ntohl(SA_MAGIC);
	*(uint32_t*)&req[4] = ntohl(json_sz);

	err = sa_write_n_bytes(sock, SA_HEADER_SIZE + json_sz, req, timeout_ms);
	if (err.code != SA_OK) {
		sa_g_log_function("ERR: failed asking for secret - %s", req);
		return err;
	}

	char header[SA_HEADER_SIZE];

	err = sa_read_n_bytes(sock, SA_HEADER_SIZE, header, timeout_ms);
	if (err.code != SA_OK) {
		sa_g_log_function("ERR: failed reading secret header, errno: %d", errno);
		return err;
	}

	uint32_t recv_magic = ntohl(*(uint32_t*)&header[0]);

	if (recv_magic != SA_MAGIC) {
		sa_g_log_function("ERR: bad magic - %x", recv_magic);
		err.code = SA_FAILED_INTERNAL;
		return err;
	}

	uint32_t recv_json_sz = ntohl(*(uint32_t*)&header[4]);

	if (recv_json_sz > SA_MAX_RECV_JSON_SIZE) {
		sa_g_log_function("ERR: response too big - %d", recv_json_sz);
		err.code = SA_FAILED_INTERNAL;
		return err;
	}

	char *recv_json = malloc(recv_json_sz + 1);

	err = sa_read_n_bytes(sock, recv_json_sz, recv_json, timeout_ms);
	if (err.code != SA_OK) {
		sa_g_log_function("ERR: failed reading secret errno: %d", errno);
		return err;
	}

	recv_json[recv_json_sz] = '\0';
	*resp = recv_json;

	return err;
}

uint8_t*
sa_parse_json(const char* json_buf, size_t* size_r)
{
	if (json_buf == NULL) {
		return NULL;
	}

	json_error_t err;

	json_t* doc = json_loads(json_buf, 0, &err);

	if (doc == NULL) {
		sa_g_log_function("ERR: failed to parse response JSON line %d (%s)",
				err.line, err.text);
		return NULL;
	}

	const char* payload_str;
	size_t payload_len;

	int unpack_err = json_unpack(doc, "{s:s%}", "Error", &payload_str,
			&payload_len);

	// If secret agent faced an error it will convey the reason.
	if (unpack_err == 0) {
		sa_g_log_function("ERR: response: %.*s",
				(int)payload_len, payload_str);
		json_decref(doc);
		return NULL;
	}

	unpack_err = json_unpack(doc, "{s:s%}", "SecretValue", &payload_str,
			&payload_len);

	if (unpack_err != 0) {
		sa_g_log_function("ERR: failed to find \"SecretValue\" in response");
		json_decref(doc);
		return NULL;
	}

	if (payload_len == 0) {
		sa_g_log_function("ERR: empty secret");
		json_decref(doc);
		return NULL;
	}

	while (strchr(TRAILING_WHITESPACE, payload_str[payload_len - 1]) != NULL) {
		payload_len--;

		if (payload_len == 0) {
			sa_g_log_function("ERR: whitespace-only secret");
			json_decref(doc);
			return NULL;
		}
	}

	// Extra byte - if this is a string, the caller will add '\0'.
	uint32_t size = sa_b64_decoded_buf_size((uint32_t)payload_len) + 1;

	uint8_t* buf = malloc(size);

	if (! sa_b64_validate_and_decode(payload_str, (uint32_t)payload_len, buf,
			&size)) {
		sa_g_log_function("ERR: failed to base64-decode secret");
		free(buf);
		json_decref(doc);
		return NULL;
	}

	json_decref(doc);

	*size_r = size;
	return buf;
}