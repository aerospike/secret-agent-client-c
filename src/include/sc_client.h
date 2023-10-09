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
#include "sc_logging.h"
#include "sc_socket.h"

#include <stdbool.h>

/*
 * sc_client.h and the files included here define the secrets-client-c API.
 * This should be the only file included when using secrets-client-c.
*/

// TODO use this on public functions and hide the rest #define SC_PUBLIC_API __attribute__ ((visibility ("default")))

#define SC_SECRETS_PATH_REFIX "secrets:"

/*
 * sc_cfg defines the configuration for the secret client sc_client.
 * sc_cfg should be initialised using sc_cfg_init or sc_cfg_new
 * before it is used.
*/
typedef struct sc_cfg_s
{
	char* addr; // address of the secret agent
	char* port; // port the secret agent is running on
	int timeout; // timeout in milliseconds
	sc_tls_cfg tls; // tls configuration
} sc_cfg;

/*
 * sc_client is used to request secrets from the secret agent
 * sc_client should be used with an initialised sc_cfg.
 * sc_client is itself initialised using sc_client_init()
 * or sc_client_new()
*/
typedef struct sc_client_s {
	sc_cfg* cfg;
} sc_client;

/*
 * sc_client_init initialises a stack allocated sc_client.
 * cfg should be an initialised sc_cfg.
*/
sc_client*
sc_client_init(sc_client* c, sc_cfg* cfg);

/*
 * sc_client_new creates and initialises a heap allocated sc_client.
 * cfg should be an initialised sc_cfg.
*/
sc_client*
sc_client_new(sc_cfg* cfg);

/*
 * sc_secret_get_bytes requests a secret from the secret agent.
 * c should be a pointer to an initialised sc_client.
 * path is the secret path, the format is, "secrets:<resource_key>:<secret_key>".
 * r is a result parameter, which is filled in with the secret value.
 * size_r is a result parameter, which is filled in with the size of the secret value.
 * Return value is an sc_err, set to SC_OK on success and any other value on failure.
*/
sc_err
sc_secret_get_bytes(const sc_client* c, const char* path, uint8_t** r, size_t* size_r);

/*
 * sc_cfg_init initialises a stack allocated sc_cfg.
*/
sc_cfg*
sc_cfg_init(sc_cfg* cfg);

/*
 * sc_cfg_new creates and initialises a heap allocated sc_cfg.
*/
sc_cfg*
sc_cfg_new();