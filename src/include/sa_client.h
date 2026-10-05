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
#include "sa_logging.h"
#include "sa_socket.h"

#include <stdbool.h>

/*
 * sa_client.h and the files included here define the secret-agent-client-c API.
 * This should be the only file included when using secret-agent-client-c.
*/

// TODO use this on public functions and hide the rest #define SA_PUBLIC_API __attribute__ ((visibility ("default")))

#define SA_SECRETS_PATH_REFIX "secrets:"

/*
 * sa_cfg defines the configuration for the secret client sa_client.
 * sa_cfg should be initialised using sa_cfg_init or sa_cfg_new
 * before it is used.
*/
typedef struct sa_cfg_s
{
	char* addr; // address of the secret agent
	char* port; // port the secret agent is running on
	int timeout; // timeout in milliseconds
	sa_tls_cfg tls; // tls configuration
} sa_cfg;

/*
 * sa_client is used to request secrets from the secret agent
 * sa_client should be used with an initialised sa_cfg.
 * sa_client is itself initialised using sa_client_init()
 * or sa_client_new()
*/
typedef struct sa_client_s {
	sa_cfg* cfg;
} sa_client;

/*
 * sa_client_init initialises a stack allocated sa_client.
 * cfg should be an initialised sa_cfg.
*/
sa_client*
sa_client_init(sa_client* c, sa_cfg* cfg);

/*
 * sa_client_new creates and initialises a heap allocated sa_client.
 * cfg should be an initialised sa_cfg.
*/
sa_client*
sa_client_new(sa_cfg* cfg);

/*
 * sa_secret_get_bytes requests a secret from the secret agent.
 * c should be a pointer to an initialised sa_client.
 * path is the secret path, the format is, "secrets:<resource_key>:<secret_key>".
 * r is a result parameter, which is filled in with the secret value.
 * On success, r is heap allocated. The caller is responsible for freeing r.
 * size_r is a result parameter, which is filled in with the size of the secret value.
 * Return value is an sa_err, set to SA_OK on success and any other value on failure.
*/
sa_err
sa_secret_get_bytes(const sa_client* c, const char* path, uint8_t** r, size_t* size_r);

/*
 * sa_cfg_init initialises a stack allocated sa_cfg.
*/
sa_cfg*
sa_cfg_init(sa_cfg* cfg);

/*
 * sa_cfg_new creates and initialises a heap allocated sa_cfg.
*/
sa_cfg*
sa_cfg_new();