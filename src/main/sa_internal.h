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

/*
 * Internal helpers shared by the library's source files.
 * This header is not installed with the public headers.
*/

#include <stdint.h>

/*
 * sa_deadline_ms returns the monotonic time in milliseconds
 * timeout_ms from now, or 0 (no deadline) if timeout_ms is negative.
*/
uint64_t sa_deadline_ms(int timeout_ms);

/*
 * sa_remaining_ms returns the milliseconds left before deadline_ms,
 * 0 once it has passed, or -1 if there is no deadline.
*/
int sa_remaining_ms(uint64_t deadline_ms);
