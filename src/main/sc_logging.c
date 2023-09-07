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

#include "sc_logging.h"

//==========================================================
// Globals.
//

sc_log_func* sc_g_log_function = sc_default_logger;

//==========================================================
// Public API.
//

void
sc_set_log_function(sc_log_func* f)
{
	sc_g_log_function = f;
}

void 
sc_default_logger(const char* format, ...) {}