/*
 * sc_logging.h
 *
 * Copyright (C) 2023 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */
#pragma once

typedef void sc_log_func(const char* format, ...);

extern sc_log_func* sc_g_log_function;

void sc_set_log_function(sc_log_func* f);

void sc_default_logger(const char* format, ...);