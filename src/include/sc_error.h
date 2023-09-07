/*
 * sc_error.h
 *
 * Copyright (C) 2023 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */
#pragma once

enum sc_error_code {
    SC_OK,
    SC_FAILED_REQUEST,
    SC_FAILED_INTERNAL,
};

typedef struct sc_error_s
{
    enum sc_error_code code;
} sc_err;
