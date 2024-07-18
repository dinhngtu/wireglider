/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <noise/protocol.h>

static const char *const error_strings[] = {
    "No error",
    "Out of memory",
    "Unknown identifier",
    "Unknown name",
    "MAC failure",
    "Not applicable",
    "System error",
    "Remote public key required",
    "Local keypair required",
    "Pre shared key required",
    "Invalid length",
    "Invalid parameter",
    "Invalid state",
    "Invalid nonce",
    "Invalid private key",
    "Invalid public key",
    "Invalid format",
    "Invalid signature",
    "END",
};
#define num_error_strings (sizeof(error_strings) / sizeof(error_strings[0]) - 1)

const char *noise_errstr(int err) {
    if (err == NOISE_ERROR_NONE)
        return error_strings[0];
    if (err < NOISE_ID('E', 1) || err >= NOISE_ID('E', num_error_strings))
        return 0;
    return error_strings[err - NOISE_ID('E', 0)];
}
