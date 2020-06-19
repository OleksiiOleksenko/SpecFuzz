/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/opensslconf.h>
#include "fuzzer.h"

#ifndef OPENSSL_NO_FUZZ_LIBFUZZER

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return FuzzerInitialize(argc, argv);
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    return FuzzerTestOneInput(buf, len);
}

#elif !defined(OPENSSL_NO_FUZZ_AFL)

#define BUF_SIZE 65536

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Exactly one argument is expected.\n");
        exit(EXIT_FAILURE);
    }

    FILE* f = fopen(argv[1], "r");
    if (!f) {
        fprintf(stderr, "Failed to open input file.");
        exit(EXIT_FAILURE);
    }

    uint8_t *buf = malloc(BUF_SIZE);
    size_t size = 0;

    size = fread(buf, 1, BUF_SIZE, f);
    if (ferror(f)) {
        fclose(f);
        fprintf(stderr, "Failed read input file.");
        exit(EXIT_FAILURE);
    }

    FuzzerInitialize(&argc, &argv);
    FuzzerTestOneInput(buf, size);

    free(buf);
    fclose(f);
    FuzzerCleanup();
    return 0;
}

#else

#error "Unsupported fuzzer"

#endif
