/* Copyright Fedor Indutny. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "http_parser.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_DATA 1024 * 1024
static char data[MAX_DATA];

static http_parser_settings settings = {
    .on_message_begin = 0,
    .on_headers_complete = 0,
    .on_message_complete = 0,
    .on_header_field = 0,
    .on_header_value = 0,
    .on_url = 0,
    .on_status = 0,
    .on_body = 0
};

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: fuzz <input file name>\n");
        return 1;
    }

    // fuzzers usually prefer to get input from a file
    FILE *fp;
    if (!(fp = fopen(argv[1], "r"))) {
        printf("Unable to open %s for reading\n", argv[1]);
        return 1;
    }

    size_t data_len;
    fseek(fp, 0, SEEK_END);
    data_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // skip super long inputs
    if (data_len >= MAX_DATA) {
        return 0;
    }

    fread(data, 1, data_len, fp);
    fclose(fp);

    http_parser *parser = malloc(sizeof(http_parser));
    http_parser_init(parser, HTTP_REQUEST);

    size_t parsed;
    parsed = http_parser_execute(parser, &settings, data, data_len);

    return 0;
}
