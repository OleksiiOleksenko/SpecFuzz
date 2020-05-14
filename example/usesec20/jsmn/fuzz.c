#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "jsmn.h"

/*
 * Read JSON from a file and printing its content to stdout.
 * The output looks like YAML, but I'm not sure if it's really compatible.
 */

static int dump(const char *js, jsmntok_t *t, size_t count, int indent) {
	int i, j, k;
	if (count == 0) {
	    printf("No tokens\n");
		return 0;
	}
	if (t->type == JSMN_PRIMITIVE) {
		printf("%.*s", t->end - t->start, js+t->start);
		return 1;
	} else if (t->type == JSMN_STRING) {
		printf("'%.*s'", t->end - t->start, js+t->start);
		return 1;
	} else if (t->type == JSMN_OBJECT) {
		printf("\n");
		j = 0;
		for (i = 0; i < t->size; i++) {
			for (k = 0; k < indent; k++) printf("  ");
			j += dump(js, t+1+j, count-j, indent+1);
			printf(": ");
			j += dump(js, t+1+j, count-j, indent+1);
			printf("\n");
		}
		return j+1;
	} else if (t->type == JSMN_ARRAY) {
		j = 0;
		printf("\n");
		for (i = 0; i < t->size; i++) {
			for (k = 0; k < indent-1; k++) printf("  ");
			printf("   - ");
			j += dump(js, t+1+j, count-j, indent+1);
			printf("\n");
		}
		return j+1;
	}
	return 0;
}

#define MAX_TOKENS 1000 * 1024
jsmntok_t tokens[MAX_TOKENS];

#define MAX_DATA 500 * 1024 * 1024
static char data[MAX_DATA];

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

    int r;
    int tok_count = 0;
	jsmn_parser p;

    jsmn_init(&p);
    tok_count = jsmn_parse(&p, data, data_len, NULL, 1);
    if (tok_count < 0) {
        printf("Parsing error %d\n", tok_count);
        return 1;
    }
    if (tok_count >= MAX_TOKENS) {
        printf("Too many tokens");
        return 0;
    }
//    printf("Token count %d\n", tok_count);

    jsmn_init(&p);
    r = jsmn_parse(&p, data, data_len, tokens, tok_count);
    if (r == JSMN_ERROR_NOMEM) {
        printf("Out of memory\n");
        return 1;
    } else if (r < 0) {
        printf("Parsing error %d\n", tok_count);
        return 1;
    }

	return EXIT_SUCCESS;
}
