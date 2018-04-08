/**
 * Set 1 Challenge 1 - Convert hex to base64
 * https://www.cryptopals.com/sets/1/challenges/1
 *
 * Convert a hex string to a base 64 string.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "util/base64.h"
#include "util/hex.h"

static int
set1_challenge1(const char *in, char **out)
{
	int rc;
	uint8_t *bytes;
	size_t bytes_size;
	char *base64str;

	assert(in != NULL);
	assert(out != NULL);

	rc = hexstr_to_bytes(in, &bytes, &bytes_size);
	if (rc < 0) {
		goto err0;
	}

	rc = bytes_to_base64str(bytes, bytes_size, &base64str);
	if (rc < 0) {
		goto err1;
	}

	free(bytes);

	*out = base64str;

	return 0;

err1:
	free(bytes);
err0:
	*out = NULL;
	return -1;
}

int
main(int argc, char *argv[])
{
	int rc;
	const char *hexstr;
	char *base64str;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [HEX]\n", argv[0]);
		goto err0;
	} else if (argc == 2) {
		hexstr = argv[1];
	} else {
		hexstr = "49276d206b696c6c696e6720796f757220627261696e206c"
			 "696b65206120706f69736f6e6f7573206d757368726f6f6d";
	}

	rc = set1_challenge1(hexstr, &base64str);
	if (rc < 0) {
		fprintf(stderr, "Hex to base 64 failed.\n");
		goto err0;
	}

	printf("%s\n", base64str);

	free(base64str);

	exit(EXIT_SUCCESS);

err0:
	exit(EXIT_FAILURE);
}
