/**
 * Set 1 Challenge 2 - Fixed XOR
 * https://www.cryptopals.com/sets/1/challenges/2
 *
 * Write a function that takes two equal-length buffers and produces their XOR
 * combination.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/hex.h"
#include "util/xor.h"

static int
set1_challenge2(const char *in1, const char *in2, char **out)
{
	int rc;
	uint8_t *bytes1, *bytes2, *xor_bytes;
	size_t bytes_size;
	char *hexstr;

	assert(in1 != NULL);
	assert(in2 != NULL);
	assert(out != NULL);

	if (strlen(in1) != strlen(in2)) {
		goto err0;
	}

	rc = hexstr_to_bytes(in1, &bytes1, &bytes_size);
	if (rc < 0) {
		goto err0;
	}

	rc = hexstr_to_bytes(in2, &bytes2, &bytes_size);
	if (rc < 0) {
		goto err1;
	}

	rc = fixed_xor(bytes1, bytes2, bytes_size, &xor_bytes);
	if (rc < 0) {
		goto err2;
	}

	rc = bytes_to_hexstr(xor_bytes, bytes_size, &hexstr);
	if (rc < 0) {
		goto err3;
	}

	free(xor_bytes);
	free(bytes2);
	free(bytes1);

	*out = hexstr;

	return 0;

err3:
	free(xor_bytes);
err2:
	free(bytes2);
err1:
	free(bytes1);
err0:
	*out = NULL;
	return -1;
}

int
main(int argc, char *argv[])
{
	int rc;
	const char *hexstr1, *hexstr2;
	char *xorstr;

	if (argc != 1 && argc != 3) {
		fprintf(stderr, "usage: %s [HEX1 HEX2]\n", argv[0]);
		goto err0;
	} else if (argc == 3) {
		hexstr1 = argv[1];
		hexstr2 = argv[2];
	} else {
		hexstr1 = "1c0111001f010100061a024b53535009181c";
		hexstr2 = "686974207468652062756c6c277320657965";
	}

	rc = set1_challenge2(hexstr1, hexstr2, &xorstr);
	if (rc < 0) {
		fprintf(stderr, "Fixed XOR failed.\n");
		goto err0;
	}

	printf("%s\n", xorstr);

	free(xorstr);

	exit(EXIT_SUCCESS);

err0:
	exit(EXIT_FAILURE);
}
