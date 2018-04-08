/**
 * Set 1 Challenge 3 - Single-byte XOR cipher
 * https://www.cryptopals.com/sets/1/challenges/3
 *
 * An encoded hex string has been XOR'd against a single character. Find the
 * key, decrypt the message.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "util/hex.h"
#include "util/xor.h"

static int
set1_challenge3(const char *in, char **out)
{
	int rc;
	uint8_t key;
	uint8_t *bytes;
	size_t bytes_size;
	char *plaintext;

	assert(in != NULL);
	assert(out != NULL);

	rc = hexstr_to_bytes(in, &bytes, &bytes_size);
	if (rc < 0) {
		goto err0;
	}

	rc = break_single_byte_xor(bytes, bytes_size, &key);
	if (rc < 0) {
		goto err1;
	}

	rc = single_byte_xorstr(bytes, bytes_size, key, &plaintext);
	if (rc < 0) {
		goto err1;
	}

	free(bytes);

	*out = plaintext;

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
	const char *ciphertext;
	char *plaintext;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [HEX]\n", argv[0]);
		goto err0;
	} else if (argc == 2) {
		ciphertext = argv[1];
	} else {
		ciphertext = "1b37373331363f78151b7f2b783431333d"
			     "78397828372d363c78373e783a393b3736";
	}

	rc = set1_challenge3(ciphertext, &plaintext);
	if (rc < 0) {
		fprintf(stderr, "Single byte XOR failed.\n");
		goto err0;
	}

	printf("%s\n", plaintext);

	free(plaintext);

	exit(EXIT_SUCCESS);

err0:
	exit(EXIT_FAILURE);
}
