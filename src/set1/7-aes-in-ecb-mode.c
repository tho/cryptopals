/**
 * Set 1 Challenge 7 - AES in ECB mode
 * https://www.cryptopals.com/sets/1/challenges/7
 *
 * The base 64 encoded content of a file has been encrypted via AES-128 in ECB
 * mode under the key "YELLOW SUBMARINE". Decrypt it.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/aes.h"
#include "util/base64.h"

static int
set1_challenge7(FILE *ifp, const char *key, char **out)
{
	int rc;
	uint8_t *ciphertext;
	size_t ciphertext_size;
	char *plaintext;

	assert(ifp != NULL);
	assert(key != NULL);
	assert(out != NULL);

	rc = base64file_to_bytes(ifp, &ciphertext, &ciphertext_size);
	if (rc < 0) {
		goto err0;
	}

	rc = aes_ecb_decrypt_str(ciphertext, ciphertext_size,
				 (const uint8_t *)key, strlen(key),
				 &plaintext);
	if (rc < 0) {
		goto err1;
	}

	free(ciphertext);

	*out = plaintext;

	return 0;

err1:
	free(ciphertext);
err0:
	*out = NULL;
	return -1;
}

int
main(int argc, char *argv[])
{
	int rc;
	const char *key, *filename;
	char *plaintext;
	FILE *ifp;

	if (argc > 3) {
		fprintf(stderr, "usage: %s [KEY] [FILE]\n", argv[0]);
		goto err0;
	} else if (argc == 3) {
		key = argv[1];
		filename = argv[2];
	} else if (argc == 2) {
		key = argv[1];
		filename = "-";
	} else {
		key = "YELLOW SUBMARINE";
		filename = "./share/cryptopals/7.txt";
	}

	if (strcmp(filename, "-") == 0) {
		ifp = stdin;
	} else {
		ifp = fopen(filename, "r");
		if (ifp == NULL) {
			perror(filename);
			goto err0;
		}
	}

	rc = set1_challenge7(ifp, key, &plaintext);
	if (rc < 0) {
		fprintf(stderr, "AES in ECB mode failed.\n");
		goto err1;
	}

	printf("%s\n", plaintext);

	free(plaintext);
	fclose(ifp);

	exit(EXIT_SUCCESS);

err1:
	fclose(ifp);
err0:
	exit(EXIT_FAILURE);
}
