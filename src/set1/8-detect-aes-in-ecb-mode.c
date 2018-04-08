/**
 * Set 1 Challenge 8 - Detect AES in ECB mode
 * https://cryptopals.com/sets/1/challenges/8
 *
 * A file contains a bunch of hex-encoded ciphertexts. One of them has been
 * encrypted with ECB. Detect it.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/aes.h"
#include "util/hex.h"
#include "util/xor.h"

static bool
is_ecb_mode(const uint8_t *bytes, size_t bytes_size)
{
	int rc;
	size_t i, j;
	const size_t block_size = AES_BLOCK_SIZE;

	assert(bytes != NULL);

	if (bytes_size < block_size * 2) {
		return false;
	}

	for (i = 0; i < bytes_size - block_size; i += block_size) {
		for (j = i + block_size; j < bytes_size; j += block_size) {
			rc = memcmp(&bytes[i], &bytes[j], block_size);
			if (rc == 0) {
				return true;
			}
		}
	}

	return false;
}

static int
set1_challenge8(FILE *ifp, char **out)
{
	int rc;
	uint8_t *bytes;
	ssize_t line_len;
	size_t line_cap, bytes_size;
	char *line, *hexstr;

	assert(ifp != NULL);
	assert(out != NULL);

	bytes = NULL;
	bytes_size = 0;
	line = NULL;
	while ((line_len = getline(&line, &line_cap, ifp)) > 0) {
		if (line[line_len - 1] == '\n') {
			line[--line_len] = '\0';
		}

		rc = hexstr_to_bytes(line, &bytes, &bytes_size);
		if (rc < 0) {
			goto err0;
		}

		if (is_ecb_mode(bytes, bytes_size)) {
			break;
		}

		free(bytes);
		bytes = NULL;
	}

	rc = bytes_to_hexstr(bytes, bytes_size, &hexstr);
	if (rc < 0) {
		goto err1;
	}

	free(bytes);

	*out = hexstr;

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
	const char *filename;
	char *hexstr;
	FILE *ifp;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [FILE]\n", argv[0]);
		goto err0;
	} else if (argc == 2) {
		filename = argv[1];
	} else {
		filename = "./share/cryptopals/8.txt";
	}

	ifp = fopen(filename, "r");
	if (ifp == NULL) {
		perror(filename);
		goto err0;
	}

	rc = set1_challenge8(ifp, &hexstr);
	if (rc < 0) {
		fprintf(stderr, "Detect AES in ECB mode failed.\n");
		goto err1;
	}

	printf("%s\n", hexstr);

	free(hexstr);
	fclose(ifp);

	exit(EXIT_SUCCESS);

err1:
	fclose(ifp);
err0:
	exit(EXIT_FAILURE);
}
