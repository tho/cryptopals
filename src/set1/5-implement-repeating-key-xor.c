/**
 * Set 1 Challenge 5 - Implement repeating-key XOR
 * https://www.cryptopals.com/sets/1/challenges/5
 *
 * In repeating-key XOR, each byte of a given key will be applied sequentially
 * to all bytes of the plaintext. If the plaintext is longer than the key the
 * key will be re-used as often as necessary.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/common.h"
#include "util/hex.h"
#include "util/xor.h"

static int
set1_challenge5(FILE *ifp, const char *key, FILE *ofp)
{
	int rc;
	uint8_t *buffer, *bytes;
	size_t buffer_size, num_items;
	char *hexstr;

	assert(ifp != NULL);
	assert(key != NULL);
	assert(ofp != NULL);

	/* Buffer size must be a multiple of the key length. 8 is arbitrary. */
	buffer_size = 8 * strlen(key);
	buffer = malloc(buffer_size * sizeof(*buffer));
	if (buffer == NULL) {
		goto err0;
	}

	bytes = NULL;
	hexstr = NULL;
	while ((num_items = fread(buffer, 1, buffer_size, ifp)) > 0) {
		rc = repeating_key_xor(buffer, num_items,
				       (const uint8_t *)key, strlen(key),
				       &bytes);
		if (rc < 0) {
			goto err1;
		}

		rc = bytes_to_hexstr(bytes, num_items, &hexstr);
		if (rc < 0) {
			free(bytes);
			goto err1;
		}

		fprintf(ofp, "%s", hexstr);

		free(bytes);
		free(hexstr);
	}
	if (ferror(ifp)) {
		perror("fread");
		goto err1;
	}

	free(buffer);

	return 0;

err1:
	free(buffer);
err0:
	return -1;
}

int
main(int argc, char *argv[])
{
	int rc;
	const char *key, *filename;
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
		key = "ICE";
		filename = "./share/cryptopals/5.txt";
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

	rc = set1_challenge5(ifp, key, stdout);
	if (rc < 0) {
		fprintf(stderr, "Repeating key XOR failed.\n");
		goto err1;
	}
	fputc('\n', stdout);

	fclose(ifp);

	exit(EXIT_SUCCESS);

err1:
	fclose(ifp);
err0:
	exit(EXIT_FAILURE);
}
