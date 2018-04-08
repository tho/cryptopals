/**
 * Set 1 Challenge 4 - Detect single-character XOR
 * https://www.cryptopals.com/sets/1/challenges/4
 *
 * One of a list of stings in a file has been encrypted by single-character
 * XOR. Find it.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util/hex.h"
#include "util/xor.h"

static int
set1_challenge4(FILE *ifp, char **out)
{
	int rc;
	uint8_t key, tmp_key;
	uint8_t *bytes, *ciphertext, *tmp;
	ssize_t line_len;
	size_t line_cap, bytes_size, ciphertext_size, score, max_score;
	char *line, *plaintext;

	assert(ifp != NULL);
	assert(out != NULL);

	key = 0;
	bytes = ciphertext= NULL;
	ciphertext_size = max_score = 0;
	line = NULL;
	while ((line_len = getline(&line, &line_cap, ifp)) > 0) {
		if (line[line_len - 1] == '\n') {
			line[--line_len] = '\0';
		}

		rc = hexstr_to_bytes(line, &bytes, &bytes_size);
		if (rc < 0) {
			goto err0;
		}

		rc = break_single_byte_xor_score(bytes, bytes_size, &tmp_key,
						 &score);
		if (rc < 0) {
			goto err1;
		}

		if (score > max_score) {
			max_score = score;

			tmp = realloc(ciphertext, bytes_size);
			if (tmp == NULL) {
				goto err1;
			}
			memcpy(tmp, bytes, bytes_size);

			ciphertext = tmp;
			ciphertext_size = bytes_size;
			key = tmp_key;
		}

		free(bytes);
		bytes = NULL;
	}
	if (ferror(ifp)) {
		perror("getline");
		goto err1;
	}

	rc = single_byte_xorstr(ciphertext, ciphertext_size, key, &plaintext);
	if (rc < 0) {
		goto err1;
	}

	free(ciphertext);
	free(bytes);
	free(line);

	*out = plaintext;

	return 0;

err1:
	free(bytes);
err0:
	free(ciphertext);
	free(line);
	*out = NULL;
	return -1;
}

int
main(int argc, char *argv[])
{
	int rc;
	const char *filename;
	char *plaintext;
	FILE *ifp;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [FILE]\n", argv[0]);
		goto err0;
	} else if (argc == 2) {
		filename = argv[1];
	} else {
		filename = "./share/cryptopals/4.txt";
	}

	ifp = fopen(filename, "r");
	if (ifp == NULL) {
		perror(filename);
		goto err0;
	}

	rc = set1_challenge4(ifp, &plaintext);
	if (rc < 0) {
		fprintf(stderr, "Detect single character XOR failed.\n");
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
