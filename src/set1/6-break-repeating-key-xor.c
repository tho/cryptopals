/**
 * Set 1 Challenge 6 - Break repeating-key XOR
 * https://www.cryptopals.com/sets/1/challenges/6
 *
 * A file has been base64'd after being encrypted with repeating-key XOR.
 * Decrypt it.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "util/base64.h"
#include "util/common.h"
#include "util/xor.h"

#define KEYSIZE_MIN 2
#define KEYSIZE_MAX 40

struct keydata {
	size_t keysize;
	size_t edit_distance;
};

static int
keydata_cmp(const void *a, const void *b)
{
	const struct keydata *k1 = a;
	const struct keydata *k2 = b;

	if (k1->edit_distance < k2->edit_distance) {
		return -1;
	} else if (k1->edit_distance > k2->edit_distance) {
		return 1;
	} else if (k1->keysize < k2->keysize) {
		return -1;
	} else if (k1->keysize > k2->keysize) {
		return 1;
	} else {
		return 0;
	}
}

static size_t
count_bits(const uint8_t *in, size_t isize)
{
	uint8_t byte;
	size_t i, count;

	assert(in != NULL);

	count = 0;
	for (i = 0; i < isize; i++) {
		for (byte = in[i]; byte != 0; byte &= (byte - 1)) {
			count++;
		}
	}

	return count;
}

static size_t
compute_edit_distance(const uint8_t *in1, const uint8_t *in2, size_t isize)
{
	int rc;
	uint8_t *bytes;
	size_t distance;

	assert(in1 != NULL);
	assert(in2 != NULL);

	rc = fixed_xor(in1, in2, isize, &bytes);
	if (rc < 0) {
		goto err0;
	}

	distance = count_bits(bytes, isize);

	free(bytes);

	return distance;

err0:
	return SIZE_MAX;
}

static size_t
get_normalized_edit_distance(const uint8_t *ciphertext, size_t ciphertext_size,
			     size_t keysize)
{
	size_t i, num_blocks, offset, distance, sum_distances, num_distances;

	assert(ciphertext != NULL);
	assert(keysize > 0);

	num_blocks = ciphertext_size / keysize;
	if (num_blocks < 2) {
		goto err0;
	}

	sum_distances = num_distances = 0;
	for (i = 0; i < num_blocks / 2; i += 2) {
		offset = i * keysize;
		distance = compute_edit_distance(&ciphertext[offset],
						 &ciphertext[offset + keysize],
						 keysize);
		if (distance > SIZE_MAX - sum_distances) {
			goto err0;
		}

		sum_distances += distance;
		num_distances++;
	}

	sum_distances /= keysize;
	if (num_distances > 1) {
		return sum_distances / num_distances;
	} else {
		return sum_distances;
	}

err0:
	return SIZE_MAX;
}

static int
find_key(const uint8_t *ciphertext, size_t ciphertext_size, size_t keysize,
	 uint8_t **out)
{
	int rc;
	uint8_t *transposed_block, *key;
	size_t i, j, num_blocks, offset;

	assert(ciphertext != NULL);
	assert(keysize > 0);
	assert(out != NULL);

	num_blocks = ciphertext_size / keysize;
	if (num_blocks == 0) {
		goto err0;
	}

	transposed_block = malloc(num_blocks * sizeof(*transposed_block));
	if (transposed_block == NULL) {
		goto err0;
	}

	key = malloc(keysize * sizeof(*key));
	if (key == NULL) {
		goto err1;
	}

	for (i = 0; i < keysize; i++) {
		for (j = 0; j < num_blocks; j++) {
			offset = j * keysize;
			transposed_block[j] = ciphertext[offset + i];
		}

		rc = break_single_byte_xor(transposed_block, j, &key[i]);
		if (rc < 0) {
			goto err2;
		}
	}

	free(transposed_block);

	*out = key;

	return 0;

err2:
	free(key);
err1:
	free(transposed_block);
err0:
	*out = NULL;
	return -1;
}

static int
decrypt(const uint8_t *ciphertext, size_t ciphertext_size,
	const uint8_t *key, size_t keysize, char **out)
{
	int rc;
	char *plaintext;

	assert(ciphertext != NULL);
	assert(key != NULL);
	assert(out != NULL);

	rc = repeating_key_xorstr(ciphertext, ciphertext_size, key, keysize,
				  &plaintext);
	if (rc < 0) {
		goto err0;
	}

	*out = plaintext;

	return 0;

err0:
	*out = NULL;
	return -1;
}

static int
set1_challenge6(FILE *ifp, char **out)
{
	int rc;
	uint8_t *ciphertext, *key;
	size_t i, ciphertext_size;
	char *plaintext;
	struct keydata keydata[KEYSIZE_MAX - KEYSIZE_MIN + 1];

	assert(ifp != NULL);
	assert(out != NULL);

	/* The ciphertext is small. Load it into memory as a whole to avoid
	 * re-reading the input file over and over again. */
	rc = base64file_to_bytes(ifp, &ciphertext, &ciphertext_size);
	if (rc < 0) {
		goto err0;
	}

	for (i = KEYSIZE_MIN; i <= KEYSIZE_MAX; i++) {
		keydata[i - KEYSIZE_MIN].keysize = i;
		keydata[i - KEYSIZE_MIN].edit_distance =
		    get_normalized_edit_distance(ciphertext, ciphertext_size, i);
	}

	/* Sort by edit distance in ascending order. */
	qsort(keydata, ARRAY_SIZE(keydata), sizeof(keydata[0]), keydata_cmp);

	/* The keysize with the smallest edit distance is probably the key. */
	rc = find_key(ciphertext, ciphertext_size, keydata[0].keysize, &key);
	if (rc < 0) {
		goto err1;
	}

	rc = decrypt(ciphertext, ciphertext_size, key, keydata[0].keysize,
		     &plaintext);
	if (rc < 0) {
		goto err2;
	}

	free(key);
	free(ciphertext);

	*out = plaintext;

	return 0;

err2:
	free(key);
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
	const char *filename;
	char *plaintext;
	FILE *ifp;

	if (argc > 2) {
		fprintf(stderr, "usage: %s [FILE]\n", argv[0]);
		goto err0;
	} else if (argc == 2) {
		filename = argv[1];
	} else {
		filename = "./share/cryptopals/6.txt";
	}

	ifp = fopen(filename, "r");
	if (ifp == NULL) {
		perror(filename);
		goto err0;
	}

	rc = set1_challenge6(ifp, &plaintext);
	if (rc < 0) {
		fprintf(stderr, "Break repeating key XOR failed.\n");
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
