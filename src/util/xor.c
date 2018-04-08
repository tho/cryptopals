#include "util/xor.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int
fixed_xor_raw(const uint8_t *in1, const uint8_t *in2, size_t isize,
	      uint8_t *out)
{
	size_t i;

	if (in1 == NULL || in2 == NULL || out == NULL) {
		goto err0;
	}

	for (i = 0; i < isize; i++) {
		out[i] = in1[i] ^ in2[i];
	}

	return 0;

err0:
	return -1;
}

int
fixed_xor(const uint8_t *in1, const uint8_t *in2, size_t isize, uint8_t **out)
{
	int rc;
	uint8_t *xor;

	if (in1 == NULL || in2 == NULL || out == NULL) {
		goto err0;
	}

	if (isize == 0) {
		*out = NULL;
	} else {
		xor = calloc(isize, sizeof(*xor));
		if (xor == NULL) {
			goto err0;
		}

		rc = fixed_xor_raw(in1, in2, isize, xor);
		if (rc < 0) {
			goto err1;
		}

		*out = xor;
	}

	return 0;

err1:
	free(xor);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

int
single_byte_xor_raw(const uint8_t *in, size_t isize, uint8_t byte, uint8_t *out)
{
	size_t i;

	if (in == NULL || out == NULL) {
		goto err0;
	}

	for (i = 0; i < isize; i++) {
		out[i] = in[i] ^ byte;
	}

	return 0;

err0:
	return -1;
}

int
single_byte_xor(const uint8_t *in, size_t isize, uint8_t byte, uint8_t **out)
{
	int rc;
	uint8_t *xor;

	if (in == NULL || out == NULL) {
		goto err0;
	}

	if (isize == 0) {
		*out = NULL;
	} else {
		xor = calloc(isize, sizeof(*xor));
		if (xor == NULL) {
			goto err0;
		}

		rc = single_byte_xor_raw(in, isize, byte, xor);
		if (rc < 0) {
			goto err1;
		}

		*out = xor;
	}

	return 0;

err1:
	free(xor);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

int
single_byte_xorstr(const uint8_t *in, size_t isize, uint8_t byte, char **out)
{
	int rc;
	char *xorstr;

	if (in == NULL || out == NULL) {
		goto err0;
	}

	xorstr = calloc(isize + 1, sizeof(*xorstr));
	if (xorstr == NULL) {
		goto err0;
	}

	rc = single_byte_xor_raw(in, isize, byte, (uint8_t *)xorstr);
	if (rc < 0) {
		goto err1;
	}

	*out = xorstr;

	return 0;

err1:
	free(xorstr);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

static size_t
score_english_plaintext(const uint8_t *in, size_t isize)
{
	size_t i, j, score;
	const char *letters = "uldrhsnioate ";
	size_t letters_len = strlen(letters);

	score = 0;

	for (i = 0; i < isize; i++) {
		for (j = 0; j < letters_len; j++) {
			if (isprint(in[i])) {
				score++;
				if (tolower(in[i]) == letters[j]) {
					score += j;
				}
			}
		}
	}

	return score;
}

int
break_single_byte_xor_score(const uint8_t *in, size_t isize,
			    uint8_t *okey, size_t *oscore)
{
	uint8_t byte, key;
	uint8_t *xor;
	size_t score, max_score;

	if (in == NULL || okey == NULL || oscore == NULL || isize == 0) {
		goto err0;
	}

	xor = calloc(isize, sizeof(*xor));
	if (xor == NULL) {
		goto err0;
	}

	key = max_score = 0;
	for (byte = 0; byte < UINT8_MAX; byte++) {
		single_byte_xor_raw(in, isize, byte, xor);

		score = score_english_plaintext(xor, isize);
		if (score > max_score) {
			max_score = score;
			key = byte;
		}
	}
	free(xor);

	*okey = key;
	*oscore = max_score;

	return 0;

err0:
	return -1;
}

int
break_single_byte_xor(const uint8_t *in, size_t isize, uint8_t *okey)
{
	size_t score;

	return break_single_byte_xor_score(in, isize, okey, &score);
}

int
repeating_key_xor_raw(const uint8_t *in, size_t isize,
		      const uint8_t *key, size_t ksize,
		      uint8_t *out)
{
	size_t i, idx;

	if (in == NULL || key == NULL || out == NULL) {
		goto err0;
	}

	for (i = idx = 0; i < isize; i++) {
		out[i] = in[i] ^ key[idx++];
		idx %= ksize;
	}

	return 0;

err0:
	return -1;
}

int
repeating_key_xor(const uint8_t *in, size_t isize,
		  const uint8_t *key, size_t ksize,
		  uint8_t **out)
{
	int rc;
	uint8_t *xor;

	if (in == NULL || key == NULL || out == NULL) {
		goto err0;
	}

	if (isize == 0) {
		*out = NULL;
	} else {
		xor = calloc(isize, sizeof(*xor));
		if (xor == NULL) {
			goto err0;
		}

		rc = repeating_key_xor_raw(in, isize, key, ksize, xor);
		if (rc < 0) {
			goto err1;
		}

		*out = xor;
	}

	return 0;

err1:
	free(xor);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

int
repeating_key_xorstr(const uint8_t *in, size_t isize,
		     const uint8_t *key, size_t ksize,
		     char **out)
{
	int rc;
	char *xorstr;

	if (in == NULL || key == NULL || out == NULL) {
		goto err0;
	}

	xorstr = calloc(isize + 1, sizeof(*xorstr));
	if (xorstr == NULL) {
		goto err0;
	}

	rc = repeating_key_xor_raw(in, isize, key, ksize, (uint8_t *)xorstr);
	if (rc < 0) {
		goto err1;
	}

	*out = xorstr;

	return 0;

err1:
	free(xorstr);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}
