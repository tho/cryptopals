/**
 * Base 64 specification: https://tools.ietf.org/html/rfc4648#section-4
 */
#include "util/base64.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "util/common.h"

static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			       "abcdefghijklmnopqrstuvwxyz"
			       "0123456789"
			       "+/=";

static const size_t alphabet_len = ARRAY_SIZE(alphabet) - 1;

/**
 * Converts a base 64 character to its 6 bit representation.
 *
 * The first time this function is called a static mapping of base 64
 * characters to their 6 bit group is created. The input character \p c is
 * then used to index the mapping to retrieve the corresponding 6 bit group.
 *
 * \param[in] c base 64 character.
 *
 * \returns 6 bit representation of \p c on success, -1 on failure
 */
static int
base64char_to_bits(int c)
{
	int ch;
	size_t i;
	static bool initialized = false;
	static int alphabet_reversed[SCHAR_MAX];

	if (c < 0 || c >= SCHAR_MAX) {
		goto err0;
	}

	if (!initialized) {
		for (i = 0; i < SCHAR_MAX; i++) {
			alphabet_reversed[i] = -1;
		}

		for (i = 0; i < alphabet_len; i++) {
			ch = alphabet[i];
			alphabet_reversed[ch] = (int)i;
		}

		initialized = true;
	}

	return alphabet_reversed[c];

err0:
	return -1;
}

/**
 * Tests bit group for padding character.
 *
 * Each base 64 character is represented by a group of 6 bits. The extra 65th
 * character, `=`, is used as a padding character at the end if fewer than 24
 * bits are available at the end of the data being encoded.
 *
 * \param[in] bitgroup Group of bits to test.
 *
 * \returns true if the but group tests true, false otherwise
 */
static int
ispad(int bitgroup)
{
	return bitgroup == 64;
}

int
base64str_to_bytes_raw(const char *in, size_t ilen, uint8_t *out, size_t *osize)
{
	int b1, b2, b3, b4;
	size_t i, j;

	if (in == NULL || out == NULL || osize == NULL ||
	    ilen % 4 != 0 || *osize % 3 != 0) {
		goto err0;
	}

	i = j = 0;
	while (i + 4 <= ilen && j + 3 <= *osize) {
		if ((b1 = base64char_to_bits(in[i++])) < 0 ||
		    (b2 = base64char_to_bits(in[i++])) < 0 ||
		    (b3 = base64char_to_bits(in[i++])) < 0 ||
		    (b4 = base64char_to_bits(in[i++])) < 0) {
			goto err0;
		}

		/* At most two consecutive padding characters may appear at
		 * the end of the input base 64 string. */
		if (ispad(b1) || ispad(b2) || (ispad(b3) && !ispad(b4)) ||
		    (ispad(b4) && i != ilen)) {
			goto err0;
		}

		out[j++] = (uint8_t)(b1 << 2 | b2 >> 4);
		if (!ispad(b3)) {
			out[j++] = (uint8_t)((b2 & 0x0f) << 4 | b3 >> 2);
		}
		if (!ispad(b4)) {
			out[j++] = (uint8_t)((b3 & 0x03) << 6 | b4);
		}
	}

	*osize = j;

	return 0;

err0:
	if (osize != NULL) {
		*osize = 0;
	}
	return -1;
}

int
base64str_to_bytes(const char *in, uint8_t **out, size_t *osize)
{
	int rc;
	uint8_t *bytes;
	size_t base64str_len, bytes_size;

	if (in == NULL || out == NULL || osize == NULL) {
		goto err0;
	}

	base64str_len = strlen(in);
	if (base64str_len == 0) {
		*out = NULL;
		*osize = 0;
	} else {
		/*
		 * Four base 64 characters represent three bytes.
		 *
		 * base64str_to_bytes_raw() checks if base64str_len is a
		 * multiple of 4. Therefore the check is omitted here.
		 */
		bytes_size = (base64str_len / 4) * 3;
		bytes = calloc(bytes_size, sizeof(*bytes));
		if (bytes == NULL) {
			goto err0;
		}

		rc = base64str_to_bytes_raw(in, base64str_len, bytes,
					    &bytes_size);
		if (rc < 0) {
			goto err1;
		}

		*out = bytes;
		*osize = bytes_size;
	}

	return 0;

err1:
	free(bytes);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	if (osize != NULL) {
		*osize = 0;
	}
	return -1;
}

int
bytes_to_base64str_raw(const uint8_t *in, size_t isize, char *out, size_t osize)
{
	size_t i, j;

	if (in == NULL || out == NULL) {
		goto err0;
	}

	for (i = j = 0; i + 3 <= isize && j + 4 < osize; i += 3) {
		out[j++] = alphabet[in[i] >> 2];
		out[j++] = alphabet[(in[i] & 0x03) << 4 | in[i + 1] >> 4];
		out[j++] = alphabet[(in[i + 1] & 0x0f) << 2 | in[i + 2] >> 6];
		out[j++] = alphabet[in[i + 2] & 0x3f];
	}

	if (i < isize && j + 4 < osize) {
		out[j++] = alphabet[in[i] >> 2];
		if (isize - i == 1) {
			out[j++] = alphabet[(in[i] & 0x03) << 4];
			out[j++] = alphabet[alphabet_len - 1];
		} else {
			out[j++] =
			    alphabet[(in[i] & 0x03) << 4 | in[i + 1] >> 4];
			out[j++] = alphabet[(in[i + 1] & 0x0f) << 2];
		}
		out[j++] = alphabet[alphabet_len - 1];
	}

	if (osize > 0) {
		out[j] = '\0';
	}

	return 0;

err0:
	return -1;
}

int
bytes_to_base64str(const uint8_t *in, size_t isize, char **out)
{
	int rc;
	char *base64str;
	size_t base64str_len;

	if (in == NULL || out == NULL) {
		goto err0;
	}

	/* Three bytes represent four base 64 characters. */
	base64str_len = ((isize / 3) + !!(isize % 3)) * 4;
	base64str = calloc(base64str_len + 1, sizeof(*base64str));
	if (base64str == NULL) {
		goto err0;
	}

	rc = bytes_to_base64str_raw(in, isize, base64str, base64str_len + 1);
	if (rc < 0) {
		goto err1;
	}

	*out = base64str;

	return 0;

err1:
	free(base64str);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

int
base64file_to_bytes(FILE *ifp, uint8_t **out, size_t *osize)
{
	int rc, c;
	off_t file_size;
	char *base64str, *wpos;

	if (ifp == NULL || out == NULL || osize == NULL) {
		goto err0;
	}

	rc = fseeko(ifp, 0, SEEK_END);
	if (rc < 0) {
		goto err0;
	}

	file_size = ftello(ifp);
	if (file_size < 0) {
		goto err0;
	}

	errno = 0;
	rewind(ifp);
	if (errno != 0) {
		goto err0;
	}

	base64str = calloc((size_t)file_size + 1, sizeof(*base64str));
	if (base64str == NULL) {
		goto err0;
	}

	wpos = base64str;
	while ((c = fgetc(ifp)) != EOF) {
		if (isbase64digit(c)) {
			*wpos++ = (char)c;
		} else if (c != '\n') {
			goto err1;
		}
	}
	if (ferror(ifp)) {
		goto err1;
	}

	rc = base64str_to_bytes(base64str, out, osize);
	if (rc < 0) {
		goto err1;
	}

	free(base64str);

	return 0;

err1:
	free(base64str);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	if (osize != NULL) {
		*osize = 0;
	}
	return -1;
}
