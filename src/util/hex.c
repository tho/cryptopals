#include "util/hex.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int
hexstr_to_bytes_raw(const char *in, size_t ilen, uint8_t *out, size_t osize)
{
	int c;
	uint8_t byte;
	size_t i, j;

	if (in == NULL || out == NULL) {
		goto err0;
	}

	for (i = j = 0; i < ilen && j < osize; i++) {
		c = tolower(in[i]);
		if (isdigit(c)) {
			byte = (uint8_t)c - '0';
		} else if (c >= 'a' && c <= 'f') {
			byte = 10 + (uint8_t)c - 'a';
		} else {
			goto err0;
		}

		if (i % 2) {
			out[j++] |= byte;
		} else {
			out[j] = (uint8_t)(byte << 4);
		}
	}

	return 0;

err0:
	return -1;
}

int
hexstr_to_bytes(const char *in, uint8_t **out, size_t *osize)
{
	int rc;
	uint8_t *bytes;
	size_t hexstr_len, bytes_size;

	if (in == NULL || out == NULL || osize == NULL) {
		goto err0;
	}

	hexstr_len = strlen(in);
	if (hexstr_len == 0) {
		*out = NULL;
		*osize = 0;
	} else {
		/* Two hex digits represent one byte. */
		bytes_size = (hexstr_len / 2) + (hexstr_len % 2);
		bytes = calloc(bytes_size, sizeof(*bytes));
		if (bytes == NULL) {
			goto err0;
		}

		rc = hexstr_to_bytes_raw(in, hexstr_len, bytes, bytes_size);
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
bytes_to_hexstr_raw(const uint8_t *in, size_t isize, char *out, size_t osize)
{
	size_t i, j;
	static const char alphabet[] = "0123456789abcdef";

	if (in == NULL || out == NULL) {
		goto err0;
	}

	for (i = j = 0; i < isize && j + 2 < osize; i++) {
		out[j++] = alphabet[in[i] >> 4];
		out[j++] = alphabet[in[i] & 0x0f];
	}

	if (osize > 0) {
		out[j] = '\0';
	}

	return 0;

err0:
	return -1;
}

int
bytes_to_hexstr(const uint8_t *in, size_t isize, char **out)
{
	int rc;
	char *hexstr;
	size_t hexstr_len;

	if (in == NULL || out == NULL) {
		goto err0;
	}

	/* One byte represents two hex digits. */
	hexstr_len = isize * 2;
	hexstr = calloc(hexstr_len + 1, sizeof(*hexstr));
	if (hexstr == NULL) {
		goto err0;
	}

	rc = bytes_to_hexstr_raw(in, isize, hexstr, hexstr_len + 1);
	if (rc < 0) {
		goto err1;
	}

	if (hexstr_len >= 2 &&
	    hexstr[hexstr_len - 1] == '0' &&
	    hexstr[hexstr_len - 2] != '0') {
		hexstr[--hexstr_len] = '\0';
	}

	*out = hexstr;

	return 0;

err1:
	free(hexstr);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}
