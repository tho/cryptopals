#include "util/hex.h"

#include <stdlib.h>
#include <string.h>

#include "test.h"

#define ASSERT_FAILURE(rc, result, result_size) \
	do {                                    \
		ASSERT((rc) == -1);             \
		ASSERT((result) == NULL);       \
		ASSERT((result_size) == 0);     \
	} while (0)

static struct {
	char *hexstr;
	size_t hexstr_len;
	uint8_t bytes[5];
	size_t bytes_size;
} test_cases[] = {{"f", 1, {0xf0}, 1},
		  {"0f", 2, {0x0f}, 1},
		  {"abc", 3, {0xab, 0xc0}, 2},
		  {"0123456789", 10, {0x01, 0x23, 0x45, 0x67, 0x89}, 5},
		  {"abcdef", 6, {0xab, 0xcd, 0xef}, 3}};

static void
test_hexstr_to_bytes_raw(void)
{
	int rc;
	uint8_t bytes[2];

	/* Invalid arguments. */
	rc = hexstr_to_bytes_raw(NULL, 0, bytes, ARRAY_SIZE(bytes));
	ASSERT(rc == -1);

	rc = hexstr_to_bytes_raw("", 0, NULL, ARRAY_SIZE(bytes));
	ASSERT(rc == -1);

	/* Verify that max ilen hex chars are converted. */
	memset(bytes, 0xff, sizeof(bytes));
	rc = hexstr_to_bytes_raw("abcd", 0, bytes, ARRAY_SIZE(bytes));
	ASSERT(rc == 0);
	ASSERT(memcmp(bytes, (uint8_t[]){0xff, 0xff}, 2) == 0);

	memset(bytes, 0xff, sizeof(bytes));
	rc = hexstr_to_bytes_raw("abcd", 2, bytes, ARRAY_SIZE(bytes));
	ASSERT(rc == 0);
	ASSERT(memcmp(bytes, (uint8_t[]){0xab, 0xff}, 2) == 0);

	/* Verify that max osize bytes are written. */
	memset(bytes, 0xff, sizeof(bytes));
	rc = hexstr_to_bytes_raw("abcd", 4, bytes, 0);
	ASSERT(rc == 0);
	ASSERT(memcmp(bytes, (uint8_t[]){0xff, 0xff}, 2) == 0);

	memset(bytes, 0xff, sizeof(bytes));
	rc = hexstr_to_bytes_raw("abcd", 4, bytes, 1);
	ASSERT(rc == 0);
	ASSERT(memcmp(bytes, (uint8_t[]){0xab, 0xff}, 2) == 0);
}

static void
test_hexstr_to_bytes(void)
{
	int rc;
	uint8_t *bytes;
	size_t i, bytes_size;

	/* Invalid arguments. */
	bytes = (uint8_t *)1;
	bytes_size = 1;
	rc = hexstr_to_bytes(NULL, &bytes, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	bytes_size = 1;
	rc = hexstr_to_bytes("", NULL, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	bytes = (uint8_t *)1;
	rc = hexstr_to_bytes("", &bytes, NULL);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	/* Test invalid hex digits. */
	bytes = (uint8_t *)1;
	bytes_size = 1;
	rc = hexstr_to_bytes("invalid", &bytes, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	/* Test empty hex string. */
	rc = hexstr_to_bytes("", &bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes == NULL);
	ASSERT(bytes_size == 0);

	/* Test mixed case hex string. */
	rc = hexstr_to_bytes("abcdefABCDEF", &bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes_size == 6);
	ASSERT(memcmp(bytes, (uint8_t[]){0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef},
		      bytes_size) == 0);
	free(bytes);

	/* Run common test cases. */
	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		rc = hexstr_to_bytes(test_cases[i].hexstr, &bytes, &bytes_size);
		ASSERT(rc == 0);
		ASSERT(bytes_size == test_cases[i].bytes_size);
		ASSERT(memcmp(bytes, test_cases[i].bytes, bytes_size) == 0);
		free(bytes);
	}
}

static void
test_bytes_to_hexstr_raw(void)
{
	int rc;
	uint8_t bytes[] = {0xab, 0xcb};
	char hexstr[5];

	/* Invalid arguments. */
	rc = bytes_to_hexstr_raw(NULL, 1, hexstr, ARRAY_SIZE(hexstr));
	ASSERT(rc == -1);

	rc = bytes_to_hexstr_raw((uint8_t[]){0x00}, 1, NULL, ARRAY_SIZE(hexstr));
	ASSERT(rc == -1);

	/* Verify that max isize bytes are converted. */
	memset(hexstr, 0, sizeof(hexstr));
	rc = bytes_to_hexstr_raw(bytes, 0, hexstr, ARRAY_SIZE(hexstr));
	ASSERT(rc == 0);
	ASSERT(strcmp(hexstr, "") == 0);

	memset(hexstr, 0, sizeof(hexstr));
	rc = bytes_to_hexstr_raw(bytes, 1, hexstr, ARRAY_SIZE(hexstr));
	ASSERT(rc == 0);
	ASSERT(strcmp(hexstr, "ab") == 0);

	/* Verify that max osize characters are written. */
	memset(hexstr, 0, sizeof(hexstr));
	rc = bytes_to_hexstr_raw(bytes, 2, hexstr, 0);
	ASSERT(rc == 0);
	ASSERT(strcmp(hexstr, "") == 0);

	memset(hexstr, 0, sizeof(hexstr));
	rc = bytes_to_hexstr_raw(bytes, 2, hexstr, 3);
	ASSERT(rc == 0);
	ASSERT(strcmp(hexstr, "ab") == 0);
}

static void
test_bytes_to_hexstr(void)
{
	int rc;
	size_t i;
	char *hexstr;

	/* Invalid arguments. */
	hexstr = (char *)1;
	rc = bytes_to_hexstr(NULL, 0, &hexstr);
	ASSERT(rc == -1);
	ASSERT(hexstr == NULL);

	rc = bytes_to_hexstr((uint8_t[]){0x00}, 1, NULL);
	ASSERT(rc == -1);

	/* Test size 0. */
	rc = bytes_to_hexstr((uint8_t[]){0x00}, 0, &hexstr);
	ASSERT(rc == 0);
	ASSERT(strlen(hexstr) == 0);
	ASSERT(strcmp(hexstr, "") == 0);
	free(hexstr);

	/* Test null byte. */
	rc = bytes_to_hexstr((uint8_t[]){0x00}, 1, &hexstr);
	ASSERT(rc == 0);
	ASSERT(strlen(hexstr) == 2);
	ASSERT(strcmp(hexstr, "00") == 0);
	free(hexstr);

	/* Run common test cases. */
	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		rc = bytes_to_hexstr(test_cases[i].bytes,
				     test_cases[i].bytes_size, &hexstr);
		ASSERT(rc == 0);
		ASSERT(strlen(hexstr) == test_cases[i].hexstr_len);
		ASSERT(strcmp(hexstr, test_cases[i].hexstr) == 0);
		free(hexstr);
	}
}

int
main(void)
{
	test_hexstr_to_bytes_raw();
	test_hexstr_to_bytes();

	test_bytes_to_hexstr_raw();
	test_bytes_to_hexstr();

	exit(EXIT_SUCCESS);
}
