#include "util/xor.h"

#include <stdlib.h>
#include <string.h>

#include "test.h"

#define ASSERT_FAILURE(rc, result)        \
	do {                              \
		ASSERT((rc) == -1);       \
		ASSERT((result) == NULL); \
	} while (0)

static void
test_fixed_xor_raw(void)
{
	int rc;
	uint8_t bytes1[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	uint8_t bytes2[8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	uint8_t xor[8], expected_bytes[8];

	/* Invalid arguments. */
	rc = fixed_xor_raw(NULL, bytes2, ARRAY_SIZE(bytes2), xor);
	ASSERT(rc == -1);

	rc = fixed_xor_raw(bytes1, NULL, ARRAY_SIZE(bytes1), xor);
	ASSERT(rc == -1);

	rc = fixed_xor_raw(bytes1, bytes2, ARRAY_SIZE(bytes1), NULL);
	ASSERT(rc == -1);

	/* Test that XOR'ing bytes with themselves yields all 0x00. */
	memset(expected_bytes, 0, sizeof(expected_bytes));
	rc = fixed_xor_raw(bytes1, bytes1, ARRAY_SIZE(bytes1), xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);

	/* Test that XOR'ing bytes with their inversion yields all 0xff */
	memset(expected_bytes, 0xff, sizeof(expected_bytes));
	rc = fixed_xor_raw(bytes1, bytes2, ARRAY_SIZE(bytes1), xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);

	/* Verify that max isize bytes are XOR'ed. */
	memset(xor, 0xff, sizeof(xor));
	memset(expected_bytes, 0xff, sizeof(expected_bytes));
	memset(expected_bytes, 0x00, sizeof(expected_bytes) / 2);
	rc = fixed_xor_raw(bytes1, bytes1, ARRAY_SIZE(bytes1) / 2, xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);
}

static void
test_fixed_xor(void)
{
	int rc;
	uint8_t bytes1[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	uint8_t bytes2[8] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	uint8_t expected_bytes[8];
	uint8_t *xor;

	/* Invalid arguments. */
	xor = (uint8_t *)1;
	rc = fixed_xor(NULL, bytes2, ARRAY_SIZE(bytes2), &xor);
	ASSERT_FAILURE(rc, xor);

	xor = (uint8_t *)1;
	rc = fixed_xor(bytes1, NULL, ARRAY_SIZE(bytes1), &xor);
	ASSERT_FAILURE(rc, xor);

	rc = fixed_xor(bytes1, bytes2, ARRAY_SIZE(bytes1), NULL);
	ASSERT(rc == -1);

	/* Test isize 0. */
	xor = (uint8_t *)1;
	rc = fixed_xor(bytes1, bytes2, 0, &xor);
	ASSERT(rc == 0);
	ASSERT(xor == NULL);

	/* Test normal case. */
	memset(expected_bytes, 0xff, sizeof(expected_bytes));
	rc = fixed_xor(bytes1, bytes2, ARRAY_SIZE(bytes1), &xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);
	free(xor);
}

static void
test_single_byte_xor_raw(void)
{
	int rc;
	uint8_t bytes[2] = {0xff, 0xff};
	uint8_t xor[2], expected_bytes[2];

	/* Invalid arguments. */
	rc = single_byte_xor_raw(NULL, ARRAY_SIZE(bytes), 0xff, xor);
	ASSERT(rc == -1);

	rc = single_byte_xor_raw(bytes, ARRAY_SIZE(bytes), 0xff, NULL);
	ASSERT(rc == -1);

	/* Test normal case. */
	memset(expected_bytes, 0, sizeof(expected_bytes));
	rc = single_byte_xor_raw(bytes, ARRAY_SIZE(bytes), 0xff, xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);

	/* Verify that max isize bytes are XOR'ed. */
	memset(xor, 0xff, sizeof(xor));
	memset(expected_bytes, 0xff, sizeof(expected_bytes));
	memset(expected_bytes, 0x00, sizeof(expected_bytes) / 2);
	rc = single_byte_xor_raw(bytes, ARRAY_SIZE(bytes) / 2, 0xff, xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);
}

static void
test_single_byte_xor(void)
{
	int rc;
	uint8_t bytes[2] = {0xff, 0xff};
	uint8_t expected_bytes[2];
	uint8_t *xor;

	/* Invalid arguments. */
	xor = (uint8_t *)1;
	rc = single_byte_xor(NULL, ARRAY_SIZE(bytes), 0xff, &xor);
	ASSERT_FAILURE(rc, xor);

	rc = single_byte_xor(bytes, ARRAY_SIZE(bytes), 0xff, NULL);
	ASSERT(rc == -1);

	/* Test isize 0. */
	xor = (uint8_t *)1;
	rc = single_byte_xor(bytes, 0, 0xff, &xor);
	ASSERT(rc == 0);
	ASSERT(xor == NULL);

	/* Test normal case. */
	memset(expected_bytes, 0x00, sizeof(expected_bytes));
	rc = single_byte_xor(bytes, ARRAY_SIZE(bytes), 0xff, &xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);
	free(xor);
}

static void
test_single_byte_xorstr(void)
{
	int rc;
	uint8_t bytes[2] = {0xff, 0xff};
	char expectedstr[3];
	char *xorstr;

	/* Invalid arguments. */
	xorstr = (char *)1;
	rc = single_byte_xorstr(NULL, ARRAY_SIZE(bytes), 0xff, &xorstr);
	ASSERT_FAILURE(rc, xorstr);

	rc = single_byte_xorstr(bytes, ARRAY_SIZE(bytes), 0xff, NULL);
	ASSERT(rc == -1);

	/* Test isize 0. */
	rc = single_byte_xorstr(bytes, 0, 0xff, &xorstr);
	ASSERT(rc == 0);
	ASSERT(strcmp(xorstr, "") == 0);
	free(xorstr);

	/* Test normal cases. */
	memset(expectedstr, 0x00, sizeof(expectedstr));
	rc = single_byte_xorstr(bytes, ARRAY_SIZE(bytes), 0xff, &xorstr);
	ASSERT(rc == 0);
	ASSERT(strcmp(xorstr, expectedstr) == 0);
	ASSERT(memcmp(xorstr, expectedstr, sizeof(expectedstr)) == 0);
	free(xorstr);

	memset(expectedstr, 0xff, sizeof(expectedstr) - 1);
	rc = single_byte_xorstr(bytes, ARRAY_SIZE(bytes), 0x00, &xorstr);
	ASSERT(rc == 0);
	ASSERT(strcmp(xorstr, expectedstr) == 0);
	ASSERT(memcmp(xorstr, expectedstr, sizeof(expectedstr)) == 0);
	free(xorstr);
}

static void
test_repeating_key_xor_raw(void)
{
	int rc;
	uint8_t bytes[4] = {0x01, 0x23, 0x01, 0x23};
	uint8_t key[2] = {0xfe, 0xdc};
	uint8_t xor[4], *expected_bytes;

	/* Invalid arguments. */
	rc = repeating_key_xor_raw(NULL, ARRAY_SIZE(bytes),
				   key, ARRAY_SIZE(key), xor);
	ASSERT(rc == -1);

	rc = repeating_key_xor_raw(bytes, ARRAY_SIZE(bytes),
				   NULL, ARRAY_SIZE(key), xor);
	ASSERT(rc == -1);

	rc = repeating_key_xor_raw(bytes, ARRAY_SIZE(bytes),
				   key, ARRAY_SIZE(key), NULL);
	ASSERT(rc == -1);

	/* Test normal case. */
	expected_bytes = (uint8_t[]){0xff, 0xff, 0xff, 0xff};
	rc = repeating_key_xor_raw(bytes, ARRAY_SIZE(bytes),
				   key, ARRAY_SIZE(key), xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(xor)) == 0);

	/* Test that input can be processed in multiples of key size. */
	expected_bytes = (uint8_t[]){0xff, 0xff, 0x01, 0x23};
	memcpy(xor, bytes, sizeof(xor));
	rc = repeating_key_xor_raw(bytes, ARRAY_SIZE(bytes) / 2,
				   key, ARRAY_SIZE(key), xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(xor)) == 0);

	expected_bytes = (uint8_t[]){0xff, 0xff, 0xff, 0xff};
	rc = repeating_key_xor_raw(&bytes[2], ARRAY_SIZE(bytes) / 2,
				   key, ARRAY_SIZE(key), &xor[2]);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(xor)) == 0);

	/*
	 * Test that no internal state is kept.
	 *
	 * The function does/should not keep internal state. Each time it is
	 * called the first input byte is XOR'ed with the first byte of the
	 * key. This implies that if the function must be called multiple
	 * times for the same input, the caller must ensure that the input is
	 * processed in multiples of key size.
	 */
	expected_bytes = (uint8_t[]){0xff, 0x23, 0x01, 0x23};
	memcpy(xor, bytes, sizeof(xor));
	rc = repeating_key_xor_raw(bytes, 1,
				   key, ARRAY_SIZE(key), xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(xor)) == 0);

	/* If the function would keep internal state,
	 * expected_bytes = (uint8_t[]){0xff, 0xff, 0xff, 0xff} */
	expected_bytes = (uint8_t[]){0xff, 0xdd, 0xdd, 0xdd};
	rc = repeating_key_xor_raw(&bytes[1], ARRAY_SIZE(bytes) - 1,
				   key, ARRAY_SIZE(key), &xor[1]);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(xor)) == 0);
}

static void
test_repeating_key_xor(void)
{
	int rc;
	uint8_t bytes[4] = {0x01, 0x23, 0x01, 0x23};
	uint8_t key[2] = {0xfe, 0xdc};
	uint8_t expected_bytes[4];
	uint8_t *xor;

	/* Invalid arguments. */
	xor = (uint8_t *)1;
	rc = repeating_key_xor(NULL, ARRAY_SIZE(bytes), key, ARRAY_SIZE(key),
			       &xor);
	ASSERT_FAILURE(rc, xor);

	xor = (uint8_t *)1;
	rc = repeating_key_xor(bytes, ARRAY_SIZE(bytes), NULL, ARRAY_SIZE(key),
			       &xor);
	ASSERT_FAILURE(rc, xor);

	rc = repeating_key_xor(bytes, ARRAY_SIZE(bytes), key, ARRAY_SIZE(key),
			       NULL);
	ASSERT(rc == -1);

	/* Test isize 0. */
	xor = (uint8_t *)1;
	rc = repeating_key_xor(bytes, 0, key, ARRAY_SIZE(key), &xor);
	ASSERT(rc == 0);
	ASSERT(xor == NULL);

	/* Test normal case. */
	memset(expected_bytes, 0xff, sizeof(expected_bytes));
	rc = repeating_key_xor(bytes, ARRAY_SIZE(bytes), key, ARRAY_SIZE(key),
			       &xor);
	ASSERT(rc == 0);
	ASSERT(memcmp(xor, expected_bytes, sizeof(expected_bytes)) == 0);
	free(xor);
}

static void
test_repeating_key_xorstr(void)
{
	int rc;
	uint8_t bytes[4] = {0x01, 0x23, 0x01, 0x23};
	uint8_t key[2] = {0xfe, 0xdc};
	char expectedstr[5];
	char *xorstr;

	/* Invalid arguments. */
	xorstr = (char *)1;
	rc = repeating_key_xorstr(NULL, ARRAY_SIZE(bytes),
				  key, ARRAY_SIZE(key), &xorstr);
	ASSERT_FAILURE(rc, xorstr);

	xorstr = (char *)1;
	rc = repeating_key_xorstr(bytes, ARRAY_SIZE(bytes),
				  NULL, ARRAY_SIZE(key), &xorstr);
	ASSERT_FAILURE(rc, xorstr);

	rc = repeating_key_xorstr(bytes, ARRAY_SIZE(bytes),
				  key, ARRAY_SIZE(key), NULL);
	ASSERT(rc == -1);

	/* Test isize 0. */
	rc = repeating_key_xorstr(bytes, 0, key, ARRAY_SIZE(key), &xorstr);
	ASSERT(rc == 0);
	ASSERT(strcmp(xorstr, "") == 0);
	free(xorstr);

	/* Test normal case. */
	memset(expectedstr, 0xff, sizeof(expectedstr));
	expectedstr[ARRAY_SIZE(expectedstr) - 1] = '\0';
	rc = repeating_key_xorstr(bytes, ARRAY_SIZE(bytes),
				  key, ARRAY_SIZE(key), &xorstr);
	ASSERT(rc == 0);
	ASSERT(strcmp(xorstr, expectedstr) == 0);
	ASSERT(memcmp(xorstr, expectedstr, sizeof(expectedstr)) == 0);
	free(xorstr);
}
int
main(void)
{
	test_fixed_xor_raw();
	test_fixed_xor();

	test_single_byte_xor_raw();
	test_single_byte_xor();
	test_single_byte_xorstr();

	test_repeating_key_xor_raw();
	test_repeating_key_xor();
	test_repeating_key_xorstr();

	exit(EXIT_SUCCESS);
}
