#include "util/base64.h"

#include <stdlib.h>
#include <string.h>

#include "test.h"

#define ASSERT_FAILURE(rc, result, result_size) \
	do {                                    \
		ASSERT((rc) == -1);             \
		ASSERT((result) == NULL);       \
		ASSERT((result_size) == 0);     \
	} while (0)

#define WRITE_STRING(s, fp)            \
	do {                           \
		if ((fp) != NULL) {    \
			fclose(fp);    \
		}                      \
		(fp) = tmpfile();      \
		rc = fputs((s), (fp)); \
		ASSERT((rc) != EOF);   \
	} while (0)

static struct {
	char *base64str;
	size_t base64str_len;
	uint8_t bytes[6];
	size_t bytes_size;
} test_cases[] = {{"AA==", 4, {0x00}, 1},
		  {"AAA=", 4, {0x00, 0x00}, 2},
		  {"AAAA", 4, {0x00, 0x00, 0x00}, 3},
		  {"Zg==", 4, {'f'}, 1},
		  {"Zm8=", 4, {'f', 'o'}, 2},
		  {"Zm9v", 4, {'f', 'o', 'o'}, 3},
		  {"Zm9vYg==", 8, {'f', 'o', 'o', 'b'}, 4},
		  {"Zm9vYmE=", 8, {'f', 'o', 'o', 'b', 'a'}, 5},
		  {"Zm9vYmFy", 8, {'f', 'o', 'o', 'b', 'a', 'r'}, 6},
		  {"Zm9vYm+/", 8, {'f', 'o', 'o', 'b', 'o', 0xbf}, 6}};

static void
test_base64str_to_bytes_raw(void)
{
	int rc;
	uint8_t bytes[6];
	size_t bytes_size;

	/* Invalid arguments. */
	bytes_size = ARRAY_SIZE(bytes);
	rc = base64str_to_bytes_raw(NULL, 4, bytes, &bytes_size);
	ASSERT(rc == -1);
	ASSERT(bytes_size == 0);

	bytes_size = ARRAY_SIZE(bytes);
	rc = base64str_to_bytes_raw("AA==", 4, NULL, &bytes_size);
	ASSERT(rc == -1);
	ASSERT(bytes_size == 0);

	bytes_size = ARRAY_SIZE(bytes);
	rc = base64str_to_bytes_raw("AA==", 4, bytes, NULL);
	ASSERT(rc == -1);
	ASSERT(bytes_size == ARRAY_SIZE(bytes));

	bytes_size = ARRAY_SIZE(bytes);
	rc = base64str_to_bytes_raw("AA=", 3, bytes, &bytes_size);
	ASSERT(rc == -1);
	ASSERT(bytes_size == 0);

	bytes_size = ARRAY_SIZE(bytes) - 1;
	rc = base64str_to_bytes_raw("AA==", 4, bytes, &bytes_size);
	ASSERT(rc == -1);
	ASSERT(bytes_size == 0);

	/* Verify that max ilen hex chars are converted. */
	bytes_size = ARRAY_SIZE(bytes);
	memset(bytes, 0xff, sizeof(bytes));
	rc = base64str_to_bytes_raw("Zm9vYmFy", 0, bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes_size == 0);
	ASSERT(memcmp(bytes,
		      (uint8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 6) == 0);

	bytes_size = ARRAY_SIZE(bytes);
	memset(bytes, 0xff, sizeof(bytes));
	rc = base64str_to_bytes_raw("Zm9vYmFy", 4, bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes_size == 3);
	ASSERT(memcmp(bytes,
		      (uint8_t[]){'f', 'o', 'o', 0xff, 0xff, 0xff}, 6) == 0);

	/* Verify that max osize bytes are written. */
	bytes_size = 0;
	memset(bytes, 0xff, sizeof(bytes));
	rc = base64str_to_bytes_raw("Zm9vYmFy", 8, bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes_size == 0);
	ASSERT(memcmp(bytes,
		      (uint8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 6) == 0);

	bytes_size = 3;
	memset(bytes, 0xff, sizeof(bytes));
	rc = base64str_to_bytes_raw("Zm9vYmFy", 8, bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes_size == 3);
	ASSERT(memcmp(bytes,
		      (uint8_t[]){'f', 'o', 'o', 0xff, 0xff, 0xff}, 6) == 0);
}

static void
test_base64str_to_bytes(void)
{
	int rc;
	uint8_t *bytes;
	size_t i, bytes_size;

	const char *invalid_base64strs[] = {":-)",      "Zg=",      "=m9vYmfy",
					    "Z=9vYmFy", "Zm=vYmFy", "Zm9=YmFy"};

	/* Invalid arguments. */
	bytes = (uint8_t *)1;
	bytes_size = 1;
	rc = base64str_to_bytes(NULL, &bytes, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	bytes_size = 1;
	rc = base64str_to_bytes("", NULL, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	bytes = (uint8_t *)1;
	rc = base64str_to_bytes("", &bytes, NULL);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	/* Test empty base 64 string. */
	rc = base64str_to_bytes("", &bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes == NULL);
	ASSERT(bytes_size == 0);

	/* Test invalid base 64 strings. */
	for (i = 0; i < ARRAY_SIZE(invalid_base64strs); i++) {
		bytes = (uint8_t *)1;
		bytes_size = 1;
		rc = base64str_to_bytes(invalid_base64strs[i], &bytes,
					&bytes_size);
		ASSERT_FAILURE(rc, bytes, bytes_size);
	}

	/* Run common test cases. */
	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		rc = base64str_to_bytes(test_cases[i].base64str,
					&bytes, &bytes_size);
		ASSERT(rc == 0);
		ASSERT(bytes_size == test_cases[i].bytes_size);
		ASSERT(memcmp(bytes, test_cases[i].bytes, bytes_size) == 0);
		free(bytes);
	}
}

static void
test_bytes_to_base64str_raw(void)
{
	int rc;
	uint8_t bytes[] = {'f', 'o', 'o', 'b', 'a', 'r'};
	char base64str[9];

	/* Invalid arguments. */
	rc = bytes_to_base64str_raw(NULL, 3, base64str, ARRAY_SIZE(base64str));
	ASSERT(rc == -1);

	rc = bytes_to_base64str_raw((uint8_t[]){0x00, 0x00, 0x00}, 3, NULL,
				    ARRAY_SIZE(base64str));
	ASSERT(rc == -1);

	/* Verify that max isize bytes are converted. */
	memset(base64str, 0, sizeof(base64str));
	rc = bytes_to_base64str_raw(bytes, 0, base64str, ARRAY_SIZE(base64str));
	ASSERT(rc == 0);
	ASSERT(strcmp(base64str, "") == 0);

	memset(base64str, 0, sizeof(base64str));
	rc = bytes_to_base64str_raw(bytes, 3, base64str, ARRAY_SIZE(base64str));
	ASSERT(rc == 0);
	ASSERT(strcmp(base64str, "Zm9v") == 0);

	/* Verify that max osize bytes are written. */
	memset(base64str, 0, sizeof(base64str));
	rc = bytes_to_base64str_raw(bytes, ARRAY_SIZE(bytes), base64str, 0);
	ASSERT(rc == 0);
	ASSERT(strcmp(base64str, "") == 0);

	memset(base64str, 0, sizeof(base64str));
	rc = bytes_to_base64str_raw(bytes, ARRAY_SIZE(bytes), base64str, 5);
	ASSERT(rc == 0);
	ASSERT(strcmp(base64str, "Zm9v") == 0);
}

static void
test_bytes_to_base64str(void)
{
	int rc;
	char *base64str;
	size_t i;

	/* Invalid arguments. */
	base64str = (char *)1;
	rc = bytes_to_base64str(NULL, 0, &base64str);
	ASSERT(rc == -1);
	ASSERT(base64str == NULL);

	rc = bytes_to_base64str((uint8_t[]){0x00}, 1, NULL);
	ASSERT(rc == -1);

	/* Test size 0. */
	rc = bytes_to_base64str((uint8_t[]){0x00}, 0, &base64str);
	ASSERT(rc == 0);
	ASSERT(strlen(base64str) == 0);
	ASSERT(strcmp(base64str, "") == 0);
	free(base64str);

	/* Run common test cases. */
	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		rc = bytes_to_base64str(test_cases[i].bytes,
					test_cases[i].bytes_size, &base64str);
		ASSERT(rc == 0);
		ASSERT(strlen(base64str) == test_cases[i].base64str_len);
		ASSERT(strcmp(base64str, test_cases[i].base64str) == 0);
		free(base64str);
	}
}

static void
test_base64file_to_bytes(void)
{
	int rc;
	uint8_t *bytes;
	size_t bytes_size;
	FILE *fp;

	fp = tmpfile();
	ASSERT(fp != NULL);

	/* Invalid arguments. */
	bytes = (uint8_t *)1;
	bytes_size = 1;
	rc = base64file_to_bytes(NULL, &bytes, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	bytes_size = 1;
	rc = base64file_to_bytes(fp, NULL, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	bytes = (uint8_t *)1;
	rc = base64file_to_bytes(fp, &bytes, NULL);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	/* Test file with invalid characters. */
	bytes = (uint8_t *)1;
	bytes_size = 1;
	WRITE_STRING("Zm9v\n:-)\nYmFy\n", fp);
	rc = base64file_to_bytes(fp, &bytes, &bytes_size);
	ASSERT_FAILURE(rc, bytes, bytes_size);

	/* Test empty file. */
	WRITE_STRING("", fp);
	rc = base64file_to_bytes(fp, &bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes == NULL);
	ASSERT(bytes_size == 0);

	/* Test multi-line file. */
	WRITE_STRING("Zm9v\nAAAA\n\nYmFy\n", fp);
	rc = base64file_to_bytes(fp, &bytes, &bytes_size);
	ASSERT(rc == 0);
	ASSERT(bytes_size == 9);
	ASSERT(
	    memcmp(bytes,
		   (uint8_t[]){'f', 'o', 'o', 0x00, 0x00, 0x00, 'b', 'a', 'r'},
		   bytes_size) == 0);

	fclose(fp);
}

int
main(void)
{
	test_base64str_to_bytes_raw();
	test_base64str_to_bytes();

	test_bytes_to_base64str_raw();
	test_bytes_to_base64str();

	test_base64file_to_bytes();

	exit(EXIT_SUCCESS);
}
