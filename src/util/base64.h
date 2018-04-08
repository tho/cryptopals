#ifndef CRYPTOPALS_UTIL_BASE64_H
#define CRYPTOPALS_UTIL_BASE64_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * Tests for any base 64 digit character.
 *
 * \param[in] c Character to test.
 *
 * \returns true if the character tests true, false otherwise
 */
static inline int
isbase64digit(int c)
{
	return isalnum(c) || c == '+' || c == '/' || c == '=';
}

/**
 * Converts a base 64 string to bytes.
 *
 * To convert the whole input base 64 string of length \p ilen a destination
 * buffer of size \p ilen `/ 4 * 3` is required. \p ilen must be a multiple of
 * `4` and \p osize must be a multiple of `3`.
 *
 * Padding characters are *not* converted. If the input string is padded
 * \p osize will be updated so that it always reflects the actual number of
 * converted bytes.
 *
 * The conversion stops if either all \p ilen base 64 characters are
 * converted, \p osize bytes are written, or if an invalid base 64 character
 * is encountered.
 *
 * \param[in] in Base 64 string.
 * \param[in] ilen Length of the base 64 string.
 * \param[out] out Destination buffer.
 * \param[in,out] osize Size of the destination buffer.
 *
 * \returns 0 on success, -1 on failure
 */
int base64str_to_bytes_raw(const char *in, size_t ilen, uint8_t *out,
			   size_t *osize);

/**
 * Convenience function which converts a base 64 string to bytes.
 *
 * The function allocates a large enough output buffer to hold the byte
 * representation of the input base 64 string. The buffer must be freed by the
 * caller. If an empty string is passed in, no memory is allocated. On error
 * internally allocated memory is freed. In both cases \p out and \p osize are
 * set to `NULL` and `0` respectively.
 *
 * \param[in] in Base 64 string.
 * \param[out] out Address of the destination buffer.
 * \param[out] osize Address of the size of the destination buffer.
 *
 * \returns 0 on success, -1 on failure
 */
int base64str_to_bytes(const char *in, uint8_t **out, size_t *osize);

/**
 * Converts bytes to a base 64 string.
 *
 * To convert all \p isize input bytes a destination buffer of size
 * \p ilen `/ 3 * 4 + 1` (`+ 4` if \p ilen is not a multiple of 3) is
 * required. As long as \p osize is greater than `0` the output buffer will be
 * null-terminated.
 *
 * The conversion stops if either all \p ilen bytes are converted or \p osize
 * bytes (including the terminating `\0`) are written.
 *
 * \param[in] in Bytes.
 * \param[in] isize Number of bytes.
 * \param[out] out Destination buffer.
 * \param[in] osize Size of the destination buffer.
 *
 * \return 0 on success, -1 on failure
 */
int bytes_to_base64str_raw(const uint8_t *in, size_t isize, char *out,
			   size_t osize);

/**
 * Convenience function which converts bytes to a base 64 string.
 *
 * The function allocates a large enough output buffer to hold the string
 * representation of the input bytes. The buffer must be freed by the caller.
 * If \p isize is `0` an empty string is returned. On error internally
 * allocated memory is freed and \p out is set to `NULL`.
 *
 * \param[in] in Bytes.
 * \param[in] isize Number of bytes.
 * \param[out] out Address of the destination buffer.
 *
 * \return 0 on success, -1 on failure
 */
int bytes_to_base64str(const uint8_t *in, size_t isize, char **out);

/**
 * Reads and decodes a base 64 encoded file.
 *
 * The function reads all base 64 characters from \p ifp and converts them to
 * bytes. The output buffer \p out must be freed by the caller. If the input
 * file is empty no memory is allocated. On error, for example if an invalid
 * base 64 character is encountered, internally allocated memory is freed. In
 * both cases \p out and \p osize are set to `NULL` and `0` respectively. The
 * input file *may* contain new-line characters which are skipped.
 *
 * \param[in] ifp Input file.
 * \param[out] out Address of the destination buffer.
 * \param[out] osize Address of the length of the destination buffer.
 *
 * \returns 0 on success; -1 on failure
 */
int base64file_to_bytes(FILE *ifp, uint8_t **out, size_t *osize);

#endif /* CRYPTOPALS_UTIL_BASE64_H */
