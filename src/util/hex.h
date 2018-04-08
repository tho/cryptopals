#ifndef CRYPTOPALS_UTIL_HEX_H
#define CRYPTOPALS_UTIL_HEX_H

#include <stddef.h>
#include <stdint.h>

/**
 * Converts a hex string to bytes.
 *
 * To convert the whole input hex string of length \p ilen a destination
 * buffer of size \p ilen `/ 2` (`+ 1` if \p ilen is odd) is required.
 *
 * The conversion stops if either all \p ilen hex characters are converted,
 * \p osize bytes are written, or if an invalid hex character is encountered.
 *
 * \param[in] in Hex string.
 * \param[in] ilen Length of the hex string.
 * \param[out] out Destination buffer.
 * \param[in] osize Size of the destination buffer.
 *
 * \returns 0 on success, -1 on failure
 */
int hexstr_to_bytes_raw(const char *in, size_t ilen, uint8_t *out,
			size_t osize);

/**
 * Convenience function which converts a hex string to bytes.
 *
 * The function allocates a large enough output buffer to hold the byte
 * representation of the input hex string. The buffer must be freed by the
 * caller. If an empty string is passed in, no memory is allocated. On error
 * internally allocated memory is freed. In both cases \p out and \p osize are
 * set to `NULL` and `0` respectively.
 *
 * \param[in] in Hex string.
 * \param[out] out Address of the destination buffer.
 * \param[out] osize Address of the size of the destination buffer.
 *
 * \returns 0 on success, -1 on failure
 */
int hexstr_to_bytes(const char *in, uint8_t **out, size_t *osize);

/**
 * Converts bytes to a hex string.
 *
 * To convert all \p isize input bytes a destination buffer of size
 * \p ilen `* 2 + 1` is required. As long as \p osize is greater than `0` the
 * output buffer will be null-terminated.
 *
 * The conversion stops if either all \p ilen bytes are converted or \p osize
 * bytes (including the terminating `\0`) are written.
 *
 * \param[in] in Bytes.
 * \param[in] isize Number of bytes.
 * \param[out] out Destination buffer.
 * \param[in] osize Size of the destination buffer.
 *
 * \returns 0 on success, -1 on failure
 */
int bytes_to_hexstr_raw(const uint8_t *in, size_t isize, char *out,
			size_t osize);

/**
 * Convenience function which converts bytes to a hex string.
 *
 * The function allocates a large enough output buffer to hold the string
 * representation of the input bytes. The buffer must be freed by the caller.
 * If \p isize is `0` an empty string is returned. On error internally
 * allocated memory is freed and \p out is set to `NULL`.
 *
 * The last character of the output string is stripped off if it is `0` and
 * the second to last character is unequal to `0`. This allows to convert
 * single bytes to single-character hex strings, for example `0xf0` => `"f"`.
 * A null-byte (`0x00`), however, is converted to `"00"`.
 *
 * \param[in] in Bytes.
 * \param[in] isize Number of bytes.
 * \param[out] out Address of the destination buffer.
 *
 * \returns 0 on success, -1 on failure
 */
int bytes_to_hexstr(const uint8_t *in, size_t isize, char **out);

#endif /* CRYPTOPALS_UTIL_HEX_H */
