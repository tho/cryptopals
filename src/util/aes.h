/**
 * AES
 * ===
 *
 * https://csrc.nist.gov/publications/detail/fips/197/final
 *
 * The internal operation of AES:
 *
 *              P                   K
 *              |                   |
 *     +--------v---------+  K0   +-v-+
 *     | Add Round Key    <-------+   |
 *     +--------+---------+       |   |
 *              |                 |   |
 *     +--------v---------+       |   |
 *     | Substitute Bytes |       |   |
 *     +------------------+       |   |
 *     | Shift Rows       |       |   |
 *     +------------------+       |   |
 *     | Mix Columns      |       |   |
 *     +------------------+  K1   |   |
 *     | Add Round Key    <-------+ K |
 *     +--------+---------+       | e |
 *              |                 | y |
 *              | (7 rounds)      |   |
 *              |                 | E |
 *     +--------v---------+       | x |
 *     | Substitute Bytes |       | p |
 *     +------------------+       | a |
 *     | Shift Rows       |       | n |
 *     +------------------+       | s |
 *     | Mix Columns      |       | i |
 *     +------------------+  K9   | o |
 *     | Add Round Key    <-------+ n |
 *     +--------+---------+       |   |
 *              |                 |   |
 *     +--------v---------+       |   |
 *     | Substitute Bytes |       |   |
 *     +------------------+       |   |
 *     | Shift Rows       |       |   |
 *     +------------------+  K10  |   |
 *     | Add Round Key    <-------+   |
 *     +--------+---------+       +---+
 *              |
 *              v
 *              C
 *
 * The internal state of AES viewed as a 4x4 array of 16 bytes:
 *
 *                    NB
 *     +-------+-------+-------+-------+
 *     |       |       |       |       |
 *     |  b0   |  b4   |  b8   |  b12  |
 *     |       |       |       |       |
 *     +-------------------------------+
 *     |       |       |       |       |
 *     |  b1   |  b5   |  b9   |  b13  |
 *     |       |       |       |       |
 *     +-------------------------------+ WORD_SIZE
 *     |       |       |       |       |
 *     |  b2   |  b6   |  b10  |  b14  |
 *     |       |       |       |       |
 *     +-------------------------------+
 *     |       |       |       |       |
 *     |  b3   |  b7   |  b11  |  b15  |
 *     |       |       |       |       |
 *     +-------+-------+-------+-------+
 */
#ifndef CRYPTOPALS_UTIL_AES_H
#define CRYPTOPALS_UTIL_AES_H

#include <stddef.h>
#include <stdint.h>

/* Block size in bytes. */
#define AES_BLOCK_SIZE 16

/* Word size in bytes. */
#define WORD_SIZE 4

/* Number of columns comprising the state. */
#define NB ((AES_BLOCK_SIZE) / (WORD_SIZE))

/* Macro to get offset of word `i` in an array of words. */
#define WORD(i) ((i) * (WORD_SIZE))

/* Macro to get the substitution byte of `b` from array `s[16][16]`.
 * The upper 4 bits of `b` represent the row, the lower 4 bits the column. */
#define SUB(b, s) ((s)[((b) >> 4) * 16 + ((b) & 0x0f)])

/* Key sizes in bytes. */
enum aes_key_size {
	AES_128_KEY_SIZE = 16,
	AES_192_KEY_SIZE = 24,
	AES_256_KEY_SIZE = 32
};

/* Number of rounds. */
enum aes_num_rounds {
	AES_128_NUM_ROUNDS = 10,
	AES_192_NUM_ROUNDS = 12,
	AES_256_NUM_ROUNDS = 14
};

static inline enum aes_num_rounds
_rounds(enum aes_key_size size)
{
	switch (size) {
	case AES_128_KEY_SIZE:
		return AES_128_NUM_ROUNDS;
	case AES_192_KEY_SIZE:
		return AES_192_NUM_ROUNDS;
	case AES_256_KEY_SIZE:
		return AES_256_NUM_ROUNDS;
	}
}

int aes_ecb_encrypt_raw(const uint8_t *in, size_t isize,
			const uint8_t *key, size_t ksize,
			uint8_t *out);
int aes_ecb_encrypt(const uint8_t *in, size_t isize,
		    const uint8_t *key, size_t ksize,
		    uint8_t **out);
int aes_ecb_encrypt_str(const uint8_t *in, size_t isize,
			const uint8_t *key, size_t ksize,
			char **out);

int aes_ecb_decrypt_raw(const uint8_t *in, size_t isize,
			const uint8_t *key, size_t ksize,
			uint8_t *out);
int aes_ecb_decrypt(const uint8_t *in, size_t isize,
		    const uint8_t *key, size_t ksize,
		    uint8_t **out);
int aes_ecb_decrypt_str(const uint8_t *in, size_t isize,
			const uint8_t *key, size_t ksize,
			char **out);

#endif /* CRYPTOPALS_UTIL_AES_H */
