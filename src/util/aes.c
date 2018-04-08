#include "util/aes.h"

#include <stdlib.h>
#include <string.h>

#include "util/galois.h"
#include "util/xor.h"

static void
_to_state(const uint8_t *in, uint8_t (*out)[NB])
{
	int row, col;
	uint8_t state[WORD_SIZE][NB];

	for (row = 0; row < WORD_SIZE; row++) {
		for (col = 0; col < NB; col++) {
			state[row][col] = in[row + WORD_SIZE * col];
		}
	}

	memcpy(out, state, sizeof(state));
}

static void
_from_state(const uint8_t (*in)[NB], uint8_t *out)
{
	int row, col;
	uint8_t bytes[WORD_SIZE * NB];

	for (row = 0; row < WORD_SIZE; row++) {
		for (col = 0; col < NB; col++) {
			bytes[row + WORD_SIZE * col] = in[row][col];
		}
	}

	memcpy(out, bytes, sizeof(bytes));
}

static uint8_t *
_rot_word(const uint8_t *in)
{
	static uint8_t out[WORD_SIZE];

	memcpy(out, &in[1], WORD_SIZE - 1);
	out[WORD_SIZE - 1] = in[0];

	return out;
}

static uint8_t *
_sub_word(const uint8_t *in)
{
	int i;
	static uint8_t out[WORD_SIZE];

	for (i = 0; i < WORD_SIZE; i++) {
		out[i] = SUB(in[i], sbox);
	}

	return out;
}

static int
_expand_key(const uint8_t *key, enum aes_key_size ksize, uint8_t **out)
{
	uint8_t *expanded_key, *tmp;
	size_t i, Nk, expanded_key_size;

	expanded_key_size = AES_BLOCK_SIZE * (_rounds(ksize) + 1);
	expanded_key = malloc(expanded_key_size);
	if (expanded_key == NULL) {
		goto err0;
	}

	memcpy(expanded_key, key, ksize);

	/* NK is the number of words comprising the key. */
	Nk = ksize / WORD_SIZE;
	/* Each iteration generates WORD_SIZE bytes. */
	for (i = Nk; i < expanded_key_size / WORD_SIZE; i++) {
		tmp = &expanded_key[WORD(i) - WORD_SIZE];

		if (i % Nk == 0) {
			tmp = _sub_word(_rot_word(tmp));
			tmp[0] ^= rcon[i / Nk];
		} else if (Nk > 6 && i % Nk == 4) {
			tmp = _sub_word(tmp);
		}

		fixed_xor_raw(&expanded_key[WORD(i - Nk)], tmp, WORD_SIZE,
			      &expanded_key[WORD(i)]);
	}

	*out = expanded_key;

	return 0;

err0:
	return -1;
}

static void
_add_round_key(uint8_t *state, const uint8_t *round_key)
{
	uint8_t tmp[WORD_SIZE][NB];

	_to_state(round_key, tmp);
	fixed_xor_raw(state, (uint8_t *)tmp, AES_BLOCK_SIZE, state);
}

static void
_sub_bytes(uint8_t (*state)[NB])
{
	int row, col;

	for (row = 0; row < WORD_SIZE; row++) {
		for (col = 0; col < NB; col++) {
			state[row][col] = SUB(state[row][col], sbox);
		}
	}
}

static void
_shift_rows(uint8_t (*state)[NB])
{
	int row, j;
	uint8_t tmp;

	for (row = 1; row < WORD_SIZE; row++) {
		for (j = 0; j < row; j++) {
			tmp = state[row][0];
			memmove(&state[row][0], &state[row][1], NB - 1);
			state[row][NB - 1] = tmp;
		}
	}
}

static void
_mix_columns(uint8_t (*state)[NB])
{
	int col;
	uint8_t tmp[WORD_SIZE][NB];

	for (col = 0; col < NB; col++) {
		tmp[0][col] = gmultiply2[state[0][col]] ^
			      gmultiply3[state[1][col]] ^
			      state[2][col] ^
			      state[3][col];
		tmp[1][col] = state[0][col] ^
			      gmultiply2[state[1][col]] ^
			      gmultiply3[state[2][col]] ^
			      state[3][col];
		tmp[2][col] = state[0][col] ^
			      state[1][col] ^
			      gmultiply2[state[2][col]] ^
			      gmultiply3[state[3][col]];
		tmp[3][col] = gmultiply3[state[0][col]] ^
			      state[1][col] ^
			      state[2][col] ^
			      gmultiply2[state[3][col]];
	}

	memcpy(state, tmp, sizeof(tmp));
}

static void
_encrypt_block(const uint8_t *in, const uint8_t *round_keys,
	       enum aes_num_rounds num_rounds, uint8_t *out)
{
	unsigned int i;
	uint8_t state[WORD_SIZE][NB];

	_to_state(in, state);

	_add_round_key((uint8_t *)state, &round_keys[0]);

	for (i = 1; i < num_rounds; i++) {
		_sub_bytes(state);
		_shift_rows(state);
		_mix_columns(state);
                _add_round_key((uint8_t *)state,
                               &round_keys[i * AES_BLOCK_SIZE]);
        }

	_sub_bytes(state);
	_shift_rows(state);
	_add_round_key((uint8_t *)state,
		       &round_keys[num_rounds * AES_BLOCK_SIZE]);

	_from_state(state, out);
}

int
aes_ecb_encrypt_raw(const uint8_t *in, size_t isize,
		    const uint8_t *key, size_t ksize,
		    uint8_t *out)
{
	int rc;
	uint8_t *round_keys;
	size_t i;
	enum aes_key_size key_size;

	if (in == NULL || key == NULL || out == NULL ||
	    (isize % AES_BLOCK_SIZE != 0) ||
	    (ksize != AES_128_KEY_SIZE &&
	     ksize != AES_192_KEY_SIZE &&
	     ksize != AES_256_KEY_SIZE)) {
		goto err0;
	}
	key_size = (enum aes_key_size)ksize;

	rc = _expand_key(key, key_size, &round_keys);
	if (rc < 0) {
		goto err0;
	}

	for (i = 0; i < isize; i += AES_BLOCK_SIZE) {
		_encrypt_block(&in[i], round_keys, _rounds(key_size), &out[i]);
	}

	free(round_keys);

	return 0;

err0:
	return -1;
}

int
aes_ecb_encrypt(const uint8_t *in, size_t isize,
		const uint8_t *key, size_t ksize,
		uint8_t **out)
{
	int rc;
	uint8_t *ciphertext;

	if (in == NULL || key == NULL || out == NULL) {
		goto err0;
	}

	if (isize == 0) {
		*out = NULL;
	} else {
		ciphertext = malloc(isize);
		if (ciphertext == NULL) {
			goto err0;
		}

		rc = aes_ecb_encrypt_raw(in, isize, key, ksize, ciphertext);
		if (rc < 0) {
			goto err1;
		}

		*out = ciphertext;
	}

	return 0;

err1:
	free(ciphertext);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

int
aes_ecb_encrypt_str(const uint8_t *in, size_t isize,
		    const uint8_t *key, size_t ksize,
		    char **out)
{
	int rc;
	char *ciphertext;

	if (in == NULL || key == NULL || out == NULL) {
		goto err0;
	}

	ciphertext = calloc(isize + 1, sizeof(*ciphertext));
	if (ciphertext == NULL) {
		goto err0;
	}

	rc = aes_ecb_encrypt_raw(in, isize, key, ksize, (uint8_t *)ciphertext);
	if (rc < 0) {
		goto err1;
	}

	*out = ciphertext;

	return 0;

err1:
	free(ciphertext);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

static void
_inverse_shift_rows(uint8_t (*state)[NB])
{
	int row, j;
	uint8_t tmp;

	for (row = 1; row < WORD_SIZE; row++) {
		for (j = 0; j < row; j++) {
			tmp = state[row][NB - 1];
			memmove(&state[row][1], &state[row][0], NB - 1);
			state[row][0] = tmp;
		}
	}
}

static void
_inverse_sub_bytes(uint8_t (*state)[NB])
{
	int row, col;

	for (row = 0; row < WORD_SIZE; row++) {
		for (col = 0; col < NB; col++) {
			state[row][col] = SUB(state[row][col], inverse_sbox);
		}
	}
}

static void
_inverse_mix_columns(uint8_t (*state)[NB])
{
	int col;
	uint8_t tmp[WORD_SIZE][NB];

	for (col = 0; col < NB; col++) {
		tmp[0][col] = gmultiply14[state[0][col]] ^
			      gmultiply11[state[1][col]] ^
			      gmultiply13[state[2][col]] ^
			      gmultiply9[state[3][col]];
		tmp[1][col] = gmultiply9[state[0][col]] ^
			      gmultiply14[state[1][col]] ^
			      gmultiply11[state[2][col]] ^
			      gmultiply13[state[3][col]];
		tmp[2][col] = gmultiply13[state[0][col]] ^
			      gmultiply9[state[1][col]] ^
			      gmultiply14[state[2][col]] ^
			      gmultiply11[state[3][col]];
		tmp[3][col] = gmultiply11[state[0][col]] ^
			      gmultiply13[state[1][col]] ^
			      gmultiply9[state[2][col]] ^
			      gmultiply14[state[3][col]];
	}

	memcpy(state, tmp, sizeof(tmp));
}

static void
_decrypt_block(const uint8_t *in, const uint8_t *round_keys,
	       enum aes_num_rounds num_rounds, uint8_t *out)
{
	unsigned int i;
	uint8_t state[WORD_SIZE][NB];

	_to_state(in, state);

	_add_round_key((uint8_t *)state,
		       &round_keys[num_rounds * AES_BLOCK_SIZE]);

	for (i = num_rounds; i > 1; i--) {
		_inverse_shift_rows(state);
		_inverse_sub_bytes(state);
		_add_round_key((uint8_t *)state,
			       &round_keys[(i - 1) * AES_BLOCK_SIZE]);
		_inverse_mix_columns(state);
	}

	_inverse_shift_rows(state);
	_inverse_sub_bytes(state);
	_add_round_key((uint8_t *)state, &round_keys[0]);

	_from_state(state, out);
}

int
aes_ecb_decrypt_raw(const uint8_t *in, size_t isize,
		    const uint8_t *key, size_t ksize,
		    uint8_t *out)
{
	int rc;
	uint8_t *round_keys;
	size_t i;
	enum aes_key_size key_size;

	if (in == NULL || key == NULL || out == NULL ||
	    (isize % AES_BLOCK_SIZE != 0) ||
	    (ksize != AES_128_KEY_SIZE &&
	     ksize != AES_192_KEY_SIZE &&
	     ksize != AES_256_KEY_SIZE)) {
		goto err0;
	}
	key_size = (enum aes_key_size)ksize;

	rc = _expand_key(key, key_size, &round_keys);
	if (rc < 0) {
		goto err0;
	}

	for (i = 0; i < isize; i += AES_BLOCK_SIZE) {
		_decrypt_block(&in[i], round_keys, _rounds(key_size), &out[i]);
	}

	free(round_keys);

	return 0;

err0:
	return -1;
}

int
aes_ecb_decrypt(const uint8_t *in, size_t isize,
		const uint8_t *key, size_t ksize,
		uint8_t **out)
{
	int rc;
	uint8_t *plaintext;

	if (in == NULL || key == NULL || out == NULL) {
		goto err0;
	}

	if (isize == 0) {
		*out = NULL;
	} else {
		plaintext = malloc(isize);
		if (plaintext == NULL) {
			goto err0;
		}

		rc = aes_ecb_decrypt_raw(in, isize, key, ksize, plaintext);
		if (rc < 0) {
			goto err1;
		}

		*out = plaintext;
	}

	return 0;

err1:
	free(plaintext);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}

int
aes_ecb_decrypt_str(const uint8_t *in, size_t isize,
		    const uint8_t *key, size_t ksize,
		    char **out)
{
	int rc;
	char *plaintext;

	if (in == NULL || key == NULL || out == NULL) {
		goto err0;
	}

	plaintext = calloc(isize + 1, sizeof(*plaintext));
	if (plaintext == NULL) {
		goto err0;
	}

	rc = aes_ecb_decrypt_raw(in, isize, key, ksize, (uint8_t *)plaintext);
	if (rc < 0) {
		goto err1;
	}

	*out = plaintext;

	return 0;

err1:
	free(plaintext);
err0:
	if (out != NULL) {
		*out = NULL;
	}
	return -1;
}
