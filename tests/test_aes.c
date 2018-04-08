/* Include implementation to test static functions. */
#include "util/aes.c"

#include <stdio.h>
#include <stdlib.h>

#include "test.h"
#include "util/hex.h"

typedef void (*transformation_function)(uint8_t (*state)[NB]);

struct transformation_test_case {
	char *input_hexstr;
	char *expected_output_hexstr;
};

static struct aes_test_case {
	char *plaintext_hexstr;
	char *ciphertext_hexstr;
	char *key_hexstr;
} aes_test_cases[] = {
	/* AES-128 */
	{"00112233445566778899aabbccddeeff",
	 "69c4e0d86a7b0430d8cdb78070b4c55a",
	 "000102030405060708090a0b0c0d0e0f"},
	/* AES-192 */
	{"00112233445566778899aabbccddeeff",
	 "dda97ca4864cdfe06eaf70a0ec0d7191",
	 "000102030405060708090a0b0c0d0e0f1011121314151617"},
	/* AES-256 */
	{"00112233445566778899aabbccddeeff",
	 "8ea2b7ca516745bfeafc49904b496089",
	 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}
};

static void
test_to_from_state(void)
{
	uint8_t state[WORD_SIZE][NB];
	uint8_t output[AES_BLOCK_SIZE];

	uint8_t input[AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03,
					 0x04, 0x05, 0x06, 0x07,
					 0x08, 0x09, 0x0a, 0x0b,
					 0x0c, 0x0d, 0x0e, 0x0f};

	uint8_t expected_state[AES_BLOCK_SIZE] = {0x00, 0x04, 0x08, 0x0c,
						  0x01, 0x05, 0x09, 0x0d,
						  0x02, 0x06, 0x0a, 0x0e,
						  0x03, 0x07, 0x0b, 0x0f};

	_to_state(input, state);
	ASSERT(memcmp(state, expected_state, ARRAY_SIZE(expected_state)) == 0);

	_from_state(state, output);
	ASSERT(memcmp(output, input, ARRAY_SIZE(output)) == 0);
}

static void
test_expand_key(void)
{
	int rc;
	uint8_t *expanded_key;
	size_t i;
	char *hexstr;

	static struct {
		enum aes_key_size key_size;
		uint8_t key[AES_256_KEY_SIZE];
		char *expanded_key_hexstr;
	} test_cases[] = {
		{AES_128_KEY_SIZE,
		 {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		 "2b7e151628aed2a6abf7158809cf4f3c"
		 "a0fafe1788542cb123a339392a6c7605"
		 "f2c295f27a96b9435935807a7359f67f"
		 "3d80477d4716fe3e1e237e446d7a883b"
		 "ef44a541a8525b7fb671253bdb0bad00"
		 "d4d1c6f87c839d87caf2b8bc11f915bc"
		 "6d88a37a110b3efddbf98641ca0093fd"
		 "4e54f70e5f5fc9f384a64fb24ea6dc4f"
		 "ead27321b58dbad2312bf5607f8d292f"
		 "ac7766f319fadc2128d12941575c006e"
		 "d014f9a8c9ee2589e13f0cc8b6630ca6"
		},
		{AES_192_KEY_SIZE,
		 {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		  0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		  0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b},
		 "8e73b0f7da0e6452c810f32b809079e5"
		 "62f8ead2522c6b7bfe0c91f72402f5a5"
		 "ec12068e6c827f6b0e7a95b95c56fec2"
		 "4db7b4bd69b5411885a74796e92538fd"
		 "e75fad44bb095386485af05721efb14f"
		 "a448f6d94d6dce24aa326360113b30e6"
		 "a25e7ed583b1cf9a27f939436a94f767"
		 "c0a69407d19da4e1ec1786eb6fa64971"
		 "485f703222cb8755e26d135233f0b7b3"
		 "40beeb282f18a2596747d26b458c553e"
		 "a7e1466c9411f1df821f750aad07d753"
		 "ca4005388fcc5006282d166abc3ce7b5"
		 "e98ba06f448c773c8ecc720401002202"
		},
		{AES_256_KEY_SIZE,
		 {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4},
		 "603deb1015ca71be2b73aef0857d7781"
		 "1f352c073b6108d72d9810a30914dff4"
		 "9ba354118e6925afa51a8b5f2067fcde"
		 "a8b09c1a93d194cdbe49846eb75d5b9a"
		 "d59aecb85bf3c917fee94248de8ebe96"
		 "b5a9328a2678a647983122292f6c79b3"
		 "812c81addadf48ba24360af2fab8b464"
		 "98c5bfc9bebd198e268c3ba709e04214"
		 "68007bacb2df331696e939e46c518d80"
		 "c814e20476a9fb8a5025c02d59c58239"
		 "de1369676ccc5a71fa2563959674ee15"
		 "5886ca5d2e2f31d77e0af1fa27cf73c3"
		 "749c47ab18501ddae2757e4f7401905a"
		 "cafaaae3e4d59b349adf6acebd10190d"
		 "fe4890d1e6188d0b046df344706c631e"
		}
	};

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		rc = _expand_key(test_cases[i].key, test_cases[i].key_size,
				 &expanded_key);
		ASSERT(rc == 0);

		rc = bytes_to_hexstr(expanded_key,
				     AES_BLOCK_SIZE *
					 (_rounds(test_cases[i].key_size) + 1),
				     &hexstr);
		ASSERT(rc == 0);
		ASSERT(strcmp(hexstr, test_cases[i].expanded_key_hexstr) == 0);

		free(hexstr);
		free(expanded_key);
	};
}

static void
_test_state_transformation(transformation_function fn,
			   struct transformation_test_case *test_cases,
			   size_t num_test_cases)
{
	int rc;
	uint8_t *bytes;
	uint8_t state[WORD_SIZE][NB];
	size_t i, bytes_size;
	char *hexstr;

	for (i = 0; i < num_test_cases; i++) {
		rc = hexstr_to_bytes(test_cases[i].input_hexstr,
				     &bytes, &bytes_size);
		ASSERT(rc == 0);

		_to_state(bytes, state);
		fn(state);
		_from_state(state, bytes);

		rc = bytes_to_hexstr(bytes, bytes_size, &hexstr);
		ASSERT(rc == 0);
		rc = strcmp(hexstr, test_cases[i].expected_output_hexstr);
		ASSERT(rc == 0);

		free(hexstr);
		free(bytes);
	}
}

static void
test_sub_bytes(void) {
	struct transformation_test_case test_cases[] = {
	    {"00102030405060708090a0b0c0d0e0f0",
	     "63cab7040953d051cd60e0e7ba70e18c"},
	    {"4f63760643e0aa85aff8c9d041fa0de4",
	     "84fb386f1ae1ac977941dd70832dd769"},
	    {"1859fbc28a1c00a078ed8aadc42f6109",
	     "adcb0f257e9c63e0bc557e951c15ef01"}
	};

	_test_state_transformation(_sub_bytes, test_cases,
				   ARRAY_SIZE(test_cases));
}

static void
test_shift_rows(void) {
	struct transformation_test_case test_cases[] = {
	    {"63cab7040953d051cd60e0e7ba70e18c",
	     "6353e08c0960e104cd70b751bacad0e7"},
	    {"1f770c64f0b579deaaac432c3d37cf0e",
	     "1fb5430ef0accf64aa370cde3d77792c"},
	    {"adcb0f257e9c63e0bc557e951c15ef01",
	     "ad9c7e017e55ef25bc150fe01ccb6395"}
	};

	_test_state_transformation(_shift_rows, test_cases,
				   ARRAY_SIZE(test_cases));
}

static void
test_mix_columns(void) {
	struct transformation_test_case test_cases[] = {
	    {"6353e08c0960e104cd70b751bacad0e7",
	     "5f72641557f5bc92f7be3b291db9f91a"},
	    {"1fb5430ef0accf64aa370cde3d77792c",
	     "b7a53ecbbf9d75a0c40efc79b674cc11"},
	    {"ad9c7e017e55ef25bc150fe01ccb6395",
	     "810dce0cc9db8172b3678c1e88a1b5bd"}
	};

	_test_state_transformation(_mix_columns, test_cases,
				   ARRAY_SIZE(test_cases));
}

static void
test_inverse_shift_rows(void)
{
	struct transformation_test_case test_cases[] = {
	    {"7ad5fda789ef4e272bca100b3d9ff59f",
	     "7a9f102789d5f50b2beffd9f3dca4ea7"},
	    {"793e76979c3403e9aab7b2d10fa96ccc",
	     "79a9b2e99c3e6cd1aa3476cc0fb70397"},
	    {"aa5ece06ee6e3c56dde68bac2621bebf",
	     "aa218b56ee5ebeacdd6ecebf26e63c06"}
	};

	_test_state_transformation(_inverse_shift_rows, test_cases,
				   ARRAY_SIZE(test_cases));
}

static void
test_inverse_sub_bytes(void) {
	struct transformation_test_case test_cases[] = {
	    {"7a9f102789d5f50b2beffd9f3dca4ea7",
	     "bd6e7c3df2b5779e0b61216e8b10b689"},
	    {"79a9b2e99c3e6cd1aa3476cc0fb70397",
	     "afb73eeb1cd1b85162280f27fb20d585"},
	    {"aa218b56ee5ebeacdd6ecebf26e63c06",
	     "627bceb9999d5aaac945ecf423f56da5"}
	};

	_test_state_transformation(_inverse_sub_bytes, test_cases,
				   ARRAY_SIZE(test_cases));
}

static void
test_inverse_mix_columns(void)
{
	struct transformation_test_case test_cases[] = {
	    {"e9f74eec023020f61bf2ccf2353c21c7",
	     "54d990a16ba09ab596bbf40ea111702f"},
	    {"71d720933b6d677dc00b8f28238e0fb7",
	     "c494bffae62322ab4bb5dc4e6fce69dd"},
	    {"2c21a820306f154ab712c75eee0da04f",
	     "d1ed44fd1a0f3f2afa4ff27b7c332a69"}
	};

	_test_state_transformation(_inverse_mix_columns, test_cases,
				   ARRAY_SIZE(test_cases));
}

static void
test_aes_encrypt_block(void)
{
	int rc;
	uint8_t *key, *round_keys;
	uint8_t plaintext[AES_BLOCK_SIZE], ciphertext[AES_BLOCK_SIZE];
	size_t i, key_size;
	char *hexstr;

	for (i = 0; i < ARRAY_SIZE(aes_test_cases); i++) {
		rc = hexstr_to_bytes(aes_test_cases[i].key_hexstr,
				     &key, &key_size);
		ASSERT(rc == 0);

		rc = _expand_key(key, (enum aes_key_size)key_size, &round_keys);
		ASSERT(rc == 0);

		rc = hexstr_to_bytes_raw(
		    aes_test_cases[i].plaintext_hexstr,
		    strlen(aes_test_cases[i].plaintext_hexstr),
		    plaintext, AES_BLOCK_SIZE);
		ASSERT(rc == 0);

		_encrypt_block(plaintext, round_keys,
			       _rounds((enum aes_key_size)key_size),
			       ciphertext);

		rc = bytes_to_hexstr(ciphertext, AES_BLOCK_SIZE, &hexstr);
		ASSERT(rc == 0);

		rc = strcmp(hexstr, aes_test_cases[i].ciphertext_hexstr);
		ASSERT(rc == 0);

		free(hexstr);
		free(round_keys);
		free(key);
	}
}

static void
test_aes_decrypt_block(void)
{
	int rc;
	uint8_t *key, *round_keys;
	uint8_t ciphertext[AES_BLOCK_SIZE], plaintext[AES_BLOCK_SIZE];
	size_t i, key_size;
	char *hexstr;

	for (i = 0; i < ARRAY_SIZE(aes_test_cases); i++) {
		rc = hexstr_to_bytes(aes_test_cases[i].key_hexstr,
				     &key, &key_size);
		ASSERT(rc == 0);

		rc = _expand_key(key, (enum aes_key_size)key_size, &round_keys);
		ASSERT(rc == 0);

		rc = hexstr_to_bytes_raw(
		    aes_test_cases[i].ciphertext_hexstr,
		    strlen(aes_test_cases[i].ciphertext_hexstr),
		    ciphertext, AES_BLOCK_SIZE);
		ASSERT(rc == 0);

		_decrypt_block(ciphertext, round_keys,
			       _rounds((enum aes_key_size)key_size),
			       plaintext);

		rc = bytes_to_hexstr(plaintext, AES_BLOCK_SIZE, &hexstr);
		ASSERT(rc == 0);

		rc = strcmp(hexstr, aes_test_cases[i].plaintext_hexstr);
		ASSERT(rc == 0);

		free(hexstr);
		free(round_keys);
		free(key);
	}
}

int
main(void)
{
	test_to_from_state();
	test_expand_key();

	test_sub_bytes();
	test_shift_rows();
	test_mix_columns();

	test_inverse_shift_rows();
	test_inverse_sub_bytes();
	test_inverse_mix_columns();

	test_aes_encrypt_block();
	test_aes_decrypt_block();

	exit(EXIT_SUCCESS);
}
