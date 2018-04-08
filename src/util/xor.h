#ifndef CRYPTOPALS_UTIL_XOR_H
#define CRYPTOPALS_UTIL_XOR_H

#include <stddef.h>
#include <stdint.h>

int fixed_xor_raw(const uint8_t *in1, const uint8_t *in2, size_t isize,
		  uint8_t *out);
int fixed_xor(const uint8_t *in1, const uint8_t *in2, size_t isize,
	      uint8_t **out);

int single_byte_xor_raw(const uint8_t *in, size_t isize, uint8_t byte,
			uint8_t *out);
int single_byte_xor(const uint8_t *in, size_t isize, uint8_t byte,
		    uint8_t **out);
int single_byte_xorstr(const uint8_t *in, size_t isize, uint8_t byte,
		       char **out);

int break_single_byte_xor(const uint8_t *in, size_t isize, uint8_t *okey);
int break_single_byte_xor_score(const uint8_t *in, size_t isize,
				uint8_t *okey, size_t *oscore);

int repeating_key_xor_raw(const uint8_t *in, size_t isize,
			  const uint8_t *key, size_t ksize,
			  uint8_t *out);
int repeating_key_xor(const uint8_t *in, size_t isize,
		      const uint8_t *key, size_t ksize,
		      uint8_t **out);
int repeating_key_xorstr(const uint8_t *in, size_t isize,
			 const uint8_t *key, size_t ksize,
			 char **out);

#endif /* CRYPTOPALS_UTIL_XOR_H */
