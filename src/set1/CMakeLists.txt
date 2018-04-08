set(challenges
	1-convert-hex-to-base64
	2-fixed-xor
	3-single-byte-xor-cipher
	4-detect-single-character-xor
	5-implement-repeating-key-xor
	6-break-repeating-key-xor
	7-aes-in-ecb-mode
	8-detect-aes-in-ecb-mode
)

foreach(challenge ${challenges})
	add_executable(${challenge} ${challenge}.c)
	target_link_libraries(${challenge} cryptopals)
endforeach(challenge)
