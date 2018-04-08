set(tests
	test_aes
	test_base64
	test_hex
	test_xor
)

foreach(test ${tests})
	add_executable(${test} ${test}.c)
	add_test(NAME ${test} COMMAND ${test})
	target_link_libraries(${test} cryptopals)
endforeach(test)
