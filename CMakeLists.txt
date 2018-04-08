#
# Project properties
#
cmake_minimum_required(VERSION 3.5)
project(cryptopals)

#
# Project options
#
option(CRYPTOPALS_BUILD_TESTS "Build the tests." ON)

#
# Project paths

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")
include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/src")

#
# Compiler flags
#
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
	-Wall \
	-Werror")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} \
	-Weverything \
	-Wno-padded \
	-fno-omit-frame-pointer \
	-fsanitize=address \
	-fsanitize=undefined \
	-fsanitize=integer \
	-fsanitize=nullability")

#
# Build targets
#
add_subdirectory(src)
if(CRYPTOPALS_BUILD_TESTS)
	enable_testing()
	add_subdirectory(tests)
endif(CRYPTOPALS_BUILD_TESTS)
