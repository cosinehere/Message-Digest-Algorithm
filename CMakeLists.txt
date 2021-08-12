# minimum cmake version
cmake_minimum_required(VERSION 3.16)

# specify project name and version
project(MessageDigestAlgorithm
	VERSION 1.0
	LANGUAGES CXX)

# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# global g++ compile flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

# MessageDigestAlgorithm.so
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
add_library(MessageDigestAlgorithm SHARED
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_MD5.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_SHA1.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_SHA256.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_SHA512.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/mdadefines.cpp
	)
target_precompile_headers(MessageDigestAlgorithm PRIVATE
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/pch.h
    )
target_compile_options(MessageDigestAlgorithm
    PRIVATE -fvisibility=hidden
    )
target_link_options(MessageDigestAlgorithm
    PRIVATE -Wl,-s
    )

# MessageDigestAlgorithmTest
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
add_executable(MDATest
	${CMAKE_SOURCE_DIR}/test/test.cpp
	)
target_link_libraries(MDATest MessageDigestAlgorithm)

