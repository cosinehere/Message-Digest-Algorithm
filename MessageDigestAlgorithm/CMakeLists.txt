message(STATUS "Enter MessageDigestAlgorithm/")

add_library(${mdalib} SHARED
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_MD5.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_SHA1.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_SHA256.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_SHA512.cpp
    ${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/CMDA_SM3.cpp
	${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/mdadefines.cpp
	)

target_precompile_headers(${mdalib}
    PRIVATE ${CMAKE_SOURCE_DIR}/MessageDigestAlgorithm/pch.h
    )

target_compile_options(${mdalib}
    PRIVATE -fvisibility=hidden
    )

target_link_options(${mdalib}
    PRIVATE -Wl,-s
    )