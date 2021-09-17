message(STATUS "Enter test/")

add_executable(${mdatest}
	${CMAKE_SOURCE_DIR}/test/test.cpp
	)

target_link_libraries(${mdatest}
    ${mdalib}
    )
