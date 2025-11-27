include_directories(
    .
)

set(example_SRCS
    cs104_client_aprofile_debug.c
    cs104_server_aprofile_debug.c
)

IF(WIN32)
set_source_files_properties(${example_SRCS}
                                      PROPERTIES LANGUAGE CXX)
ENDIF(WIN32)

add_executable(cs104_client_aprofile_debug
  cs104_client_aprofile_debug.c
)

target_link_libraries(cs104_client_aprofile_debug
    lib60870
)

add_executable(cs104_server_aprofile_debug
  cs104_server_aprofile_debug.c
)

target_link_libraries(cs104_server_aprofile_debug
    lib60870
)
