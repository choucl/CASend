include_directories(${CASend_SOURCE_DIR}/inc)
find_package(OpenMP)

set(COMMON_SOURCES packet.c pbar.c rsa.c sock.c util.c)
set(LINK_LIBS m pthread crypto)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_C_FLAGS "-DQUIET=0 -DOPENSSL_API_COMPAT=11001")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -DDEBUG")

add_library(CommonModule ${COMMON_SOURCES})
add_library(ClientModule sender.c receiver.c register.c)
add_executable(server server.c)
add_executable(casend casend.c)
target_link_libraries(ClientModule CommonModule)
target_link_libraries(server CommonModule ${LINK_LIBS})
target_link_libraries(casend ClientModule ${LINK_LIBS} OpenMP::OpenMP_C)
