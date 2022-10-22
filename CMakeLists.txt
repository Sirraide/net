cmake_minimum_required(VERSION 3.21)
project(net VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

add_compile_options(-fdiagnostics-color=always -fPIC)
add_definitions(-DNET_SSL_CERT="${PROJECT_SOURCE_DIR}/libs/openssl/apps/cert.pem")

##
## Targets
##

## OpenSSL
add_custom_target (
	openssl
	WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
	COMMAND ${CMAKE_COMMAND} -P "${PROJECT_SOURCE_DIR}/build-ssl.cmake"
	BYPRODUCTS ${PROJECT_SOURCE_DIR}/libs/libcrypto.so ${PROJECT_SOURCE_DIR}/libs/libssl.so
	USES_TERMINAL
)

## Other Targets

file(GLOB CLI src/client.cc)
file(GLOB SRV src/server.cc)

set(ENABLE_WEBSOCKETS ON)

add_subdirectory(libs/fmt)
add_subdirectory(libs/curl)
add_executable(client ${CLI})
add_executable(server ${SRV})

##
## Compile options
##

add_library(options INTERFACE)
target_compile_options(options INTERFACE
        -Wall -Wextra -Wundef -Werror=return-type
        -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable -Wno-subobject-linkage
        -Wno-unused-label
        -Wno-empty-body -Wno-nonnull -Wno-invalid-offsetof -fdiagnostics-color=always)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(options INTERFACE -O3 -march=native -DNDEBUG)
else ()
	target_compile_options(options INTERFACE -O0 -ggdb -rdynamic)
	target_link_options(options INTERFACE -rdynamic)
endif ()

target_include_directories(options INTERFACE include libs/fmt/include libs/json/include libs/curl/include)

add_dependencies(options openssl)
target_link_libraries(options INTERFACE
	fmt
	libcurl
	${PROJECT_SOURCE_DIR}/libs/libcrypto.so
	${PROJECT_SOURCE_DIR}/libs/libssl.so
)

target_link_libraries(client PRIVATE options fmt libcurl)
target_link_libraries(server PRIVATE options fmt libcurl)
