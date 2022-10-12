cmake_minimum_required(VERSION 3.21)
project(net VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

add_compile_options(-fdiagnostics-color=always -fPIC)

##
## Targets
##

file(GLOB CLI src/client.cc)
file(GLOB SRV src/server.cc)

add_subdirectory(libs/fmt)
add_executable(client ${CLI})
add_executable(server ${SRV})

##
## Compile options
##

add_library(options INTERFACE)
target_compile_options(options INTERFACE
        -Wall -Wextra -Wundef -Werror=return-type
        -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable -Wno-subobject-linkage
        -Wno-empty-body -Wno-nonnull -Wno-invalid-offsetof -fdiagnostics-color=always)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(options INTERFACE -O3 -DNDEBUG)
else ()
	target_compile_options(options INTERFACE -O0 -ggdb -rdynamic)
	target_link_options(options INTERFACE -rdynamic)
endif ()

target_include_directories(options INTERFACE include)

target_link_libraries(client PRIVATE options fmt)
target_link_libraries(server PRIVATE options fmt)
