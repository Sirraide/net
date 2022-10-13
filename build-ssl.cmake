function(build)
    ## Get the current git hash.
    execute_process (
        COMMAND git rev-parse HEAD
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/libs/openssl"
        OUTPUT_VARIABLE git_hash
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY
    )

    ## Determine if we need to rebuild.
    if(EXISTS "${CMAKE_SOURCE_DIR}/out/ssl-ver.txt")
        file(READ "${CMAKE_SOURCE_DIR}/out/ssl-ver.txt" ssl_ver)
        if(ssl_ver STREQUAL git_hash)
            message(STATUS "OpenSSL is up to date")
            return()
        endif()
    endif()

    ## Configure and build OpenSSL.
    message(STATUS "Building OpenSSL")
    execute_process(
        COMMAND nproc
        OUTPUT_VARIABLE nproc
        COMMAND_ERROR_IS_FATAL ANY
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process (
        COMMAND ./config "--prefix=${CMAKE_SOURCE_DIR}/out/openssl" "--openssldir=${CMAKE_SOURCE_DIR}/out/openssl"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/libs/openssl"
        ECHO_ERROR_VARIABLE
        ECHO_OUTPUT_VARIABLE
        COMMAND_ERROR_IS_FATAL ANY
    )
    execute_process (
        COMMAND make -j ${nproc}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/libs/openssl"
        ECHO_ERROR_VARIABLE
        ECHO_OUTPUT_VARIABLE
        COMMAND_ERROR_IS_FATAL ANY
    )

    file(WRITE "${CMAKE_SOURCE_DIR}/out/ssl-ver.txt" "${git_hash}")
endfunction()

build()