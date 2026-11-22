if(NOT PD_OPENSSL_PREFIX OR NOT PD_XZ_PREFIX)
    message(STATUS "Skipping pd-update-installer: OpenSSL/XZ prefixes are not configured")
    return()
endif()

add_darwin_executable(pd-update-installer MACOSX_VERSION_MIN 26.5)

find_path(PD_OPENSSL_INCLUDE_DIR openssl/evp.h
    PATHS "${PD_OPENSSL_PREFIX}/include"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
    REQUIRED)
find_library(PD_OPENSSL_CRYPTO_LIBRARY crypto
    PATHS "${PD_OPENSSL_PREFIX}/lib"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
    REQUIRED)
find_path(PD_XZ_INCLUDE_DIR lzma.h
    PATHS "${PD_XZ_PREFIX}/include"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
    REQUIRED)
find_library(PD_XZ_LIBRARY lzma
    PATHS "${PD_XZ_PREFIX}/lib"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
    REQUIRED)

target_sources(pd-update-installer PRIVATE main.c)
target_include_directories(pd-update-installer PRIVATE
    "${PD_OPENSSL_INCLUDE_DIR}" "${PD_XZ_INCLUDE_DIR}")
target_compile_options(pd-update-installer PRIVATE
    -fno-stack-protector -fno-exceptions
    -fno-unwind-tables -fno-asynchronous-unwind-tables)
target_link_libraries(pd-update-installer PRIVATE
    "${PD_OPENSSL_CRYPTO_LIBRARY}" "${PD_XZ_LIBRARY}")
install(TARGETS pd-update-installer DESTINATION sbin COMPONENT BaseSystem)
