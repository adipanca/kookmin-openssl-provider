cmake_minimum_required(VERSION 3.16)
project(kookmin_oqs_provider C)


set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)


# Opsi: Anda bisa set OPENSSL_ROOT_DIR jika build OpenSSL kustom
# cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/openssl-master


list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")


find_package(OpenSSL 3.0 QUIET COMPONENTS Crypto)
if(NOT OpenSSL_FOUND)
    find_package(OpenSSL3 REQUIRED) # fallback pencarian kustom
endif()


find_package(liboqs REQUIRED)


add_library(kookminlib MODULE
    src/provider_core.c
    src/km_util.c
    
    # SIGNATURE
    src/sig/sig_ops.c
    src/sig/sig_keymgmt.c

    # KEM
    src/kem/kem_ops.c
    src/kem/kem_keymgmt.c
)


# Nama modul provider = nama file .so yang akan diload OpenSSL
set_target_properties(kookminlib PROPERTIES
    OUTPUT_NAME "kookminlib"
    PREFIX "" # provider biasanya tanpa prefix 'lib'
)


# Header
target_include_directories(kookminlib PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${liboqs_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)


# Link libcrypto dan liboqs
if (TARGET OpenSSL::Crypto)
    target_link_libraries(kookminlib PRIVATE OpenSSL::Crypto ${liboqs_LIBRARIES})
else()
    target_link_libraries(kookminlib PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${liboqs_LIBRARIES})
endif()


# Di Linux, provider diletakkan di $lib/ossl-modules/
include(GNUInstallDirs)
# Default ke lib64 di Linux 64-bit, selain itu biarkan default GNUInstallDirs
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SIZEOF_VOID_P EQUAL 8
   AND NOT DEFINED CMAKE_INSTALL_LIBDIR)
  set(CMAKE_INSTALL_LIBDIR "lib64")
endif()
install(TARGETS kookminlib
LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/ossl-modules)


message(STATUS "Using OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Using liboqs include: ${liboqs_INCLUDE_DIRS}")