cmake_minimum_required(VERSION 3.16...3.29)
project(kookmin_lib_provider C)

# Silence CMP0144 warning on newer CMake
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# If user exported OPENSSL_ROOT, use it to set the var FindOpenSSL expects
if(DEFINED ENV{OPENSSL_ROOT} AND NOT DEFINED OPENSSL_ROOT_DIR)
  set(OPENSSL_ROOT_DIR "$ENV{OPENSSL_ROOT}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Try the stock FindOpenSSL first
find_package(OpenSSL 3.0 QUIET COMPONENTS Crypto)
if(NOT OpenSSL_FOUND)
  # Your custom fallback module
  find_package(OpenSSL3 REQUIRED)
endif()

find_package(liboqs REQUIRED)

add_library(kookminlib MODULE
    src/bio.c
    src/kem/kem.c
    src/keys.c
    src/capabilities.c
    src/keymgmt.c
    src/provider.c
    src/encdec/encoder.c
    src/encdec/decoder.c
    src/sig/sig.c
)

set_target_properties(kookminlib PROPERTIES
    OUTPUT_NAME "kookminlib"
    PREFIX ""  # providers usually have no 'lib' prefix
)

target_include_directories(kookminlib PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${liboqs_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (TARGET OpenSSL::Crypto)
  target_link_libraries(kookminlib PRIVATE OpenSSL::Crypto ${liboqs_LIBRARIES})
else()
  target_link_libraries(kookminlib PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${liboqs_LIBRARIES})
endif()

include(GNUInstallDirs)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SIZEOF_VOID_P EQUAL 8
   AND NOT DEFINED CMAKE_INSTALL_LIBDIR)
  set(CMAKE_INSTALL_LIBDIR "lib")
endif()
install(TARGETS kookminlib
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/ossl-modules)

message(STATUS "Using OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Using liboqs include: ${liboqs_INCLUDE_DIRS}")
