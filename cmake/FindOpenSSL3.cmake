find_path(OPENSSL_INCLUDE_DIR
NAMES openssl/opensslv.h
HINTS $ENV{OPENSSL_ROOT_DIR}/include /usr/local/include /opt/homebrew/include /usr/include
)


find_library(OPENSSL_CRYPTO_LIBRARY
NAMES crypto libcrypto
HINTS $ENV{OPENSSL_ROOT_DIR}/lib /usr/local/lib /opt/homebrew/lib /usr/lib
)


include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenSSL3 DEFAULT_MSG OPENSSL_INCLUDE_DIR OPENSSL_CRYPTO_LIBRARY)


mark_as_advanced(OPENSSL_INCLUDE_DIR OPENSSL_CRYPTO_LIBRARY)