// The system OpenSSL's headers (-Dimpl=openssl), translated by the build
// into the `c` module. Add a header here when ztls starts using it.
//
// Many of OpenSSL's calls are macros over SSL_ctrl and BIO_ctrl, which
// translate-c may not carry over; ztls calls those underlying functions.
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
