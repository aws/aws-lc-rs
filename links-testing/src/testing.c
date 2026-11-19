#include <openssl/is_awslc.h>
#include <openssl/evp.h>
#if LINKS_TESTING_FULL_LIBCRYPTO
#include <openssl/x509.h>
#endif

int testing_evp_key_type(int nid) {
#if LINKS_TESTING_FULL_LIBCRYPTO
    // X509_free is outside the universal bindings, so this links only against
    // the full libcrypto, which the sys crate reports as libcrypto_full=1.
    X509_free(NULL);
#endif
    return EVP_PKEY_type(nid);
}
