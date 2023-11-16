#include <openssl/is_awslc.h>
#include <openssl/evp.h>

int testing_evp_key_type(int nid) {
    return EVP_PKEY_type(nid);
}
