#include <openssl/evp.h>

int main(){
    const EVP_MD* a = EVP_md5();
    const EVP_MD* b = EVP_sha1();
    (void)a; (void)b;
    return 0;
}
