#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

int main(void){
    HCRYPTPROV h = 0;
    CryptAcquireContextA(&h, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    BCRYPT_ALG_HANDLE a = 0;
    BCryptOpenAlgorithmProvider(&a, BCRYPT_MD5_ALGORITHM, 0, 0);
    HCERTSTORE s = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, 0);
    if(s) CertCloseStore(s, 0);
    if(a) BCryptCloseAlgorithmProvider(a, 0);
    if(h) CryptReleaseContext(h, 0);
    return 0;
}
