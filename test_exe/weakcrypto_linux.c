#include <openssl/des.h>
#include <openssl/md5.h>

int main(){
    DES_cblock key = {0};
    DES_key_schedule ks;
    DES_set_key(&key, &ks);
    MD5_CTX m;
    MD5_Init(&m);
    return 0;
}
