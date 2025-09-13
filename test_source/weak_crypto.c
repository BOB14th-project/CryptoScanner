#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

int main(){
    DES_cblock key = {0};
    DES_key_schedule ks;
    DES_set_key(&key, &ks);
    unsigned char in[8]={0}, out[8]={0};
    DES_ecb_encrypt((const_DES_cblock*)in, (DES_cblock*)out, &ks, 1);
    RC4_KEY rck;
    unsigned char k[16]={0}, buf[16]={0};
    RC4_set_key(&rck, 16, k);
    RC4(&rck, 16, buf, buf);
    MD5_CTX m; MD5_Init(&m);
    SHA_CTX s; SHA1_Init(&s);
    return 0;
}
