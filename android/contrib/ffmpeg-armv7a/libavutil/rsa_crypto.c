#include <stddef.h>
#include <stdint.h>
#include "rsa_crypto.h"
#include "openssl/crypto.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "base64.h"
#include "log.h"
#include "time.h"
/*
static void test_rsa_encrypt( int bits, const char* seed, char* prikey, const char* pubkey ){
    BIO* bio_private = BIO_new(BIO_s_mem());
    BIO* bio_public = BIO_new(BIO_s_mem());
    BIO_write(bio_private,prikey,strlen(prikey));
    BIO_write(bio_public,pubkey,strlen(pubkey));
    RSA* privateRSA = NULL;
    RSA* publicRSA = NULL;
    privateRSA = PEM_read_bio_RSAPrivateKey(bio_private, &privateRSA, NULL, (void*)seed);
    publicRSA = PEM_read_bio_RSA_PUBKEY(bio_public, &publicRSA, NULL, NULL);
    BIO_free(bio_private);
    BIO_free(bio_public);
    
    int keySize = RSA_size(privateRSA);
    char decData[]="0123456789 0123456789 0123456789";
    char encData[2048];
    
    //public key encrypte, private key decrypt
    int  flen = strlen(decData);
    int retlen =  RSA_public_encrypt(flen, (unsigned char *)decData, (unsigned char *)encData, publicRSA,  RSA_PKCS1_PADDING);
    av_log(NULL, AV_LOG_DEBUG,"public key encrypt result enclen=%d, keylen=%d, timestamp=%lld\n", retlen, bits/8, av_gettime()/1000 );
    memset(decData, 0, sizeof(decData));
    retlen = RSA_private_decrypt(retlen, (unsigned char *)encData, (unsigned char *)decData, privateRSA, RSA_PKCS1_PADDING);
    av_log(NULL, AV_LOG_DEBUG,"private key decrypt result declen=%d, content=%s, timestamp=%lld\n",retlen, decData, av_gettime()/1000  );
    
    
    //private key encrypt, public key decrypt
    retlen =  RSA_private_encrypt(flen, (unsigned char *)decData, (unsigned char *)encData, privateRSA,  RSA_PKCS1_PADDING);
    av_log(NULL, AV_LOG_DEBUG,"private key encrypt result enclen=%d, keylen=%d, timestamp=%lld\n", retlen, bits/8, av_gettime()/1000 );
    memset(decData, 0, sizeof(decData));
    retlen = RSA_public_decrypt(retlen, (unsigned char *)encData, (unsigned char *)decData, publicRSA, RSA_PKCS1_PADDING);
    av_log(NULL, AV_LOG_DEBUG,"public key decrypt result declen=%d, content=%s, timestamp=%lld\n",retlen, decData, av_gettime()/1000 );
}
*/

int ff_rsa_decrypt( const char* seed, const char* private_key, const char* src, char** dst){
    OpenSSL_add_all_algorithms();
    BIO* bio_private = NULL;
    RSA* private_rsa = NULL;
    int ret = -1;
    if (src==NULL||private_key==NULL||seed==NULL) {
        av_log(NULL, AV_LOG_ERROR,"invalid decrypt paramter\n");
        return ret;
    }
    bio_private = BIO_new(BIO_s_mem());
    BIO_write(bio_private, private_key, strlen(private_key));
    private_rsa = PEM_read_bio_RSAPrivateKey(bio_private, &private_rsa, NULL, (void*)seed);
    if ( private_rsa ) {
        int enc_data_buflen = strlen(src);
        char* enc_data = av_malloc(enc_data_buflen);
        memset(enc_data, 0, enc_data_buflen );
        int enc_data_len = av_base64_decode_urlsafe(enc_data, src, enc_data_buflen);
        if (enc_data_len<0) {
            av_free(enc_data);
            av_log(NULL, AV_LOG_ERROR,"fail to base64 decode the content\n");
            goto finish_decrypt;
        }
        *dst = av_malloc(enc_data_buflen);
        memset(*dst, 0, enc_data_buflen );
        int retlen = RSA_private_decrypt(enc_data_len, (unsigned char *)enc_data, (unsigned char *)(*dst), private_rsa, RSA_PKCS1_PADDING);
        av_free(enc_data);
        if (retlen<=0 ) {
            av_log(NULL, AV_LOG_ERROR,"fail to decrypt content, srclen=%d\n",strlen(src));
            av_free(*dst);
            goto finish_decrypt;
        }
        av_log(NULL, AV_LOG_DEBUG,"success to decrypt content, dstlen=%d\n",retlen);
        ret = retlen;
    }else {
        av_log(NULL, AV_LOG_ERROR,"fail to read private key to decrypt content\n");
    }
finish_decrypt:
    if(bio_private) BIO_free(bio_private);
    if(private_rsa) RSA_free(private_rsa);
    return ret;
}

int ff_create_rsa_keys(enum RSABits bits, const char* seed, char** private_key, char** public_key ){
    if ( bits==RSA2048 ) {
        bits = 2048;
    }else{
        bits = 1024;
    }
    
    int64_t timebegin = (int64_t)av_gettime();
    //create rsa keys
    OpenSSL_add_all_algorithms();
    RAND_seed(seed, strlen(seed));
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    int ret = 0;
    if (!RSA_generate_key_ex(rsa, bits, bn, NULL)) {
        av_log(NULL, AV_LOG_ERROR, "fail to generate rsa keys\n");
        ret = -1;
        goto finish_create_rsa;
    }
    
    //read private and public keys
    BIO* bio_private = BIO_new(BIO_s_mem());
    BIO* bio_public = BIO_new(BIO_s_mem());
    if (!(bio_private && PEM_write_bio_RSAPrivateKey(bio_private, rsa, EVP_aes_128_cbc(), seed, strlen(seed), NULL, NULL))) {
        av_log(NULL, AV_LOG_ERROR, "fail to write private key\n");
        ret = -2;
        goto finish_create_rsa;
    }
    if(!(bio_public && PEM_write_bio_RSA_PUBKEY(bio_public, rsa))){
        av_log(NULL, AV_LOG_ERROR, "fail to write public key\n");
        ret = -3;
        goto finish_create_rsa;
    }
    
    size_t public_len = (size_t)BIO_pending(bio_public);
    size_t private_len = (size_t)BIO_pending(bio_private);
    *public_key = malloc(public_len + 1);
    *private_key = malloc(private_len + 1);
    memset(*public_key,0,public_len + 1);
    memset(*private_key,0,private_len + 1);
    if (*public_key) {
        BIO_read(bio_public, (char*)*public_key, public_len);
        av_log(NULL, AV_LOG_DEBUG,"create RSA public key: %s\n",*public_key);
    }
    if (*private_key) {
        BIO_read(bio_private, (char*)*private_key, private_len);
        av_log(NULL, AV_LOG_DEBUG,"create RSA private key: %s\n",*private_key);
    }
    
finish_create_rsa:
    if(bn) BN_free(bn);
    if(rsa) RSA_free(rsa);
    if (bio_private) BIO_free(bio_private);
    if (bio_public) BIO_free(bio_public);
    av_log(NULL, AV_LOG_DEBUG,"create RSA keys finish, ret=%d, bits=%d, escape=%lld\n",ret, bits, (av_gettime()-timebegin)/1000);
    //test_rsa_encrypt(bits, seed, *private_key, *public_key);
    return ret;
}
