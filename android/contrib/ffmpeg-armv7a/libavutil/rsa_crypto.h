

#ifndef RSA_CRYPTO_H
#define RSA_CRYPTO_H


#define PUBLIC_KEY_HEAD "-----BEGIN PUBLIC KEY-----\n"
#define PUBLIC_KEY_TAIL "\n-----END PUBLIC KEY-----"

typedef enum RSABits{
    RSA1024,
    RSA2048
}RSABits;


/**
 * create rsa publick key and private key string in format of PEM
 * @bits, rsa key bits, max bit is 2048
 * @seed, seed of creating rsa keys
 * @private_key, rsa private key
 * @public_key, rsa public key
 * @returns  decrypt data lenght if success, otherwise fail
 */
int ff_create_rsa_keys(enum RSABits bits, const char* seed, char** private_key, char** public_key);


/**
 * decrypt data encrypt by rsa publick key
 * @seed, seed of creating rsa keys
 * @private_key, rsa private key to decrypt data
 * @src, encrypted data in format of base64 urlsafe
 * @dst, decrypted data
 * @returns  >0 decrypt data lenght if success, <=0 fail
 */
int ff_rsa_decrypt( const char* seed, const char* private_key, const char* src, char** dst);

#endif //RSA_CRYPTO_H
