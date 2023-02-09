#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>

//#ifdef __cplusplus
//extern "C" {
//#endif

#define BLOWFISH_BLOCK_SIZE 4              // Blowfish operates on 4 bytes at a time

typedef struct stBlowfish{
        uint16_t p[18];
        uint16_t s[2][256];
        int loops;
}BLOWFISH_CTX;

/*
 * blowfish context init function
 *   key: user key to init context
 *   loop:  encrypt/decrypt function implements count
 *   ctx: blowfish context which is used to implement the algorithm
 */
void blowfish_init(const uint8_t* key, int key_len, int loops, BLOWFISH_CTX *ctx);

/*
 * blowfish encrypt/decrpt function
 *   in：output buffer， lenght should be BLOWFISH_BLOCK_SIZE
 *   out：input buffer， lenght should be BLOWFISH_BLOCK_SIZE
 *   blockcnt: count of 4 bytes
 *   reutrn: 0==success, -1==fail, ctx is null
 */
int blowfish_encrypt(const BLOWFISH_CTX *ctx, const uint8_t* in, uint8_t* out, int blockcnt);
int blowfish_decrypt(const BLOWFISH_CTX *ctx, const uint8_t* in, uint8_t* out, int blockcnt);

//#ifdef __cplusplus
//}
//#endif

#endif
