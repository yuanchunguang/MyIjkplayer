

#ifndef CUSTOMKEYS_H
#define CUSTOMKEYS_H
#include "libavutil/common.h"

#define CUSTOMKEY_ALG "customkey_alg"
#define CUSTOMKEY_SRC "customkey_src"

#define CUSTOMKEY_ERROR_ALG_INVALID  -11
#define CUSTOMKEY_ERROR_KEY_FAIL     -12

typedef enum {
    KEY_EVEN = 0,
    KEY_ODD = 1
}OEKEY_TYPE;

typedef enum {
    SORT_ASC,
    SORT_DESC,
    SORT_NONE,
}SORT_TYPE;


typedef enum{
    ALG_NONE,           //alg name Unknown
    ALG_BLOWFISH32,       //alg name X
    ALG_AES128,           //alg name Y
}CUSTOM_ALG_TYPE;

typedef struct{
    int index;    //key index range [1, 8]
    int factor;   //factor for alg, diffrent alg has sperate meanings
    int alg;      //alg type, such as X, Y, Z...
    uint8_t key[16];
}AVCustomAlgOpt;

/* parse alg descrpiton to get decrypt alg options and key
 *   opt: alg option, include alg type, key index, alg factor
 *   alg: alg description, format should be like: Type[A-Z]://X:4
 *   src: param of sha256 to get decrypt key
 */
int customkey_get_alg(AVCustomAlgOpt* opt, const char* alg, const char* src);

#endif /* CUSTOMKEYS_H */
