
#include "customkeys.h"
#include "libavutil/log.h"
#include "libavutil/sha.h"
#include "libavutil/aes.h"
#include "libavutil/avstring.h"

//ALG crypte type name:
//X: blowfish32
//Y: AES-128 ecb
typedef struct{
    char* alg;
    int alg_type;
}ALG_INFO;

ALG_INFO g_alg_tables[] = {
    {"X", ALG_BLOWFISH32},
    {"Y", ALG_AES128 }
};

//get 16bytes key, key index range should be [1,8]
int customkey_get(int index, uint8_t* usrkey, uint32_t usrkey_len, uint8_t* key, uint32_t key_len);
//generate custom key
int customkey_gen(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t dst_len, int type, int sort);
//sort input
void customkey_sort(uint8_t* src, uint32_t len, int sort);

static int compair_fun(int type, uint8_t l, uint8_t r){
    switch (type) {
        case SORT_DESC:
            return l<r?1:0;
        case SORT_ASC:
            return l>r?1:0;
        default:
            return 0;
    }
}

void customkey_sort(uint8_t* src, uint32_t len, int sort){
    int i,j;
    uint8_t temp;
    for (i=1;i<len;i++){
        temp = src[i];
        for (j=i; j>0 && compair_fun(sort, src[j-1], temp); j--){
            src[j] = src[j-1];
        }
        src[j] = temp;
    }
}

int customkey_gen(const uint8_t* src, uint32_t src_len, uint8_t* dst, uint32_t len, int type, int sort){
    if (src==NULL||dst==NULL||len<16) {
        return -1;
    }
    struct AVSHA* sha = av_sha_alloc();
    int ret = av_sha_init(sha, 256);
    if (ret!=0) {
        av_log(NULL, AV_LOG_ERROR, "customkey_gen, sha init fail, %d\n", ret);
        return -2;
    }
    av_sha_update(sha, src, src_len);
    uint8_t out [32]={0};
    av_sha_final(sha, out);
    customkey_sort(out, 32, sort);
    for (int i=(type+1)%2; i<32; i+=2) {
        dst[i/2] = out[i];
    }
    return 0;
}


int customkey_get(int index, uint8_t* src, uint32_t src_len, uint8_t* key, uint32_t key_len){
    if (index<=0||index>8) {
        av_log(NULL, AV_LOG_ERROR, "customkey_get, key number outof range, %d\n", index);
        return -1;
    }
    int ret = -2;
    uint8_t* prefix = (uint8_t*)"MyPlayerCustomKey";
    uint32_t prefix_len = (uint32_t)strlen((char*)prefix);
    uint32_t merge_len = src_len + prefix_len + 1;
    switch (index) {
        case 1:
        case 2:
            ret = customkey_gen(prefix, prefix_len, key, key_len, index%2, SORT_DESC);
            break;
        case 3:
        case 4:
            ret = customkey_gen(src, src_len, key, key_len, index%2, SORT_NONE);
            break;
        case 5:
        case 6:{
            uint8_t* src_sort = (uint8_t*)av_malloc(src_len);
            memcpy(src_sort, src, src_len);
            customkey_sort(src_sort, src_len, SORT_ASC);
            ret = customkey_gen(src_sort, src_len, key, key_len, index%2, SORT_NONE);
            av_free(src_sort);
            break;
        }
        case 7:
        case 8:{
            uint8_t* src_merge = (uint8_t*)av_malloc(merge_len);
            memcpy(src_merge, prefix, prefix_len);
            memcpy(src_merge+prefix_len, ":", 1);
            memcpy(src_merge+prefix_len+1, src, src_len);
            ret = customkey_gen(src_merge, merge_len, key, key_len, index%2, SORT_NONE);
            av_free(src_merge);
            break;
        }
        default:
            break;
    }
    
#if 1
    char keyhex[64];
    memset(keyhex, 0, sizeof(keyhex));
    for (int i=0; i<key_len; i++) {
        sprintf(keyhex+(i*2), "%02x", key[i]);
    }
    av_log(NULL, AV_LOG_DEBUG, "customkey_get, key[%d]=%s\n", index, keyhex);
#endif
    return ret;
}

//customkey looks like: TypeA://
int customkey_get_alg(AVCustomAlgOpt* opt, const char* key, const char* src){
    memset(opt, 0, sizeof(AVCustomAlgOpt));
    char* keydump = av_strdup(key);
    char* pkey = keydump;
    int ret = av_strstart(keydump, "Type", (const char**)&pkey);
    if (ret!=0) {
        if( pkey[0]>='A' && pkey[0]<='Z' ){
            opt->index = (uint8_t)pkey[0] - 'A' + 1;
            pkey = av_stristr(pkey, "://");
            if (pkey!=NULL) {
                pkey+=3;
                ret = CUSTOMKEY_ERROR_ALG_INVALID;
                char* savestr = NULL;
                char* alg_name = av_strtok(pkey, ":", &savestr);
                if (alg_name!=NULL) {
                    pkey = NULL;
                    char* alg_factor = av_strtok(pkey, ":", &savestr);
                    if (alg_factor!=NULL) {
                        sscanf(alg_factor, "%d", &opt->factor);
                        for (int i=0;  i<sizeof(g_alg_tables)/sizeof(ALG_INFO); i++) {
                            if (strcmp(g_alg_tables[i].alg, alg_name)==0) {
                                opt->alg = g_alg_tables[i].alg_type;
                                ret = 0;
                                goto result_alg_key;
                            }
                        }
                    }
                }
            }
        }
    }
result_alg_key:
    if (opt->alg>0) {
        ret = customkey_get(opt->index, src, strlen(src), opt->key, sizeof(opt->key));
        if (ret!=0) {
            ret = CUSTOMKEY_ERROR_KEY_FAIL;
        }
    }
    av_log(NULL, AV_LOG_DEBUG, "customkey_get_alg, ret=%d\n", ret);
    av_free(keydump);
    return ret;
}
