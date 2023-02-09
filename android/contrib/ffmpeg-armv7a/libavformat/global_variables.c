
#include "global_variables.h"
#include "internal.h"

void ffg_pss_set_http_redirect_path(AVApplicationContext *app_ctx, const char *source)
{
    if(!app_ctx)
        return;
    
    memset(app_ctx->pss->redirect_path, 0, sizeof(app_ctx->pss->redirect_path));
    
    av_strlcpy(app_ctx->pss->redirect_path, source, sizeof(app_ctx->pss->redirect_path));
}

//record current http request path for player start_time_log
/*void ffg_pss_set_http_path_info(AVApplicationContext *app_ctx, const char *source)
{
    if(!app_ctx)
        return;
    PlayerStartStatus *pss = app_ctx->pss;
    
    
    memset(pss->path,0,sizeof(pss->path));
    if(source!=NULL && strlen(source)<4096)
    {
        av_strlcpy(pss->path,source,sizeof(pss->path));
        if(av_strnstr(pss->path, ".m3u8", strlen(pss->path)))
        {
            pss->path_type = PATH_M3U8;
        }
        else if(av_strnstr(pss->path, ".ts", strlen(pss->path)) || av_strnstr(pss->path, ".m4s", strlen(pss->path)))
        {
            pss->path_type = PATH_TS;
        }
        else if(av_strnstr(pss->path, "key_id", strlen(pss->path)))
        {
            pss->path_type = PATH_KEY;
        }
        else if(av_strnstr(pss->path, ".mp4", strlen(pss->path)))
        {
			pss->path_type = PATH_MP4;
		}
    }
    else
    {
        av_log(NULL,AV_LOG_ERROR,"fail to pss_set_http_path_info with invalid path");
    }
}*/


enum enumPathType ffg_get_http_path_info(const char *source)
{    
	enum enumPathType re = PATH_UNKNOWN;
    if(source!=NULL && strlen(source)<4096)
    {
        if(av_strnstr(source, ".m3u8", strlen(source)))
        {
            re = PATH_M3U8;
        }
        else if(av_strnstr(source, ".ts", strlen(source)) || av_strnstr(source, ".m4s", strlen(source)))
        {
            re = PATH_TS;
        }
        else if(av_strnstr(source, "key_id", strlen(source)))
        {
            re = PATH_KEY;
        }
        else if(av_strnstr(source, ".mp4", strlen(source)))
        {
			re = PATH_MP4;
		}
    }
    else
    {
        av_log(NULL,AV_LOG_ERROR,"fail to pss_set_http_path_info with invalid path");
    }
	
	return re;
}

int ff_init_player_options(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return -1;
    
    app_ctx->po->dic = NULL;
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&app_ctx->po->mutex, &mutexattr);
    return 0;
}
void ff_uninit_player_options(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return;
    
    if (app_ctx->po->dic) {
        av_dict_free(&app_ctx->po->dic);
    }
    app_ctx->po->dic = NULL;
    pthread_mutex_destroy(&app_ctx->po->mutex);
}

int ff_set_player_option(AVApplicationContext *app_ctx,const char *key, const char *value ){
    if(!app_ctx)
        return -1;
    
    if (value==NULL) {
        return -1;
    }
    pthread_mutex_lock(&app_ctx->po->mutex);
    int ret = av_dict_set(&app_ctx->po->dic, key,value,AV_DICT_MATCH_CASE);
    pthread_mutex_unlock(&app_ctx->po->mutex);
    return ret;
}

int ff_get_player_option(AVApplicationContext *app_ctx,const char *key, char **value ){
    if(!app_ctx)
        return -1;
    
    pthread_mutex_lock(&app_ctx->po->mutex);
    AVDictionaryEntry* entry = av_dict_get(app_ctx->po->dic, key, NULL, AV_DICT_MATCH_CASE);
    int ret = -1;
    if (entry && entry->value!=NULL && strlen(entry->value)>=0 ) {
        int size = strlen(entry->value);
        *value = av_mallocz(size+1);
        memset(*value, 0, size+1);
        memcpy(*value, entry->value, size+1);
        ret = 0;
    }
    pthread_mutex_unlock(&app_ctx->po->mutex);
    return ret;
}

int ff_set_player_option_int(AVApplicationContext *app_ctx,const char *key, int64_t value ){
    if(!app_ctx)
        return -1;
    pthread_mutex_lock(&app_ctx->po->mutex);
    int ret = av_dict_set_int(&app_ctx->po->dic, key, value, AV_DICT_MATCH_CASE);
    pthread_mutex_unlock(&app_ctx->po->mutex);
    return ret;
}

int ff_get_player_option_int(AVApplicationContext *app_ctx,const char *key, int64_t *value ){
    if(!app_ctx)
        return -1;
    
    pthread_mutex_lock(&app_ctx->po->mutex);
    AVDictionaryEntry* entry = av_dict_get(app_ctx->po->dic, key, NULL, AV_DICT_MATCH_CASE);
    int ret = -1;
    if (entry && entry->value!=NULL && strlen(entry->value)>=0 ) {
        *value = atoll(entry->value);
        ret = 0;
    }
    pthread_mutex_unlock(&app_ctx->po->mutex);
    return ret;
}


void ffg_dns_reset_statistic(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return;
    
    memset(app_ctx->dnss, 0, sizeof(stDNSStatistic));
}

void ffg_dns_add_info(AVApplicationContext *app_ctx, int64_t curtime, const char* hostname){
    if(!app_ctx)
        return;
        
    app_ctx->dnss->dns_totaltime += curtime;
    app_ctx->dnss->dns_curtime = curtime;
    app_ctx->dnss->dns_counts ++;
    if (app_ctx->dnss->dns_counts<=1) {
        app_ctx->dnss->dns_firsttime = curtime;
    }
    if (hostname!=NULL) {
        av_strlcpy(app_ctx->dnss->hostname, hostname, sizeof(app_ctx->dnss->hostname));
    }
}

int64_t ffg_dns_get_avgtime(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return -1;
        
    if (app_ctx->dnss->dns_counts>0) {
        return app_ctx->dnss->dns_totaltime/app_ctx->dnss->dns_counts;
    }
    return 0;
}

int ffg_dns_get_counts(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return -1;
        
    return app_ctx->dnss->dns_counts;
}

int64_t ffg_dns_get_firsttime(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return -1;
        
    return app_ctx->dnss->dns_firsttime;
}

void ffg_tcp_reset_statistic(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return;
    
    memset(app_ctx->tcps, 0, sizeof(stTcpStatistic));
}

void ffg_tcp_add_info(AVApplicationContext *app_ctx, int64_t curtime, const char* hostname, const char* ip){
    if(!app_ctx)
        return;
    
    app_ctx->tcps->totaltime += curtime;
    app_ctx->tcps->curtime = curtime;
    app_ctx->tcps->counts++;
    if (app_ctx->tcps->counts<=1) {
        app_ctx->tcps->firsttime = curtime;
    }
    if (hostname!=NULL) {
        av_strlcpy(app_ctx->tcps->hostname, hostname, sizeof(app_ctx->tcps->hostname));
    }
    if (ip!=NULL) {
        av_strlcpy(app_ctx->tcps->ip, ip, sizeof(app_ctx->tcps->ip));
    }
}

int64_t ffg_tcp_get_avgtime(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return -1;
    if (app_ctx->tcps->counts>0) {
        return app_ctx->tcps->totaltime/app_ctx->tcps->counts;
    }
    return 0;
}

int64_t ffg_tcp_get_firsttime(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return -1;
    
    return app_ctx->tcps->firsttime;
}


int ffg_tcp_get_counts(AVApplicationContext *app_ctx){
    if(!app_ctx)
        return -1;
    
    return app_ctx->tcps->counts;
}

void ffg_pss_set_cache_switch(AVApplicationContext *app_ctx, int onoff) {
	if (!app_ctx)
		return;

	app_ctx->caches->cache = onoff;
}

int ffg_pss_get_cache_switch(AVApplicationContext *app_ctx) {
	if (!app_ctx)
		return -1;

	return app_ctx->caches->cache;
}

void ffg_pss_set_cache_path(AVApplicationContext *app_ctx, const char* path) {
	if (!app_ctx)
		return;

	memset(app_ctx->caches->cache_path, 0, sizeof(app_ctx->caches->cache_path));
	if (path != NULL && strlen(path) < MAX_URL_SIZE) {
		av_strlcpy(app_ctx->caches->cache_path, path,
				sizeof(app_ctx->caches->cache_path));
	} else {
		av_log(NULL, AV_LOG_ERROR,
				"fail to ffg_set_cache_path with invalid path");
	}
}

char* ffg_pss_get_cache_path(AVApplicationContext *app_ctx) {
	if (!app_ctx)
		return -1;

	return app_ctx->caches->cache_path;
}
