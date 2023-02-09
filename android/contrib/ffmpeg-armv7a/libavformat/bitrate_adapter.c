#include "bitrate_adapter.h"
#include "libavutil/log.h"
#include "libavutil/time.h"
#include "libavutil/mem.h"
//#include "global_variables.h"

//init bitrate info
int bitrate_init_varaints(AVApplicationContext *app_ctx, int n_variants){
    if (!app_ctx)
        return -1;

    if (!app_ctx->adaptive_bitrate_switching) {
        return -1;
    }
    memset(app_ctx->bi, 0, sizeof(BitrateInfo));
    app_ctx->bi->bandwidth_array = (int64_t*) av_mallocz(n_variants * sizeof(int64_t));
    app_ctx->bi->url_array = (char**) av_mallocz(n_variants * sizeof(char*));
    if ( app_ctx->bi->url_array==NULL || app_ctx->bi->bandwidth_array==NULL ) {
        return -2;
    }
    app_ctx->bi->is_inited = 1;
    app_ctx->bi->bandwidth_count = n_variants;
    return 0;
}


void bitrate_uninit_varaints(AVApplicationContext *app_ctx){
    if (!app_ctx)
        return;
    
    if (!app_ctx->bi->is_inited)
        return;
    
    for(int i = 0; i<app_ctx->bi->bandwidth_count; ++i)
    {
        av_free(app_ctx->bi->url_array[i]);
    }
    if (app_ctx->bi->url_array) {
        av_free(app_ctx->bi->url_array);
    }
    if (app_ctx->bi->bandwidth_array) {
        av_free(app_ctx->bi->bandwidth_array);
    }
    memset(&app_ctx->bi, 0, sizeof(BitrateInfo));
}

void bitrate_insert_varaint(AVApplicationContext *app_ctx, int i, char* url, int64_t band_width){
    if (!app_ctx)
        return;
    
    if(!app_ctx->bi->is_inited || app_ctx->bi->bandwidth_array == NULL || app_ctx->bi->url_array==NULL || url==NULL){
        return;
    }
    app_ctx->bi->url_array[i] = (char*) av_mallocz((strlen(url) + 1 ) * sizeof(char));
    strcpy(app_ctx->bi->url_array[i], url);
    app_ctx->bi->bandwidth_array[i] = band_width;
    av_log(NULL, AV_LOG_DEBUG, "multirate: insert bandwidth=%lld, url=%s\n", band_width, url);
}

void bitrate_begin_calculate(AVApplicationContext *app_ctx){
    if (!app_ctx)
        return;
        
    if (!app_ctx->bi->is_inited)
        return;
    
    app_ctx->bi->loaded_bytes = 0LL;
    app_ctx->bi->start_loading = av_gettime();
 }

void bitrate_finish_calculate(AVApplicationContext *app_ctx){
    if (!app_ctx)
        return;

    if (!(app_ctx->adaptive_bitrate_switching&&app_ctx->bi->is_inited))
        return;
    int64_t interval = av_gettime() - app_ctx->bi->start_loading;
    app_ctx->bi->current_bitrate = app_ctx->bi->loaded_bytes * 8 * 1000000 / interval;
    av_log(NULL, AV_LOG_DEBUG, "multirate: calculate current bitrate=%lld, Byterate=%lld, bytes=%lld, timeoffset=%lld\n", app_ctx->bi->current_bitrate, app_ctx->bi->current_bitrate/8, app_ctx->bi->loaded_bytes, interval);
    
}

int is_bitrate_inited(AVApplicationContext *app_ctx){
    if (!app_ctx)
        return -1;

     return app_ctx->bi->is_inited;
}


void bitrate_add_download_data(AVApplicationContext *app_ctx, int64_t bytes){
    if (!app_ctx)
        return;

     if( app_ctx->bi->is_inited && bytes > 0 ){
    	 app_ctx->bi->loaded_bytes += bytes;
     }
 }


 int get_current_bitrate_index(AVApplicationContext *app_ctx){
     if (!app_ctx)
         return -1;

     return app_ctx->bi->current_url_index;
 }


 int is_current_bitrate_url(AVApplicationContext *app_ctx, char* url){
     if (!app_ctx)
         return -1;
     
     if(app_ctx->bi->current_url){
         return strcmp(app_ctx->bi->current_url, url)==0?1:0;
     }
     return 0;
 }

static char* update_better_bitrate(AVApplicationContext *app_ctx, int index_better ){
    if (!app_ctx)
        return NULL;
    
    if (index_better>=0 && index_better < app_ctx->bi->bandwidth_count) {
        app_ctx->bi->current_url = app_ctx->bi->url_array[index_better];
        app_ctx->bi->current_url_index = index_better;
        app_ctx->bi->current_bandwidth = app_ctx->bi->bandwidth_array[index_better];
        av_log(NULL, AV_LOG_DEBUG, "multirate: select url=%s, index=%d, bandwidth=%lld\n", app_ctx->bi->current_url, app_ctx->bi->current_url_index, app_ctx->bi->current_bandwidth );
    }
    return app_ctx->bi->current_url;
}

 char* find_better_bitrate(AVApplicationContext *app_ctx) {
     if (!app_ctx)
         return NULL;
     
     if (!app_ctx->bi->is_inited)
         return NULL;
     if (app_ctx->bi->current_bitrate == 0) {
         app_ctx->bi->current_url = app_ctx->bi->url_array[0];
         app_ctx->bi->current_url_index = 0;
         app_ctx->bi->current_bandwidth = app_ctx->bi->bandwidth_array[0];
         av_log(NULL, AV_LOG_DEBUG, "multirate: select url=%s, index=%d, bandwidth=%lld\n", app_ctx->bi->current_url, app_ctx->bi->current_url_index, app_ctx->bi->current_bandwidth );
         return app_ctx->bi->current_url;
     }
     
     //确保码率是排序的,达到高一级码率带宽90%时才能升级码率
     int index_better = app_ctx->bi->current_url_index;
     if (app_ctx->bi->current_bitrate > app_ctx->bi->current_bandwidth) {
         index_better = app_ctx->bi->current_url_index+1;
         if (index_better < app_ctx->bi->bandwidth_count) {
             int64_t next_bandwidth = app_ctx->bi->bandwidth_array[index_better];
             if (app_ctx->bi->current_bitrate < next_bandwidth*0.9) {
                 av_log(NULL, AV_LOG_DEBUG, "multirate: bitrate not enough to select higher_bandwidth=%lld, lower_bindwidth=%lld, current_bitrate=%lld\n", next_bandwidth, app_ctx->bi->current_bandwidth, app_ctx->bi->current_bitrate );
                 return app_ctx->bi->current_url;
             }else{
                 return update_better_bitrate(app_ctx, index_better);
             }
         }
     }else if(app_ctx->bi->current_bitrate*0.9 < app_ctx->bi->current_bandwidth) {
         index_better = app_ctx->bi->current_url_index-1;
         return update_better_bitrate(app_ctx, index_better);
     }else{
     }
     return app_ctx->bi->current_url;
 }




