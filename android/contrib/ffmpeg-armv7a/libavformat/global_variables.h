#ifndef GLOBAL_VARIABLES_H
#define GLOBAL_VARIABLES_H

#include <stdint.h>
#include "libavutil/application.h"

void ffg_pss_set_http_redirect_path(AVApplicationContext *app_ctx ,const char *source);
//void ffg_pss_set_http_path_info(AVApplicationContext *app_tx, const char *source);
enum enumPathType ffg_get_http_path_info(const char *source);

//for set play option
int ff_init_player_options(AVApplicationContext *app_tx);
void ff_uninit_player_options(AVApplicationContext *app_tx);
int ff_set_player_option(AVApplicationContext *app_tx,const char *key, const char *value );
int ff_get_player_option(AVApplicationContext *app_tx,const char *key, char **value );
int ff_set_player_option_int(AVApplicationContext *app_tx,const char *key, int64_t value );
int ff_get_player_option_int(AVApplicationContext *app_tx,const char *key, int64_t* value );


//dns escaped time statistic
void ffg_dns_reset_statistic(AVApplicationContext *app_ctx);
void ffg_dns_add_info(AVApplicationContext *app_ctx, int64_t curtime, const char* hostname);
int64_t ffg_dns_get_avgtime(AVApplicationContext *app_ctx);
int64_t ffg_dns_get_firsttime(AVApplicationContext *app_ctx);
int ffg_dns_get_counts(AVApplicationContext *app_ctx);

//tcp escaped time statistic
void ffg_tcp_reset_statistic(AVApplicationContext *app_ctx);
void ffg_tcp_add_info(AVApplicationContext *app_ctx, int64_t curtime, const char* hostname, const char* ip);
int64_t ffg_tcp_get_avgtime(AVApplicationContext *app_ctx);
int64_t ffg_tcp_get_firsttime(AVApplicationContext *app_ctx);
int ffg_tcp_get_counts(AVApplicationContext *app_ctx);

//switch of file cache
void ffg_pss_set_cache_switch(AVApplicationContext *app_ctx, int onoff);
int ffg_pss_get_cache_switch(AVApplicationContext *app_ctx);

void ffg_pss_set_cache_path(AVApplicationContext *app_ctx, const char* path);
char* ffg_pss_get_cache_path(AVApplicationContext *app_ctx);
#endif
