#ifndef BITRATE_ADAPTER_H
#define BITRATE_ADAPTER_H

#include <sys/types.h>
#include "libavutil/application.h"


int bitrate_init_varaints(AVApplicationContext *app_ctx, int n_variants);
void bitrate_uninit_varaints(AVApplicationContext *app_ctx);
int is_bitrate_inited(AVApplicationContext *app_ctx);

void bitrate_insert_varaint(AVApplicationContext *app_ctx, int i, char* url, int64_t band_width);
void bitrate_begin_calculate(AVApplicationContext *app_ctx);
void bitrate_finish_calculate(AVApplicationContext *app_ctx);
void bitrate_add_download_data(AVApplicationContext *app_ctx, int64_t bytes);

int get_current_bitrate_index(AVApplicationContext *app_ctx);
int is_current_bitrate_url(AVApplicationContext *app_ctx, char* url);
char* find_better_bitrate(AVApplicationContext *app_ctx);
#endif //BITRATE_ADAPTER_H
