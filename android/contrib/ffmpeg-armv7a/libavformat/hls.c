/*
 * Apple HTTP Live Streaming demuxer
 * Copyright (c) 2010 Martin Storsjo
 * Copyright (c) 2013 Anssi Hannula
 * Copyright (c) 2011 Cedirc Fung (wolfplanet@gmail.com)
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * Apple HTTP Live Streaming demuxer
 * http://tools.ietf.org/html/draft-pantos-http-live-streaming
 */

#include "libavutil/avstring.h"
#include "libavutil/avassert.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mathematics.h"
#include "libavutil/opt.h"
#include "libavutil/dict.h"
#include "libavutil/time.h"
#include "avformat.h"
#include "internal.h"
#include "avio_internal.h"
#include "id3v2.h"
#include "avformat.h"
#include "libavutil/base64.h"
#include "libavutil/hmac.h"
#include "libavutil/rsa_crypto.h"
#include "libavutil/crc.h"
#include "libavformat/http.h"
#include "global_variables.h"
#include "bitrate_adapter.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include "global_variables.h"
#include "libavutil/customkeys.h"
#include "libavutil/blowfish32.h"
#include "libavutil/aes.h"

#if CONFIG_ZLIB
#include <zlib.h>
#endif /* CONFIG_ZLIB */

//chenwq decrese buffer size for fast avformat find stream info
#define INITIAL_BUFFER_SIZE 32768//16384//
#define MAX_FIELD_LEN 64
#define MAX_CHARACTERISTICS_LEN 512

#define MPEG_TIME_BASE 90000
#define MPEG_TIME_BASE_Q (AVRational){1, MPEG_TIME_BASE}


#define MAX_LICENSE_CONTENT_LEN 4096
#define LICENSE_PARAM_COUNT     5


#define DRM_NONE              0
#define DRM_STAR              1
#define DRM_AES128            2


#define AES128_KEY_LEN              16
#define LP_KEY_MAX_LEN              32
#define LP_VALUE_MAX_LEN            512

//for save hls fmp4 init.mp4
#define MAX_STAR_INIT_DATA  20480

#define MIN_SLEEP_INTETVAL   100000   //100ms

#define INTERFACE_LICENSE       "/license-server/v1/licenses"

#define LP_USERID               "user_id"
#define LP_DEVICEID             "device_id"
#define LP_KEYID                "key_id"
#define LP_APPID                "app_id"
#define LP_TIMESTAMP            "timestamp"
#define LP_SIGNATURE            "sign"
#define LP_TOKEN                "token"

#define LR_CODE                 "code"
#define LR_MESSAGE              "message"
#define LR_KEY                  "key"
#define LR_CRC                  "crc"
#define LR_RIGHT                "right"


#define KEY_VALUE_SPERATOR      "&"
#define KEY_VALUE_LINKER        '='

typedef struct stKeyValue
{
    char key[LP_KEY_MAX_LEN];
    char value[LP_VALUE_MAX_LEN];
}stKeyValue;

typedef struct stLicenseInfo{
    int code;
    char message[LP_VALUE_MAX_LEN];
    char key[AES128_KEY_LEN];
    unsigned int crc;
    char right[LP_VALUE_MAX_LEN];
}stLicenseInfo;

char* g_param_keys[] = { LP_USERID, LP_KEYID, LP_DEVICEID, LP_APPID, LP_TIMESTAMP };

/*
 * An apple http stream consists of a playlist with media segment files,
 * played sequentially. There may be several playlists with the same
 * video content, in different bandwidth variants, that are played in
 * parallel (preferably only one bandwidth variant at a time). In this case,
 * the user supplied the url to a main playlist that only lists the variant
 * playlists.
 *
 * If the main playlist doesn't point at any variants, we still create
 * one anonymous toplevel variant for this, to maintain the structure.
 */

enum KeyType {
    KEY_NONE,
    KEY_AES_128,
    KEY_SAMPLE_AES,
    KEY_STAR_CRYPT
};

struct segment {
    int64_t previous_duration;
    int64_t duration;
    int64_t start_time;  //sum of #EXTINF ahead of current segment
    int64_t url_offset;
    int64_t size;
    char *url;
    char *key;          //section key
	char *star_init_data;
    enum KeyType key_type;
    uint8_t iv[16];
    char* key_src;      //key src to get starkey
    char* key_initsec;  //section key for init data
    /* associated Media Initialization Section, treated as a segment */
    struct segment *init_section;
};

struct rendition;

enum PlaylistType {
    PLS_TYPE_UNSPECIFIED,
    PLS_TYPE_EVENT,
    PLS_TYPE_VOD
};

/*
 * Each playlist has its own demuxer. If it currently is active,
 * it has an open AVIOContext too, and potentially an AVPacket
 * containing the next packet from this stream.
 */
struct playlist {
    char url[MAX_URL_SIZE];
    AVIOContext pb; //context for hls read_data
    uint8_t* read_buffer;
    AVIOContext *input;   //context for read current ts
    AVFormatContext *parent; //format context for hls
    int index;
    AVFormatContext *ctx;   //format context for ts
    AVPacket pkt;
    int stream_offset;
    int input_read_done;

    int finished;   //1=vod, 0==live
    enum PlaylistType type;
    int64_t target_duration;
    int start_seq_no;
    int n_segments;
    struct segment **segments;
    int needed, cur_needed;
    int cur_seq_no;
    int64_t cur_seg_offset;
    int64_t last_load_time;  //time of last load playlist of m3u8

    /* Currently active Media Initialization Section */
    struct segment *cur_init_section;
    uint8_t* init_sec_buf;
    unsigned int init_sec_buf_size;
    unsigned int init_sec_data_len;
    unsigned int init_sec_buf_read_offset;

    char key_url[MAX_URL_SIZE];
    uint8_t key[16];

    /* ID3 timestamp handling (elementary audio streams have ID3 timestamps
     * (and possibly other ID3 tags) in the beginning of each segment) */
    int is_id3_timestamped; /* -1: not yet known */
    int64_t id3_mpegts_timestamp; /* in mpegts tb */
    int64_t id3_offset; /* in stream original tb */
    uint8_t* id3_buf; /* temp buffer for id3 parsing */
    unsigned int id3_buf_size;
    AVDictionary *id3_initial; /* data from first id3 tag */
    int id3_found; /* ID3 tag found at some point */
    int id3_changed; /* ID3 tag data has changed at some point */
    ID3v2ExtraMeta *id3_deferred_extra; /* stored here until subdemuxer is opened */

    int64_t seek_timestamp;
    int seek_flags;
    int seek_stream_index; /* into subdemuxer stream array */

    /* Renditions associated with this playlist, if any.
     * Alternative rendition playlists have a single rendition associated
     * with them, and variant main Media Playlists may have
     * multiple (playlist-less) renditions associated with them. */
    int n_renditions;
    struct rendition **renditions;

    /* Media Initialization Sections (EXT-X-MAP) associated with this
     * playlist, if any. */
    int n_init_sections;
    struct segment **init_sections;
    int original_n_segments;
    struct segment **original_segments;
	
	struct m3u8_read_optimize* m3u8_optimize;
	int m3u8_optimize_index;  //the odd return #EXTINF,the even return segment path
    
    enum AVMediaType _type;
};

/*
 * Renditions are e.g. alternative subtitle or audio streams.
 * The rendition may either be an external playlist or it may be
 * contained in the main Media Playlist of the variant (in which case
 * playlist is NULL).
 */
struct rendition {
    enum AVMediaType type;
    struct playlist *playlist;
    char group_id[MAX_FIELD_LEN];
    char language[MAX_FIELD_LEN];
    char name[MAX_FIELD_LEN];
    int disposition;
};

struct variant {
    int bandwidth;

    /* every variant contains at least the main Media Playlist in index 0 */
    int n_playlists;
    struct playlist **playlists;

    char audio_group[MAX_FIELD_LEN];
    char video_group[MAX_FIELD_LEN];
    char subtitles_group[MAX_FIELD_LEN];
};

typedef struct HLSContext {
    AVClass *class;
    AVFormatContext *ctx;
    int n_variants;
    struct variant **variants;
    int n_playlists;
    struct playlist **playlists;
    int n_renditions;
    struct rendition **renditions;

    int cur_seq_no;
    int live_start_index;
    int first_packet;
    int64_t first_timestamp;
    int64_t cur_timestamp;
    AVIOInterruptCB *interrupt_callback;
    char *user_agent;                    ///< holds HTTP user agent set as an AVOption to the HTTP protocol context
    char *cookies;                       ///< holds HTTP cookie values set in either the initial response or as an AVOption to the HTTP protocol context
    char *headers;                       ///< holds HTTP headers set as an AVOption to the HTTP protocol context
    char *http_proxy;                    ///< holds the address of the HTTP proxy server
    AVDictionary *avio_opts;
    int strict_std_compliance;
    int http_persistent;  //for hls http keepalive
    int use_redirect_ip;
	int use_m3u8_optimize_read; //for m3u8 read optimize
    AVIOContext *playlist_pb;
    AVIOContext *playlist_pb_audio;
    AVApplicationContext *app_ctx;
    int64_t retry_interval_time;
	int des_regular_rate;
	int des_retry_interval;
	int parallel_open;
	URLStartStatus* uss_default;
	URLStartStatus* uss_alt;  //in order to record the audio m3u8  status when open hls video and audio in parallel
    
    URLStartStatus* uss_default_segment;
    URLStartStatus* uss_alt_segment;  //in order to record the audio segment status when open hls video and audio in parallel
    int rw_timeout;
    int reconnect_count;
    int open_timeout;
} HLSContext;


int is_bitrate_updated = 0;

static int read_chomp_line(AVIOContext *s, char *buf, int maxlen)
{
    int len = ff_get_line(s, buf, maxlen);
    while (len > 0 && av_isspace(buf[len - 1]))
        buf[--len] = '\0';
    return len;
}


static void free_segment_list(struct playlist *pls)
{
    int i;
    for (i = 0; i < pls->n_segments; i++) {
        av_freep(&pls->segments[i]->key);
        av_freep(&pls->segments[i]->url);
		av_freep(&pls->segments[i]->star_init_data);
        av_freep(&pls->segments[i]->key_src);
        av_freep(&pls->segments[i]->key_initsec);
        av_freep(&pls->segments[i]);
    }
    av_freep(&pls->segments);
    pls->n_segments = 0;
}

static void free_original_segment_list(struct playlist *pls)
{
    if ( pls->original_n_segments==0 && pls->original_segments==NULL ) {
        return;
    }
    
    int i;
    for (i = 0; i < pls->original_n_segments; i++) {
        av_freep(&pls->original_segments[i]->key);
        av_freep(&pls->original_segments[i]->url);
		av_freep(&pls->original_segments[i]->star_init_data);
        av_freep(&pls->segments[i]->key_src);
        av_freep(&pls->segments[i]->key_initsec);
        av_freep(&pls->original_segments[i]);
    }
    av_freep(&pls->original_segments);
    pls->original_n_segments = 0;
}
static void free_init_section_list(struct playlist *pls)
{
    int i;
    for (i = 0; i < pls->n_init_sections; i++) {
        av_freep(&pls->init_sections[i]->url);
		av_freep(&pls->init_sections[i]->star_init_data);
        av_freep(&pls->init_sections[i]->key_src);
        av_freep(&pls->init_sections[i]->key_initsec);
        av_freep(&pls->init_sections[i]);
    }
    av_freep(&pls->init_sections);
    pls->n_init_sections = 0;
}

static void free_playlist_list(HLSContext *c)
{
    int i;
    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        free_segment_list(pls);
        free_original_segment_list(pls);
        free_init_section_list(pls);
        av_freep(&pls->renditions);
        av_freep(&pls->id3_buf);
        av_dict_free(&pls->id3_initial);
        ff_id3v2_free_extra_meta(&pls->id3_deferred_extra);
        av_freep(&pls->init_sec_buf);
        av_packet_unref(&pls->pkt);
        av_freep(&pls->pb.buffer);
		av_freep(&pls->m3u8_optimize);
        if (pls->input){
            ff_format_io_close(c->ctx, &pls->input);
        }
        pls->input_read_done = 0;
        
        
        if (pls->ctx) {
            pls->ctx->pb = NULL;
            avformat_close_input(&pls->ctx);
        }
        av_free(pls);
    }
    av_freep(&c->playlists);
    av_freep(&c->cookies);
    av_freep(&c->user_agent);
    av_freep(&c->headers);
    av_freep(&c->http_proxy);
    c->n_playlists = 0;
}

static void free_variant_list(HLSContext *c)
{
    int i;
    for (i = 0; i < c->n_variants; i++) {
        struct variant *var = c->variants[i];
        av_freep(&var->playlists);
        av_free(var);
    }
    av_freep(&c->variants);
    c->n_variants = 0;
}

static void free_rendition_list(HLSContext *c)
{
    int i;
    for (i = 0; i < c->n_renditions; i++)
        av_freep(&c->renditions[i]);
    av_freep(&c->renditions);
    c->n_renditions = 0;
}

/*
 * Used to reset a statically allocated AVPacket to a clean slate,
 * containing no data.
 */
static void reset_packet(AVPacket *pkt)
{
    av_init_packet(pkt);
    pkt->data = NULL;
}

static struct playlist *new_playlist(HLSContext *c, const char *url,
                                     const char *base)
{
    struct playlist *pls = av_mallocz(sizeof(struct playlist));
    if (!pls)
        return NULL;
    reset_packet(&pls->pkt);
    ff_make_absolute_url(pls->url, sizeof(pls->url), base, url);
    pls->seek_timestamp = AV_NOPTS_VALUE;

    pls->is_id3_timestamped = -1;
    pls->id3_mpegts_timestamp = AV_NOPTS_VALUE;

    dynarray_add(&c->playlists, &c->n_playlists, pls);
    return pls;
}

struct variant_info {
    char bandwidth[20];
    /* variant group ids: */
    char audio[MAX_FIELD_LEN];
    char video[MAX_FIELD_LEN];
    char subtitles[MAX_FIELD_LEN];
};

static struct variant *new_variant(HLSContext *c, struct variant_info *info,
                                   const char *url, const char *base)
{
    struct variant *var;
    struct playlist *pls;

    pls = new_playlist(c, url, base);
    if (!pls)
        return NULL;

    var = av_mallocz(sizeof(struct variant));
    if (!var)
        return NULL;

    if (info) {
        var->bandwidth = atoi(info->bandwidth);
        strcpy(var->audio_group, info->audio);
        strcpy(var->video_group, info->video);
        strcpy(var->subtitles_group, info->subtitles);
        
        pls->_type = AVMEDIA_TYPE_VIDEO;
    }

    dynarray_add(&c->variants, &c->n_variants, var);
    dynarray_add(&var->playlists, &var->n_playlists, pls);
    return var;
}

static void handle_variant_args(struct variant_info *info, const char *key,
                                int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "BANDWIDTH=", key_len)) {
        *dest     =        info->bandwidth;
        *dest_len = sizeof(info->bandwidth);
    } else if (!strncmp(key, "AUDIO=", key_len)) {
        *dest     =        info->audio;
        *dest_len = sizeof(info->audio);
    } else if (!strncmp(key, "VIDEO=", key_len)) {
        *dest     =        info->video;
        *dest_len = sizeof(info->video);
    } else if (!strncmp(key, "SUBTITLES=", key_len)) {
        *dest     =        info->subtitles;
        *dest_len = sizeof(info->subtitles);
    }
}

struct key_info {
     char uri[MAX_URL_SIZE];
     char method[11];
     char iv[35];
};

struct star_key_info {
    char alg[MAX_URL_SIZE]; //algorithm type; such as: "TypeA://X/Y:4"
    char src[MAX_URL_SIZE]; //src for get star keys
};

static void handle_key_args(struct key_info *info, const char *key,
                            int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "METHOD=", key_len)) {
        *dest     =        info->method;
        *dest_len = sizeof(info->method);
    } else if (!strncmp(key, "URI=", key_len)) {
        *dest     =        info->uri;
        *dest_len = sizeof(info->uri);
    } else if (!strncmp(key, "IV=", key_len)) {
        *dest     =        info->iv;
        *dest_len = sizeof(info->iv);
    }
}

static void handle_starkey_args(struct star_key_info *info, const char *key,
                            int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "ALG=", key_len)) {
        *dest     =        info->alg;
        *dest_len = sizeof(info->alg);
    } else if (!strncmp(key, "SRC=", key_len)) {
        *dest     =        info->src;
        *dest_len = sizeof(info->src);
    }
}

struct m3u8_read_optimize_info{
	char vod[12];
	char start_index[MAX_URL_SIZE];
	char end_index[MAX_URL_SIZE];
	char index_count[12];
	char segment_duration[50];
	char segment_total_duration[50];
	char last_segment_duration[50];
	char initmp4_count[12];
	char max_offset[50];
};

static void handle_m3u8_optimize_args(struct m3u8_read_optimize_info *info, const char *key,
									  int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "VOD=", key_len)) {
        *dest     =        info->vod;
        *dest_len = sizeof(info->vod);
    } else if (!strncmp(key, "START_INDEX=", key_len)) {
        *dest     =        info->start_index;
        *dest_len = sizeof(info->start_index);
	}else if (!strncmp(key, "END_INDEX=", key_len)) {
		*dest     =        info->end_index;
		*dest_len = sizeof(info->end_index);
	} else if (!strncmp(key, "INDEX_COUNT=", key_len)) {
		*dest     =        info->index_count;
		*dest_len = sizeof(info->index_count);
	}else if (!strncmp(key, "SEGMENT_DURATION=", key_len)) {
		*dest     =        info->segment_duration;
		*dest_len = sizeof(info->segment_duration);
	}else if (!strncmp(key, "SEGMENT_TOTAL_DURATION=", key_len)) {
		*dest     =        info->segment_total_duration;
		*dest_len = sizeof(info->segment_total_duration);
	}else if (!strncmp(key, "LAST_SEGMENT_DURATION=", key_len)) {
		*dest     =        info->last_segment_duration;
		*dest_len = sizeof(info->last_segment_duration);
	}else if (!strncmp(key, "MAX_OFFSET=", key_len)) {
		*dest     =        info->max_offset;
		*dest_len = sizeof(info->max_offset);
	}else if (!strncmp(key, "INITMP4_COUNT=", key_len)) {
		*dest     =        info->initmp4_count;
		*dest_len = sizeof(info->initmp4_count);
	}
}


struct m3u8_read_optimize{
	int vod;
	char start_index[MAX_URL_SIZE];
	char end_index[MAX_URL_SIZE];
	int index_count;
	float segment_duration;
	float segment_total_duration;
	float last_segment_duration;
	float max_offset;
	int64_t start_number;
	int64_t end_number;
	int initmp4_count;
	char start_path[MAX_URL_SIZE];
	char segment_type[100]; //example ts,m4s
	int effective_number;  // example 00000.ts
	
	int optimize_valid;
};

static struct m3u8_read_optimize *new_m3u8_optimize(struct playlist *pls, struct m3u8_read_optimize_info *info)
{
	if (!info)
		return NULL;
	
	struct m3u8_read_optimize *op = av_mallocz(sizeof(struct m3u8_read_optimize));
    if (!op)
        return NULL;
	
	op->vod = atoi(info->vod);
	strcpy(op->start_index, info->start_index);
	strcpy(op->end_index, info->end_index);
	op->index_count = atoi(info->index_count);
	op->segment_duration = atof(info->segment_duration);
	op->segment_total_duration = atof(info->segment_total_duration);
	op->last_segment_duration = atof(info->last_segment_duration);
	op->initmp4_count = atoi(info->initmp4_count);
	op->max_offset = atof(info->max_offset);
	
	return op;
}

static int check_is_number(const char * sn){
	int is_number = 1;
	
	while(*sn)
	{
		if ( *sn >= '0' && *sn <= '9')
		{
			sn++;
			continue;
		}
		else
		{
			is_number  = 0;
			break;
		}
	}
	
	return is_number;
	
}


static int check_m3u8_optimize_valid(struct playlist *pls) 
{	
	int ret_flag = 0;
	char ret_msg[200] = {0}; 
	
	pls->m3u8_optimize_index = 0;
	pls->m3u8_optimize->start_path[0] = '\0';
	pls->m3u8_optimize->effective_number = 0;
	
	
	char *p_path = NULL;
	char *p_number_begin = NULL;
	char *p_type = NULL;
	
	av_log(NULL, AV_LOG_INFO, "m3u8_optimize check begin,vod:%d, start_index:%s , end_index:%s, index_count:%d, segment_duration:%f,segment_total_duration:%f \n",
		   pls->m3u8_optimize->vod,pls->m3u8_optimize->start_index,pls->m3u8_optimize->end_index,pls->m3u8_optimize->index_count,pls->m3u8_optimize->segment_duration,
		   pls->m3u8_optimize->segment_total_duration);
	
	av_log(NULL, AV_LOG_INFO, "m3u8_optimize check begin2, last_segment_duration:%f,initmp4_count:%d,max_offset:%f \n",
		   pls->m3u8_optimize->last_segment_duration,pls->m3u8_optimize->initmp4_count,pls->m3u8_optimize->max_offset);
	do
	{
		
		if (pls->m3u8_optimize->vod != 1 || strlen(pls->m3u8_optimize->start_index) <= 0 || strlen(pls->m3u8_optimize->end_index) <= 0 || pls->m3u8_optimize->index_count <= 0 || \
				pls->m3u8_optimize->segment_duration <= 0 || pls->m3u8_optimize->segment_total_duration <= 0 || pls->m3u8_optimize->last_segment_duration <= 0 || \
				pls->m3u8_optimize->initmp4_count > 1 )
		{
			strcpy(ret_msg,"m3u8_optimize:invalid m3u8_optimize_read data ");
			break;
		}
		
		if (pls->m3u8_optimize->max_offset > 1)
		{
			strcpy(ret_msg,"m3u8_optimize:max_offset is greater than 1");
			break;
		}
		
		
		char *src = pls->m3u8_optimize->start_index;
		char segment_number[MAX_URL_SIZE] = {'\0'};
		int len_number = 0;
		
		//for start_index check
		p_type = strrchr(src, '.');
		av_strlcpy(pls->m3u8_optimize->segment_type, p_type, sizeof(pls->m3u8_optimize->segment_type));
		
		if (src[0] == '/')  //example /vod/00001.ts
		{
			p_path = strrchr(src, '/') ;
			
			int len_path = p_path - src + 1;
			
			if (len_path <= 0)
			{
				strcpy(ret_msg,"m3u8_optimize:invalid start_index ");
				break;
			}
			av_strlcpy(pls->m3u8_optimize->start_path,src,len_path+1);
			
			p_number_begin = p_path + 1;
					   
		}
		else if ( src[0] >= '0' && src[0] <= '9') //example  00001.ts
		{
			pls->m3u8_optimize->start_path[0] = '\0';
			p_number_begin = src;
		}
		else
		{
			strcpy(ret_msg,"m3u8_optimize:invalid start_index format ");
			break;
		}
		
		len_number = p_type - p_number_begin;
		
		if (len_number <= 0)
		{
			strcpy(ret_msg,"m3u8_optimize:invalid start_number ");
			break;
		}
		
		av_strlcpy(segment_number,p_number_begin,len_number + 1);
		
		
		if (check_is_number(segment_number) == 0)
		{
			strcpy(ret_msg,"m3u8_optimize:invalid start_number ");
			break;
		}
		
		if(segment_number[0] == '0' && len_number > 1)
		{
			pls->m3u8_optimize->effective_number = len_number;
		}		
		pls->m3u8_optimize->start_number = atoi(segment_number);
		
		
		//for end_index check
		src = pls->m3u8_optimize->end_index;
		p_type = strrchr(src, '.');
  
		if (src[0] == '/')  //example /vod/00001.ts
		{
		  p_path = strrchr(src, '/') ;
		  p_number_begin = p_path + 1;
		  
		}
		else if ( src[0] >= '0' && src[0] <= '9') //example  00001.ts
		{
		  p_number_begin = src;
		}
		else
		{
		  strcpy(ret_msg,"m3u8_optimize:invalid end_index format ");
		  break;
		}
		
		len_number = p_type - p_number_begin;
		if (len_number <= 0)
		{
			strcpy(ret_msg,"m3u8_optimize:invalid end_number ");
			break;
		}
		
		av_strlcpy(segment_number,p_number_begin,len_number + 1);
		
		
		if (check_is_number(segment_number) == 0)
		{
			strcpy(ret_msg,"m3u8_optimize:invalid end_number ");
			break;
		}	
		pls->m3u8_optimize->end_number = atoi(segment_number);
		
		int all_index_count = pls->m3u8_optimize->end_number - pls->m3u8_optimize->start_number + 1;
		if (all_index_count != pls->m3u8_optimize->index_count)
		{
			strcpy(ret_msg,"m3u8_optimize:the index_count is skip ");
			break;
		}
		
		
		pls->m3u8_optimize->optimize_valid = 1;
		ret_flag = 1;
			 
		 sprintf(ret_msg,"m3u8_optimize success, start_number:%lld, end_number:%lld, start_path:%s, segment_type:%s, effective_number:%d",pls->m3u8_optimize->start_number,
				pls->m3u8_optimize->end_number, pls->m3u8_optimize->start_path,pls->m3u8_optimize->segment_type,pls->m3u8_optimize->effective_number);
		
	}while(0);
	
	av_log(NULL, AV_LOG_INFO, "%s\n",ret_msg);
	return ret_flag;
}

static int check_audio_lang_exist(const char* language, AVIOContext* in){
    char* out = NULL;
    avio_copy(in, &out);
    if (out!=NULL){
        if(strstr(out, language)){
            av_free(out);
            return 1;
        }
    }
    return 0;
}

static int filter_master_chomp_line(const char *language, AVIOContext *in, char *buf, int maxlen, char *langs, int langssize, int *audio_index){
    int read_end = 0;
    char lang[32]={0};
    while(!read_end){
        memset(buf, 0, maxlen);
        memset(lang, 0, sizeof(lang));
        read_chomp_line(in, buf, maxlen);
		
		char* ptr = NULL;
		if (av_strstart(buf, "#EXT-X-MEDIA:", &ptr)&&av_stristr(ptr,"TYPE=AUDIO")){
			char* langptr_tag = "LANGUAGE=\"";
			char* langptr = av_stristr(ptr, langptr_tag);
			char* langptrend = av_stristr(langptr, "\",");
			if (langptrend&&langptr) {
				langptr += strlen(langptr_tag);
				strncpy(lang, langptr, langptrend-langptr);
				av_strlcat(langs, lang, langssize);
				av_strlcat(langs, ";", langssize);
				av_log(NULL, AV_LOG_DEBUG, "filter_master_chomp_line, get audio lang: %s\n", langs);
			}
			
			(*audio_index) += 1;
			
			if (language != NULL){
				if (av_stristr(ptr, language)){
					//get the speicfied languag
					return 0;
				}else{
					//skip other language
					continue;
				}
			}else{ //if the language is NULL,we use the first language
				
				if (*audio_index == 1)
				{
					//use the first language
					return 0;
				}else{
					continue;
				}	
			}		
		}
		
		break;
    }
		
    if (!strstr(buf, "#") && buf[0]){
        //reach the end
        return 1;
    }else{
        return 0;
    }
	
}

static int combine_chomp_line(HLSContext *c, struct playlist *pls, char *buf, int maxlen)
{
    URLStartStatus* pUSS = c->uss_default;
    if (c->parallel_open && pls->_type == AVMEDIA_TYPE_AUDIO){
        pUSS = c->uss_alt;
    }
    
	pls->m3u8_optimize_index++;
	
	if (pls->m3u8_optimize_index > 2*pls->m3u8_optimize->index_count + 1)
	{
		add_flow_log(c->app_ctx,pUSS,FL_FILE_SIZE,c->app_ctx->m3u8_read_size);
		add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_ERROR_CODE, 0);
		add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_FINISH,av_gettime()/1000);
		return 0;
	}
	
	if (pls->m3u8_optimize_index == 2*pls->m3u8_optimize->index_count + 1)
	{
		if(pls->m3u8_optimize->vod == 1)
		{
			sprintf(buf,"#EXT-X-ENDLIST");
			av_log(NULL,AV_LOG_DEBUG,"m3u8_optimize combine line: %s\n",buf);
			return 1;
		}
		else
		{
			return -1;
		}
	}
	
	if (pls-> m3u8_optimize_index % 2 != 0) 
	{
		if((pls->m3u8_optimize_index + 1) == 2*pls->m3u8_optimize->index_count )
		{
			
			sprintf(buf,"#EXTINF:%f",pls->m3u8_optimize->last_segment_duration);
		}
		else
		{
			sprintf(buf,"#EXTINF:%f",pls->m3u8_optimize->segment_duration);
		}
	}
	else
	{
		int64_t index = pls->m3u8_optimize->start_number + pls->m3u8_optimize_index / 2 - 1;
		if (pls->m3u8_optimize->effective_number == 0)
		{
			sprintf(buf,"%s%lld%s",pls->m3u8_optimize->start_path,index,pls->m3u8_optimize->segment_type);
		}
		else if (pls->m3u8_optimize->effective_number > 0)
		{
			sprintf(buf,"%s%0*lld%s",pls->m3u8_optimize->start_path,pls->m3u8_optimize->effective_number,index,pls->m3u8_optimize->segment_type);
		}
		else
		{
			return -1;
		}
	}
	av_log(NULL,AV_LOG_DEBUG,"m3u8_optimize combine line: %s\n",buf);
	return 1;
}


struct init_section_info {
    char uri[MAX_URL_SIZE];
    char byterange[32];
	char star_init_data[MAX_STAR_INIT_DATA];
    char alg[MAX_URL_SIZE];
};

static struct segment *new_init_section(struct playlist *pls,
                                        struct init_section_info *info,
                                        const char *url_base,
                                        const char* key_src)
{
    struct segment *sec;
    char *ptr;
    char tmp_str[MAX_URL_SIZE];

    if (!info->uri[0])
        return NULL;

    sec = av_mallocz(sizeof(*sec));
    if (!sec)
        return NULL;

    ff_make_absolute_url(tmp_str, sizeof(tmp_str), url_base, info->uri);
    sec->url = av_strdup(tmp_str);
    if (!sec->url) {
        av_free(sec);
        return NULL;
    }

	
	if (info->star_init_data[0])
		sec->star_init_data = av_strdup(info->star_init_data);
	else
		sec->star_init_data = NULL;
    
    
    if (info->alg[0]) {
        sec->key_initsec = av_strdup(info->alg);
    }
    
    if (key_src[0]) {
        sec->key_src = av_strdup(key_src);
    }

    if (info->byterange[0]) {
        sec->size = atoi(info->byterange);
        ptr = strchr(info->byterange, '@');
        if (ptr)
            sec->url_offset = atoi(ptr+1);
    } else {
        /* the entire file is the init section */
        sec->size = -1;
    }

    dynarray_add(&pls->init_sections, &pls->n_init_sections, sec);

    return sec;
}

static void handle_init_section_args(struct init_section_info *info, const char *key,
                                           int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "URI=", key_len)) {
        *dest     =        info->uri;
        *dest_len = sizeof(info->uri);
    } else if (!strncmp(key, "BYTERANGE=", key_len)) {
        *dest     =        info->byterange;
        *dest_len = sizeof(info->byterange);
	} else if (!strncmp(key, "STAR-INIT-DATA=", key_len)) {
		*dest     =        info->star_init_data;
		*dest_len = sizeof(info->star_init_data);
    } else if (!strncmp(key, "ALG=", key_len)) {
        *dest     =        info->alg;
        *dest_len = sizeof(info->alg);
    }
}

struct rendition_info {
    char type[16];
    char uri[MAX_URL_SIZE];
    char group_id[MAX_FIELD_LEN];
    char language[MAX_FIELD_LEN];
    char assoc_language[MAX_FIELD_LEN];
    char name[MAX_FIELD_LEN];
    char defaultr[4];
    char forced[4];
    char characteristics[MAX_CHARACTERISTICS_LEN];
};

static struct rendition *new_rendition(HLSContext *c, struct rendition_info *info,
                                      const char *url_base)
{
    struct rendition *rend;
    enum AVMediaType type = AVMEDIA_TYPE_UNKNOWN;
    char *characteristic;
    char *chr_ptr;
    char *saveptr;

    if (!strcmp(info->type, "AUDIO"))
        type = AVMEDIA_TYPE_AUDIO;
    else if (!strcmp(info->type, "VIDEO"))
        type = AVMEDIA_TYPE_VIDEO;
    else if (!strcmp(info->type, "SUBTITLES"))
        type = AVMEDIA_TYPE_SUBTITLE;
    else if (!strcmp(info->type, "CLOSED-CAPTIONS"))
        /* CLOSED-CAPTIONS is ignored since we do not support CEA-608 CC in
         * AVC SEI RBSP anyway */
        return NULL;

    if (type == AVMEDIA_TYPE_UNKNOWN)
        return NULL;

    /* URI is mandatory for subtitles as per spec */
    if (type == AVMEDIA_TYPE_SUBTITLE && !info->uri[0])
        return NULL;

    /* TODO: handle subtitles (each segment has to parsed separately) */
    if (c->strict_std_compliance > FF_COMPLIANCE_EXPERIMENTAL)
        if (type == AVMEDIA_TYPE_SUBTITLE)
            return NULL;

    rend = av_mallocz(sizeof(struct rendition));
    if (!rend)
        return NULL;

    dynarray_add(&c->renditions, &c->n_renditions, rend);

    rend->type = type;
    strcpy(rend->group_id, info->group_id);
    strcpy(rend->language, info->language);
    strcpy(rend->name, info->name);

    /* add the playlist if this is an external rendition */
    if (info->uri[0]) {
        rend->playlist = new_playlist(c, info->uri, url_base);
        if (rend->playlist)
            dynarray_add(&rend->playlist->renditions,
                         &rend->playlist->n_renditions, rend);
        
        rend->playlist->_type = type;
    }

    if (info->assoc_language[0]) {
        int langlen = strlen(rend->language);
        if (langlen < sizeof(rend->language) - 3) {
            rend->language[langlen] = ',';
            strncpy(rend->language + langlen + 1, info->assoc_language,
                    sizeof(rend->language) - langlen - 2);
        }
    }

    if (!strcmp(info->defaultr, "YES"))
        rend->disposition |= AV_DISPOSITION_DEFAULT;
    if (!strcmp(info->forced, "YES"))
        rend->disposition |= AV_DISPOSITION_FORCED;

    chr_ptr = info->characteristics;
    while ((characteristic = av_strtok(chr_ptr, ",", &saveptr))) {
        if (!strcmp(characteristic, "public.accessibility.describes-music-and-sound"))
            rend->disposition |= AV_DISPOSITION_HEARING_IMPAIRED;
        else if (!strcmp(characteristic, "public.accessibility.describes-video"))
            rend->disposition |= AV_DISPOSITION_VISUAL_IMPAIRED;

        chr_ptr = NULL;
    }

    return rend;
}

static void handle_rendition_args(struct rendition_info *info, const char *key,
                                  int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "TYPE=", key_len)) {
        *dest     =        info->type;
        *dest_len = sizeof(info->type);
    } else if (!strncmp(key, "URI=", key_len)) {
        *dest     =        info->uri;
        *dest_len = sizeof(info->uri);
    } else if (!strncmp(key, "GROUP-ID=", key_len)) {
        *dest     =        info->group_id;
        *dest_len = sizeof(info->group_id);
    } else if (!strncmp(key, "LANGUAGE=", key_len)) {
        *dest     =        info->language;
        *dest_len = sizeof(info->language);
    } else if (!strncmp(key, "ASSOC-LANGUAGE=", key_len)) {
        *dest     =        info->assoc_language;
        *dest_len = sizeof(info->assoc_language);
    } else if (!strncmp(key, "NAME=", key_len)) {
        *dest     =        info->name;
        *dest_len = sizeof(info->name);
    } else if (!strncmp(key, "DEFAULT=", key_len)) {
        *dest     =        info->defaultr;
        *dest_len = sizeof(info->defaultr);
    } else if (!strncmp(key, "FORCED=", key_len)) {
        *dest     =        info->forced;
        *dest_len = sizeof(info->forced);
    } else if (!strncmp(key, "CHARACTERISTICS=", key_len)) {
        *dest     =        info->characteristics;
        *dest_len = sizeof(info->characteristics);
    }
    /*
     * ignored:
     * - AUTOSELECT: client may autoselect based on e.g. system language
     * - INSTREAM-ID: EIA-608 closed caption number ("CC1".."CC4")
     */
}

/* used by parse_playlist to allocate a new variant+playlist when the
 * playlist is detected to be a Media Playlist (not Master Playlist)
 * and we have no parent Master Playlist (parsing of which would have
 * allocated the variant and playlist already)
 * *pls == NULL  => Master Playlist or parentless Media Playlist
 * *pls != NULL => parented Media Playlist, playlist+variant allocated */
static int ensure_playlist(HLSContext *c, struct playlist **pls, const char *url)
{
    if (*pls)
        return 0;
    if (!new_variant(c, NULL, url, NULL))
        return AVERROR(ENOMEM);
    *pls = c->playlists[c->n_playlists - 1];
    return 0;
}

static int64_t default_reload_interval(struct playlist *pls)
{
	HLSContext *c = pls->parent->priv_data;
	
	if (c && c->des_regular_rate > 0 && pls->target_duration > 0){
		return (int64_t)((double)c->des_regular_rate / 100 * pls->target_duration);
	}
	else{
		return pls->n_segments > 0 ?
			   pls->segments[pls->n_segments - 1]->duration :
			   pls->target_duration;
	}
}

static void update_options(char **dest, const char *name, void *src)
{
    av_freep(dest);
    av_opt_get(src, name, AV_OPT_SEARCH_CHILDREN, (uint8_t**)dest);
    if (*dest && !strlen(*dest))
        av_freep(dest);
}


static int open_url_keepalive(AVFormatContext *s, AVIOContext **pb,
                              const char *url, AVDictionary **opts)
{
#if !CONFIG_HTTP_PROTOCOL
    return AVERROR_PROTOCOL_NOT_FOUND;
#else
    int ret;
    URLContext *uc = ffio_geturlcontext(*pb);
    av_assert0(uc);
    (*pb)->eof_reached = 0;
    ret = ff_http_do_new_request(uc, url, opts);
    if (ret < 0) {
        ff_format_io_close(s, pb);
    }
    return ret;
#endif
}


static int open_url(AVFormatContext *s, AVIOContext **pb, const char *url,
                    AVDictionary *opts, AVDictionary *opts2, int *is_http)
{
    HLSContext *c = s->priv_data;
    AVDictionary *tmp = NULL;
    const char *proto_name = NULL;
    int ret;

    av_dict_copy(&tmp, opts, 0);
    av_dict_copy(&tmp, opts2, 0);

    if (av_strstart(url, "crypto", NULL)) {
        if (url[6] == '+' || url[6] == ':')
            proto_name = avio_find_protocol_name(url + 7);
    }

    if (!proto_name)
        proto_name = avio_find_protocol_name(url);

    if (!proto_name)
        return AVERROR_INVALIDDATA;

    // only http(s) & file are allowed
    if (!av_strstart(proto_name, "http", NULL) && !av_strstart(proto_name, "file", NULL) && !av_strstart(proto_name, "ijkmediadatasource", NULL) )
        return AVERROR_INVALIDDATA;
    if (!strncmp(proto_name, url, strlen(proto_name)) && url[strlen(proto_name)] == ':')
        ;
    else if (av_strstart(url, "crypto", NULL) && !strncmp(proto_name, url + 7, strlen(proto_name)) && url[7 + strlen(proto_name)] == ':')
        ;
    else if (strcmp(proto_name, "file") || !strncmp(url, "file,", 5))
        return AVERROR_INVALIDDATA;
    
    if( av_strstart(proto_name, "ijkmediadatasource", NULL) )
    {
        av_dict_set(&tmp, "ijkmediadatasource", s->filename, 0);
    }
	
	if (is_http && c->http_persistent && *pb) {
        ret = open_url_keepalive(c->ctx, pb, url, &tmp);
        if (ret == AVERROR_EXIT) {
            return ret;
        } else if (ret < 0) {
            //if (ret != AVERROR_EOF)
            av_log(s, AV_LOG_WARNING, "keepalive request failed for '%s', retrying with new connection: %s\n", url, av_err2str(ret));
            ret = s->io_open(s, pb, url, AVIO_FLAG_READ, &tmp);
        }
    } else {
        ret = s->io_open(s, pb, url, AVIO_FLAG_READ, &tmp);
    }

    if (ret >= 0) {
        // update cookies on http response with setcookies.
        void *u = (s->flags & AVFMT_FLAG_CUSTOM_IO) ? NULL : s->pb;
        update_options(&c->cookies, "cookies", u);
        av_dict_set(&opts, "cookies", c->cookies, 0);
    }

    av_dict_free(&tmp);

    if (is_http)
        *is_http = av_strstart(proto_name, "http", NULL);

    return ret;
}

static struct segment *clone_segment(struct segment *_seg)
{
	struct segment *seg;
	seg = av_malloc(sizeof(struct segment));
	if (!seg) {
	   return 0;
	}

	seg->url = av_strdup(_seg->url);
	seg->key = av_strdup(_seg->key);
	seg->star_init_data = av_strdup(_seg->star_init_data);

	return seg;
}


static void parse_lang_tag(AVApplicationContext *app_ctx, URLContext* url_ctx, AVIOContext *in, char *lang_tag_re){
	if(app_ctx == NULL || url_ctx == NULL || in == NULL)
		return;
	
    char lang_tag[256]={0};
	
    if (url_ctx && url_ctx->args.info != NULL && url_ctx->args.info_len > 0) {
        if (strlen(url_ctx->args.lang)){
            sprintf(lang_tag, "LANGUAGE=\"%s\"", url_ctx->args.lang);
            if (check_audio_lang_exist(lang_tag, in)){
               strcpy(lang_tag_re, lang_tag);
			   return;
            }
        }
    }
	
	
	if (strlen(app_ctx->pss->audio_track) > 0){
		sprintf(lang_tag, "LANGUAGE=\"%s\"", app_ctx->pss->audio_track);
		if (check_audio_lang_exist(lang_tag, in)){
			strcpy(lang_tag_re, lang_tag);
			return;
		}
	}
	
	
	if (strlen(app_ctx->pss->audio_track_priority_list) > 0){
		char* p = NULL;
		
		char* pLang = strtok_r(app_ctx->pss->audio_track_priority_list, ";", &p);
		
		while (pLang != NULL){
			
			if (strlen(pLang) > 0){
				sprintf(lang_tag, "LANGUAGE=\"%s\"", pLang);
				if (check_audio_lang_exist(lang_tag, in)){
					strcpy(lang_tag_re, lang_tag);
					return;
				}
			}
			
			pLang = strtok_r(NULL, ";", &p);
		}
	}
	
}


static int parse_playlist(HLSContext *c, const char *url,
                          struct playlist *pls, AVIOContext *in)
{
    av_log(NULL, AV_LOG_DEBUG, "parse_playlist, ioctx=%d\n", in);
    int ret = 0, is_segment = 0, is_variant = 0;
    int64_t duration = 0, previous_duration1 = 0, previous_duration = 0, total_duration = 0;
    enum KeyType key_type = KEY_NONE;
    uint8_t iv[16] = "";
    int has_iv = 0;
    char key[MAX_URL_SIZE] = "";
    char key_src[MAX_URL_SIZE] = "";
    char line[MAX_URL_SIZE];
    const char *ptr;
    int close_in = 0;
    int64_t seg_offset = 0;
    int64_t seg_size = -1;
    uint8_t *new_url = NULL;
    struct variant_info variant_info;
    char tmp_str[MAX_URL_SIZE];
    struct segment *cur_init_section = NULL;
    int start_seq_no = -1;
    int is_http = av_strstart(url, "http", NULL);
	int has_m3u8_optimize = 0;
	int m3u8_optimize_need_read = 0;
    int m3u8_master_read_end = 0;
    
    if( c->parallel_open && pls->_type == AVMEDIA_TYPE_AUDIO )
    {
        if (is_http && !in && c->http_persistent && c->playlist_pb_audio) {
            in = c->playlist_pb_audio;
            ret = open_url_keepalive(c->ctx, &c->playlist_pb_audio, url, NULL);
            if (ret == AVERROR_EXIT) {
                return ret;
            } else if (ret < 0) {
                //if (ret != AVERROR_EOF)
                av_log(c->ctx, AV_LOG_WARNING, "keepalive request failed for '%s', retrying with new connection: %s\n", url, av_err2str(ret));
                in = NULL;
            }
        }
    }
    else
    {
        if (is_http && !in && c->http_persistent && c->playlist_pb) {
            in = c->playlist_pb;
            ret = open_url_keepalive(c->ctx, &c->playlist_pb, url, NULL);
            
            if (ret == AVERROR_EXIT) {
                return ret;
            } else if (ret < 0) {
                //if (ret != AVERROR_EOF)
                av_log(c->ctx, AV_LOG_WARNING, "keepalive request failed for '%s', retrying with new connection: %s\n", url, av_err2str(ret));
                in = NULL;
            }
        }
    }
    
    
    if (!in) {
#if 1
        AVDictionary *opts = NULL;
        //close_in = 1;
        //use options of user set
        av_dict_copy(&opts, c->avio_opts, 0);
        /* Some HLS servers don't like being sent the range header */
        av_dict_set(&opts, "seekable", "0", 0);

        // broker prior HTTP options that should be consistent across requests
        av_dict_set(&opts, "user-agent", c->user_agent, 0);
        av_dict_set(&opts, "cookies", c->cookies, 0);
        av_dict_set(&opts, "headers", c->headers, 0);
        av_dict_set(&opts, "http_proxy", c->http_proxy, 0);

        av_log(NULL, AV_LOG_TRACE,"chenwq: reload play list, interval=%lld\n", (av_gettime_relative()-pls->last_load_time)/1000);
        
        if (c->http_persistent)
            av_dict_set(&opts, "multiple_requests", "1", 0);
        
        if (c->use_redirect_ip)
            av_dict_set(&opts, "use_redirect_ip", "1", 0);
		
		
		URLStartStatus* pUSS = c->uss_default;
		if (c->parallel_open && pls->_type == AVMEDIA_TYPE_AUDIO){
			pUSS = c->uss_alt;
		}	
		//pUSS->path_type = ffg_get_http_path_info(url);
		av_dict_set_int(&opts, "URLStartStatus", (int64_t)(intptr_t)pUSS, 0);
        ret = c->ctx->io_open(c->ctx, &in, url, AVIO_FLAG_READ, &opts); 
        av_dict_free(&opts);
        if (ret < 0)
            return ret;
        
        if( c->parallel_open )
        {
            if (is_http && c->http_persistent && pls->_type == AVMEDIA_TYPE_VIDEO)
            {
                c->playlist_pb = in;
            }
            else if ( is_http && c->http_persistent && pls->_type == AVMEDIA_TYPE_AUDIO )
            {
                c->playlist_pb_audio = in;
            }
            else
                close_in = 1;
        }
        else
        {
            if (is_http && c->http_persistent )
                c->playlist_pb = in;
            else
                close_in = 1;
        }
        
#else
        ret = open_in(c, &in, url);
        if (ret < 0)
            return ret;
        close_in = 1;
#endif
    }

    if (av_opt_get(in, "location", AV_OPT_SEARCH_CHILDREN, &new_url) >= 0 && strlen(new_url)>0 )
        url = new_url;

    read_chomp_line(in, line, sizeof(line));
    if (strcmp(line, "#EXTM3U")) {
        ret = AVERROR_INVALIDDATA;
        goto fail;
    }

    if (pls) {
        free_segment_list(pls);
        free_original_segment_list(pls);

        pls->finished = 0;
        pls->type = PLS_TYPE_UNSPECIFIED;
    }
    
    if (c && c->app_ctx && c->app_ctx->demuxer) {
        c->app_ctx->demuxer->slave = SEGMENT_TS;
        memset(c->app_ctx->demuxer->master, 0, sizeof(c->app_ctx->demuxer->master));
        strcpy(c->app_ctx->demuxer->master, "hls");
    }
    
	
    char lang_tag[256]={0};
	char *lang = NULL;
	URLContext* url_ctx = ffio_geturlcontext(in);
    if (url_ctx && url_ctx->args.info != NULL && url_ctx->args.info_len > 0){
		if (c && c->app_ctx){
			parse_lang_tag(c->app_ctx, url_ctx, in, lang_tag);
			
			//get lang tag
			if (strlen(lang_tag) > 0){
				lang = lang_tag;
			}
		}	
	}
	
	
    char audio_langs[1024] = {0};
	int lang_index = 0;
	
    while (!avio_feof(in) || m3u8_optimize_need_read ) {
		if (c->use_m3u8_optimize_read && has_m3u8_optimize){
			m3u8_optimize_need_read = combine_chomp_line(c, pls, line, sizeof(line));
			if(m3u8_optimize_need_read == 0)
				break;
        }else if(url_ctx && url_ctx->args.info != NULL && url_ctx->args.info_len > 0){
            m3u8_master_read_end = filter_master_chomp_line(lang, in, line, sizeof(line), audio_langs, sizeof(audio_langs), &lang_index);
            if (m3u8_master_read_end) {
                if (audio_langs&&strlen(audio_langs)>0) {
                    av_application_did_parse_audio_tracks(c->app_ctx, audio_langs);
                }
            }
        }
		else{
			read_chomp_line(in, line, sizeof(line));
		}
		
		if (av_strstart(line, "#EXT-X-M3U8-OPTIMIZE:", &ptr) && c->use_m3u8_optimize_read ){
			struct m3u8_read_optimize_info info = {{0}};
			
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_m3u8_optimize_args, &info);	
			
			if (pls->m3u8_optimize)
				av_freep(&pls->m3u8_optimize);
				
			pls->m3u8_optimize = new_m3u8_optimize(pls, &info);
			if (check_m3u8_optimize_valid(pls))
			{
				has_m3u8_optimize = 1;
				m3u8_optimize_need_read = 1;
				av_application_did_http_m3u8_optimize(c->app_ctx,NULL);
			}
				
			
		}else if (av_strstart(line, "#EXT-X-STREAM-INF:", &ptr)) {
            is_variant = 1;
            memset(&variant_info, 0, sizeof(variant_info));
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_variant_args,
                               &variant_info);
        } else if (av_strstart(line, "#EXT-X-KEY:", &ptr)) {
            struct key_info info = {{0}};
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_key_args,
                               &info);
            key_type = KEY_NONE;
            has_iv = 0;
            if (!strcmp(info.method, "AES-128"))
                key_type = KEY_AES_128;
            if (!strcmp(info.method, "SAMPLE-AES"))
                key_type = KEY_SAMPLE_AES;
            if (!strncmp(info.iv, "0x", 2) || !strncmp(info.iv, "0X", 2)) {
                ff_hex_to_data(iv, info.iv + 2);
                has_iv = 1;
            }
            av_strlcpy(key, info.uri, sizeof(key));
        }else if (av_strstart(line, "#EXT-X-STARK:", &ptr)) {
            struct star_key_info info = {{0}};
            ff_parse_key_value(ptr, (ff_parse_key_val_cb)handle_starkey_args, &info);
            av_strlcpy(key, info.alg, sizeof(key));
            if (strlen(key)>0) {
                key_type = KEY_STAR_CRYPT;
            } else {
                key_type = KEY_NONE;
            }
            av_strlcpy(key_src, info.src, sizeof(key_src));
        }else if (av_strstart(line, "#EXT-X-MEDIA:", &ptr)) {
            struct rendition_info info = {{0}};
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_rendition_args,
                               &info);
            new_rendition(c, &info, url);
        } else if (av_strstart(line, "#EXT-X-TARGETDURATION:", &ptr)) {
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            pls->target_duration = atoi(ptr) * AV_TIME_BASE;
        } else if (av_strstart(line, "#EXT-X-MEDIA-SEQUENCE:", &ptr)) {
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            /* Some buggy HLS servers write #EXT-X-MEDIA-SEQUENCE more than once */
            if (start_seq_no < 0) {
                start_seq_no = atoi(ptr);
                pls->start_seq_no = start_seq_no;
            }
        } else if (av_strstart(line, "#EXT-X-PLAYLIST-TYPE:", &ptr)) {
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            if (!strcmp(ptr, "EVENT"))
                pls->type = PLS_TYPE_EVENT;
            else if (!strcmp(ptr, "VOD"))
                pls->type = PLS_TYPE_VOD;
        } else if (av_strstart(line, "#EXT-X-MAP:", &ptr)) {
            struct init_section_info info = {{0}};
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_init_section_args, &info);
            
            //live stream no need to update init section with same section data
            //such as go to see moov, update init secion with duplicated moov is useless
            if(pls->cur_init_section){
                if (pls->cur_init_section->star_init_data && !strcmp(info.star_init_data, pls->cur_init_section->star_init_data)){
                    if((pls->cur_init_section->key_initsec && !strcmp(info.alg, pls->cur_init_section->key_initsec))||
                       (pls->cur_init_section->key_initsec==NULL && !strlen(info.alg))){
                        av_log(NULL, AV_LOG_WARNING, "the same to current init section, no need to update_init_section\n");
                        cur_init_section = pls->cur_init_section;
                    }
                }
            }
            if(cur_init_section==NULL){
                cur_init_section = new_init_section(pls, &info, url, key_src);
            }

            if (c && c->app_ctx && c->app_ctx->demuxer && strstr(info.uri,".mp4")!=NULL) {
                c->app_ctx->demuxer->slave = SEGMENT_FMP4;
            }
            
        } else if (av_strstart(line, "#EXT-X-ENDLIST", &ptr)) {
            if (pls)
                pls->finished = 1;
        } else if (av_strstart(line, "#EXT-X-DISCONTINUITY", &ptr)) {
            previous_duration = previous_duration1;
        } else if (av_strstart(line, "#EXTINF:", &ptr)) {
            is_segment = 1;
            duration   = atof(ptr) * AV_TIME_BASE;
        } else if (av_strstart(line, "#EXT-X-BYTERANGE:", &ptr)) {
            seg_size = atoi(ptr);
            ptr = strchr(ptr, '@');
            if (ptr)
                seg_offset = atoi(ptr+1);
        } else if (av_strstart(line, "#", NULL)) {
            continue;
        } else if (line[0]) {
            if (is_variant) {
                if (!new_variant(c, &variant_info, line, url)) {
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
                is_variant = 0;
            }
            if (is_segment) {
                struct segment *seg;
                if (!pls) {
                    if (!new_variant(c, 0, url, NULL)) {
                        ret = AVERROR(ENOMEM);
                        goto fail;
                    }
                    pls = c->playlists[c->n_playlists - 1];
                }
                seg = av_mallocz(sizeof(struct segment));
				seg->star_init_data = NULL;
                if (!seg) {
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
                previous_duration1 += duration;
                seg->previous_duration = previous_duration;
                seg->start_time = total_duration;
                total_duration += duration;
                seg->duration = duration;
                seg->key_type = key_type;
                if (has_iv) {
                    memcpy(seg->iv, iv, sizeof(iv));
                } else {
                    int seq = pls->start_seq_no + pls->n_segments;
                    memset(seg->iv, 0, sizeof(seg->iv));
                    AV_WB32(seg->iv + 12, seq);
                }

                if (key_type != KEY_NONE) {
                    if (key_type==KEY_STAR_CRYPT) {
                        seg->key = av_strdup(key);
                        seg->key_src = av_strdup(key_src);
                    }else{
                        ff_make_absolute_url(tmp_str, sizeof(tmp_str), url, key);
                        seg->key = av_strdup(tmp_str);
                    }
                    if (!seg->key) {
                        av_free(seg);
                        ret = AVERROR(ENOMEM);
                        goto fail;
                    }
                } else {
                    seg->key = NULL;
                }

                ff_make_absolute_url(tmp_str, sizeof(tmp_str), url, line);

				if (c && c->app_ctx && c->app_ctx->caches
						&& c->app_ctx->caches->cache) {
					char bufferpath[256] = { };
					snprintf(bufferpath, sizeof(bufferpath), "%s/%s",
							c->app_ctx->caches->cache_path,
							av_basename(tmp_str));

					if (access(bufferpath, F_OK) == 0) {
						seg->url = av_strdup(bufferpath);
						av_application_did_http_local_cached_video(c->app_ctx, seg->url);
						av_log(NULL, AV_LOG_DEBUG, "cache::local_cached_video, url=%s\n", seg->url);
					} else {
						seg->url = av_strdup(tmp_str);
					}
				} else {
					seg->url = av_strdup(tmp_str);
				}
				
				if( av_stristr(url, "ijkmediadatasource:") )
                {
                    char bufferpath[256] = { };
                    snprintf(bufferpath, sizeof(bufferpath), "ijkmediadatasource:%s", av_basename(tmp_str));
                    seg->url = av_strdup(bufferpath);
                }

                if (!seg->url) {
                    av_free(seg->key);
                    av_free(seg);
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }

                dynarray_add(&pls->segments, &pls->n_segments, seg);

                //backup the segment because we will copy it to the playlist which is using. If not, the original segment will be missing.
                if(c->app_ctx->adaptive_bitrate_switching)
                {
                	struct segment *original_seg = clone_segment(seg);
                	if( original_seg )
                		dynarray_add(&pls->original_segments, &pls->original_n_segments, original_seg);
                }

                is_segment = 0;

                seg->size = seg_size;
                if (seg_size >= 0) {
                    seg->url_offset = seg_offset;
                    seg_offset += seg_size;
                    seg_size = -1;
                } else {
                    seg->url_offset = 0;
                    seg_offset = 0;
                }

                seg->init_section = cur_init_section;
				
				//av_log(NULL, AV_LOG_DEBUG, "chenwq: parse play list to create segment, url=%s, startime=%lld, duration=%lld\n", seg->url, seg->start_time/AV_TIME_BASE,seg->duration/AV_TIME_BASE);
            }
        }
    }
    if (pls){
        pls->last_load_time = av_gettime_relative();
        if (c->des_regular_rate > 0){
            av_log(NULL, AV_LOG_DEBUG, "ffmpeg:hls des_target_duration:%lld,des_regular_interval:%lld\n",
		   pls->target_duration, (int64_t)((double)c->des_regular_rate / 100 * pls->target_duration));
        }
    }

fail:
    av_free(new_url);
    if (close_in){
        in->protocol_close = 1;
        ff_format_io_close(c->ctx, &in);
    }
    return ret;
}

static struct segment *current_segment(struct playlist *pls)
{
    return pls->segments[pls->cur_seq_no - pls->start_seq_no];
}

enum ReadFromURLMode {
    READ_NORMAL,
    READ_COMPLETE,
};

static int read_from_url(struct playlist *pls, struct segment *seg,
                         uint8_t *buf, int buf_size,
                         enum ReadFromURLMode mode)
{
    int ret;

     /* limit read if the segment was only a part of a file */
    if (seg->size >= 0)
        buf_size = FFMIN(buf_size, seg->size - pls->cur_seg_offset);

    if (mode == READ_COMPLETE) {
        ret = avio_read(pls->input, buf, buf_size);
        if (ret != buf_size)
            av_log(NULL, AV_LOG_ERROR, "Could not read complete segment.\n");
    } else
        ret = avio_read(pls->input, buf, buf_size);
    
    if (ret > 0){
        pls->cur_seg_offset += ret;
        av_log(NULL, AV_LOG_TRACE, "chenwq: read ts data from io buffer, offset=%lld, buflen=%d, readlen=%d, url=%s\n", pls->cur_seg_offset, buf_size, ret,seg->url );
    }
    return ret;
}

/* Parse the raw ID3 data and pass contents to caller */
static void parse_id3(AVFormatContext *s, AVIOContext *pb,
                      AVDictionary **metadata, int64_t *dts,
                      ID3v2ExtraMetaAPIC **apic, ID3v2ExtraMeta **extra_meta)
{
    static const char id3_priv_owner_ts[] = "com.apple.streaming.transportStreamTimestamp";
    ID3v2ExtraMeta *meta;

    ff_id3v2_read_dict(pb, metadata, ID3v2_DEFAULT_MAGIC, extra_meta);
    for (meta = *extra_meta; meta; meta = meta->next) {
        if (!strcmp(meta->tag, "PRIV")) {
            ID3v2ExtraMetaPRIV *priv = meta->data;
            if (priv->datasize == 8 && !strcmp(priv->owner, id3_priv_owner_ts)) {
                /* 33-bit MPEG timestamp */
                int64_t ts = AV_RB64(priv->data);
                av_log(s, AV_LOG_DEBUG, "HLS ID3 audio timestamp %"PRId64"\n", ts);
                if ((ts & ~((1ULL << 33) - 1)) == 0)
                    *dts = ts;
                else
                    av_log(s, AV_LOG_ERROR, "Invalid HLS ID3 audio timestamp %"PRId64"\n", ts);
            }
        } else if (!strcmp(meta->tag, "APIC") && apic)
            *apic = meta->data;
    }
}

/* Check if the ID3 metadata contents have changed */
static int id3_has_changed_values(struct playlist *pls, AVDictionary *metadata,
                                  ID3v2ExtraMetaAPIC *apic)
{
    AVDictionaryEntry *entry = NULL;
    AVDictionaryEntry *oldentry;
    /* check that no keys have changed values */
    while ((entry = av_dict_get(metadata, "", entry, AV_DICT_IGNORE_SUFFIX))) {
        oldentry = av_dict_get(pls->id3_initial, entry->key, NULL, AV_DICT_MATCH_CASE);
        if (!oldentry || strcmp(oldentry->value, entry->value) != 0)
            return 1;
    }

    /* check if apic appeared */
    if (apic && (pls->ctx->nb_streams != 2 || !pls->ctx->streams[1]->attached_pic.data))
        return 1;

    if (apic) {
        int size = pls->ctx->streams[1]->attached_pic.size;
        if (size != apic->buf->size - AV_INPUT_BUFFER_PADDING_SIZE)
            return 1;

        if (memcmp(apic->buf->data, pls->ctx->streams[1]->attached_pic.data, size) != 0)
            return 1;
    }

    return 0;
}

/* Parse ID3 data and handle the found data */
static void handle_id3(AVIOContext *pb, struct playlist *pls)
{
    AVDictionary *metadata = NULL;
    ID3v2ExtraMetaAPIC *apic = NULL;
    ID3v2ExtraMeta *extra_meta = NULL;
    int64_t timestamp = AV_NOPTS_VALUE;

    parse_id3(pls->ctx, pb, &metadata, &timestamp, &apic, &extra_meta);

    if (timestamp != AV_NOPTS_VALUE) {
        pls->id3_mpegts_timestamp = timestamp;
        pls->id3_offset = 0;
    }

    if (!pls->id3_found) {
        /* initial ID3 tags */
        av_assert0(!pls->id3_deferred_extra);
        pls->id3_found = 1;

        /* get picture attachment and set text metadata */
        if (pls->ctx->nb_streams)
            ff_id3v2_parse_apic(pls->ctx, &extra_meta);
        else
            /* demuxer not yet opened, defer picture attachment */
            pls->id3_deferred_extra = extra_meta;

        av_dict_copy(&pls->ctx->metadata, metadata, 0);
        pls->id3_initial = metadata;

    } else {
        if (!pls->id3_changed && id3_has_changed_values(pls, metadata, apic)) {
            avpriv_report_missing_feature(pls->ctx, "Changing ID3 metadata in HLS audio elementary stream");
            pls->id3_changed = 1;
        }
        av_dict_free(&metadata);
    }

    if (!pls->id3_deferred_extra)
        ff_id3v2_free_extra_meta(&extra_meta);
}

static void intercept_id3(struct playlist *pls, uint8_t *buf,
                         int buf_size, int *len)
{
    /* intercept id3 tags, we do not want to pass them to the raw
     * demuxer on all segment switches */
    int bytes;
    int id3_buf_pos = 0;
    int fill_buf = 0;
    struct segment *seg = current_segment(pls);

    /* gather all the id3 tags */
    while (1) {
        /* see if we can retrieve enough data for ID3 header */
        if (*len < ID3v2_HEADER_SIZE && buf_size >= ID3v2_HEADER_SIZE) {
            bytes = read_from_url(pls, seg, buf + *len, ID3v2_HEADER_SIZE - *len, READ_COMPLETE);
            if (bytes > 0) {

                if (bytes == ID3v2_HEADER_SIZE - *len)
                    /* no EOF yet, so fill the caller buffer again after
                     * we have stripped the ID3 tags */
                    fill_buf = 1;

                *len += bytes;

            } else if (*len <= 0) {
                /* error/EOF */
                *len = bytes;
                fill_buf = 0;
            }
        }

        if (*len < ID3v2_HEADER_SIZE)
            break;

        if (ff_id3v2_match(buf, ID3v2_DEFAULT_MAGIC)) {
            int64_t maxsize = seg->size >= 0 ? seg->size : 1024*1024;
            int taglen = ff_id3v2_tag_len(buf);
            int tag_got_bytes = FFMIN(taglen, *len);
            int remaining = taglen - tag_got_bytes;

            if (taglen > maxsize) {
                av_log(pls->ctx, AV_LOG_ERROR, "Too large HLS ID3 tag (%d > %"PRId64" bytes)\n",
                       taglen, maxsize);
                break;
            }

            /*
             * Copy the id3 tag to our temporary id3 buffer.
             * We could read a small id3 tag directly without memcpy, but
             * we would still need to copy the large tags, and handling
             * both of those cases together with the possibility for multiple
             * tags would make the handling a bit complex.
             */
            pls->id3_buf = av_fast_realloc(pls->id3_buf, &pls->id3_buf_size, id3_buf_pos + taglen);
            if (!pls->id3_buf)
                break;
            memcpy(pls->id3_buf + id3_buf_pos, buf, tag_got_bytes);
            id3_buf_pos += tag_got_bytes;

            /* strip the intercepted bytes */
            *len -= tag_got_bytes;
            memmove(buf, buf + tag_got_bytes, *len);
            av_log(pls->ctx, AV_LOG_DEBUG, "Stripped %d HLS ID3 bytes\n", tag_got_bytes);

            if (remaining > 0) {
                /* read the rest of the tag in */
                if (read_from_url(pls, seg, pls->id3_buf + id3_buf_pos, remaining, READ_COMPLETE) != remaining)
                    break;
                id3_buf_pos += remaining;
                av_log(pls->ctx, AV_LOG_DEBUG, "Stripped additional %d HLS ID3 bytes\n", remaining);
            }

        } else {
            /* no more ID3 tags */
            break;
        }
    }

    /* re-fill buffer for the caller unless EOF */
    if (*len >= 0 && (fill_buf || *len == 0)) {
        bytes = read_from_url(pls, seg, buf + *len, buf_size - *len, READ_NORMAL);

        /* ignore error if we already had some data */
        if (bytes >= 0)
            *len += bytes;
        else if (*len == 0)
            *len = bytes;
    }

    if (pls->id3_buf) {
        /* Now parse all the ID3 tags */
        AVIOContext id3ioctx;
        ffio_init_context(&id3ioctx, pls->id3_buf, id3_buf_pos, 0, NULL, NULL, NULL, NULL);
        handle_id3(&id3ioctx, pls);
    }

    if (pls->is_id3_timestamped == -1)
        pls->is_id3_timestamped = (pls->id3_mpegts_timestamp != AV_NOPTS_VALUE);
}

static void sort_param_list( struct stKeyValue* paramList[], int paramNum ){
    struct stKeyValue* temp = NULL;
    int i = 0;
    int j = 0;
    for( i=0; i<paramNum; ++i){
        for( j=i+1; j<paramNum ; ++j)
        {
            if(strcmp(paramList[i]->key, paramList[j]->key)>0)
            {
                temp = paramList[i];
                paramList[i] = paramList[j];
                paramList[j] = temp;
            }  
        }
    }
    //reorder odd before even
    struct stKeyValue* frontParams[5];
    struct stKeyValue* behindParams[5];
    int frontCount = 0;
    int behindCount = 0;
    for ( i = 0; i < paramNum; ++i)
    {
        if (i%2==0)
            frontParams[frontCount++] = paramList[i];
        else
            behindParams[behindCount++] = paramList[i];
    }

    for ( i = 0; i < frontCount; ++i)
    {
        paramList[i] = frontParams[i];
    }

    for ( i=0; i < behindCount; ++i )
    {
        paramList[frontCount+i] = behindParams[i];
    }

}

static int generate_sign(HLSContext *c, char* sign, int size, struct stKeyValue* paramList [], int paramNum){
    int param_str_len = (sizeof(struct stKeyValue)+5)*paramNum;
    char *param_str = av_malloc(param_str_len);
    memset(param_str, 0, param_str_len);
    char* token = NULL;
    AVHMAC* hmac = NULL;
    
    int ret = -1;
    for ( int i=0; i<paramNum; i++) {
        char param[1024]={0};
        sprintf(param,"%s=%s", paramList[i]->key, paramList[i]->value);
        strcat(param_str, param);
        if ( i<paramNum-1 )
            strcat(param_str, "#$");
    }
    av_log(NULL, AV_LOG_DEBUG, "sign license param begin: %s\n", param_str);
    ff_get_player_option(c->app_ctx,OPT_LICENSE_TOKEN, &token);
    if (token==NULL){
        ret = -2;
        goto sign_fail;
    } 
    char* key = strrchr(token, '.')+1;
    if (key==NULL){
        ret = -3;
       goto sign_fail; 
    } 
        
    char sign_hmac[32] = {0};
    hmac = av_hmac_alloc(AV_HMAC_SHA256);
    ret = av_hmac_calc(hmac, param_str, strlen(param_str), key, strlen(key), sign_hmac, sizeof(sign_hmac));
    if( ret>0 ){
        av_base64_encode_urlsafe(sign, size, sign_hmac, sizeof(sign_hmac));
        av_log(NULL, AV_LOG_DEBUG, "sign license param success: key=%s, param=%s, sign=%s\n", key, param_str, sign);
        ret = 0;
    }else{
        ret = -4;
    }

sign_fail:
    if(hmac) av_hmac_free(hmac);
    if(param_str) av_free(param_str);
    if(token) av_free(token);
    return ret;
}

static int make_license_key_url(HLSContext *c,char* key_url, const char* key, AVDictionary** opts_license, const AVDictionary* opts){
    int ret = -1;
    char* keyid = strstr(key, LP_KEYID);
    if (keyid!=NULL&&strstr(keyid,"=")!=NULL) {
        keyid = strstr(keyid,"=") + 1;
    }
    else{
        av_log(NULL, AV_LOG_ERROR, "invalid format of key url, key=%s\n", key);
        return ret;
    }

    //sizeof(g_param_keys)/(sizeof(char*));
    int paramNum = LICENSE_PARAM_COUNT;
    struct stKeyValue* paramList[LICENSE_PARAM_COUNT];
    int64_t timestamp = av_gettime()/1000000;
    memset(paramList, 0, sizeof(struct stKeyValue*)*paramNum);
    for (int i = 0; i < paramNum; ++i)
    {
        paramList[i] = av_malloc(sizeof(struct stKeyValue));
        strcpy(paramList[i]->key,g_param_keys[i]);
        if (strcmp(LP_TIMESTAMP, g_param_keys[i])==0)
            sprintf(paramList[i]->value, "%lld", timestamp );
        else if (strcmp(LP_KEYID, g_param_keys[i])==0)
            strcpy(paramList[i]->value, keyid);
        else{
            char* key_value = NULL;
            ff_get_player_option(c->app_ctx, g_param_keys[i], &key_value);
            if (key_value!=NULL){
                strcpy(paramList[i]->value, key_value);
                av_free(key_value);
            }
        }
    }
    sort_param_list(paramList, paramNum);

    //sign hmac256 and base64 max length is 32/3*4=44 btyes
    char sign[64] = {0};
    ret = generate_sign(c,sign, sizeof(sign), paramList, paramNum);
    for (int i = 0; i<paramNum; ++i){
        av_free(paramList[i]);
    }
    if (ret==0) {
        sprintf(key_url, "%s&%s=%lld&%s=%s", key, LP_TIMESTAMP, timestamp, LP_SIGNATURE, sign );
        av_log(NULL, AV_LOG_DEBUG, "success to make license key url =%s\n", key_url);
    }
    else{
        av_log(NULL, AV_LOG_ERROR, "fail to make license key url, sign param error =%d\n", ret);
    }

    char* token = NULL;
    ff_get_player_option(c->app_ctx, OPT_LICENSE_TOKEN, &token);
    
    ret |= av_dict_copy(opts_license, opts, 0);
    ret |= av_dict_set(opts_license, "content_type", "text/plain;charset=UTF-8", 0);
    ret |= av_dict_set(opts_license, "authorization", token, 0);

#if 0
    //test to add headers when no api gateway
    char headers[1024]={0};
    char header_user[128]={0};
    char header_app[128]={0};
    char header_device[128]={0};
    char* user_id = NULL;
    char* app_id = NULL;
    char* device_id = NULL;
    ff_get_player_option(c->app_ctx, OPT_LICENSE_USER_ID, &user_id);
    ff_get_player_option(c->app_ctx, OPT_LICENSE_APP_ID, &app_id);
    ff_get_player_option(c->app_ctx, OPT_LICENSE_DEVICE_ID, &device_id);
    sprintf(header_user, "X-UserID: %s\r\n", user_id);
    sprintf(header_app, "X-ApplicationID: %s\r\n", app_id);
    sprintf(header_device, "X-DeviceID: %s\r\n", device_id);
    av_free(user_id);
    av_free(app_id);
    av_free(device_id);
    strcat(headers, header_user);
    strcat(headers, header_app);
    strcat(headers, header_device);
    ret |= av_dict_set(opts_license, "headers", headers, 0);
#endif
    return ret;
}

//parse license content from server and get plaintext of the content key
//license content format: code=xxx&message=xxx&key=xxx&crc=xxx&right=xxx
static int parse_license(HLSContext *c, struct stLicenseInfo* license, const char* license_str ){
    int param_num = 0;
    int max_param_num = 10;
    char* paramList [10] = {0};
    char* param = NULL;
    char* p = NULL;
    char params[MAX_LICENSE_CONTENT_LEN]={0};
    strcpy(params, license_str);
    param = strtok_r(params, KEY_VALUE_SPERATOR, &p);
    //split each param
    av_log(NULL,AV_LOG_DEBUG,"license content params: \n");
    while(param != NULL){
        if(param_num>max_param_num)
            break;
        paramList[param_num] = av_malloc(strlen(param)+1);
        strcpy(paramList[param_num],param);
        param_num++;
        av_log(NULL,AV_LOG_DEBUG,"%d, %s\n", param_num, param);
        param = strtok_r(NULL, KEY_VALUE_SPERATOR, &p);
    }

    //rsa2048 encrypt and base64 key max len 256/3*4=342
    //crc base64 max len 4/3*4=6
    char key_enc[LP_VALUE_MAX_LEN] = {0};
    char crc_enc[LP_VALUE_MAX_LEN] = {0};
    for (int i = 0; i < param_num; ++i){
        char*p = paramList[i];
        char* param_value = strchr(p, KEY_VALUE_LINKER)+1;
        char param_key[LP_KEY_MAX_LEN] = {0};
        strncpy(param_key, paramList[i], param_value-p-1);
        if (strcmp(param_key, LR_KEY)==0)
            strcpy(key_enc, param_value);
        if (strcmp(param_key, LR_CRC)==0)
            strcpy(crc_enc, param_value);
        if (strcmp(param_key, LR_MESSAGE)==0)
            strcpy(license->message, param_value);
        if (strcmp(param_key, LR_RIGHT)==0)
            strcpy(license->right, param_value);
        if (strcmp(param_key, LR_CODE)==0)
            license->code = atoi(param_value);
    }
    for (int i = 0; i < param_num; ++i)
    {
        av_free(paramList[i]);
    }
    
    if (license->code!=0) {
        av_log(NULL, AV_LOG_ERROR, "fail to get license, err=%d\n", license->code);
        return -license->code;
    }

    //decrypt content key
    char* key_dec = NULL;
    char* private_key = NULL;
    char* seed = NULL;
    ff_get_player_option(c->app_ctx, OPT_LICENSE_DEVICE_ID, &seed);
    ff_get_player_option(c->app_ctx, OPT_LICENSE_PRIVATE_KEY, &private_key);
    int ret = ff_rsa_decrypt( seed, private_key, key_enc, &key_dec );
    if (private_key) 
        av_free(private_key);
    if (seed) 
        av_free(seed);
    if (key_dec==NULL||ret<AES128_KEY_LEN)
    {
        av_log(NULL, AV_LOG_ERROR, "fail to decrypt content key, ret=%d\n", ret);
        return -10;
    }
    memcpy(license->key, key_dec, AES128_KEY_LEN);
    av_free(key_dec);

//    char* hex_key = NULL;
//    string2hexstr(license->key, &hex_key);
//    av_log(NULL, AV_LOG_DEBUG, "content key hex=%s\n", hex_key);
//    av_free(hex_key);
    
    //check crc by the same algorithm to java crc32
    ret = av_base64_decode_urlsafe((char*)&license->crc, crc_enc, sizeof(license->crc));
    if (ret<=0){
        av_log(NULL, AV_LOG_ERROR, "fail to decode key crc, ret=%d\n", ret);
        return -20;
    }
    license->crc = av_bswap32(license->crc);
    AVCRC* crc_ctx = av_crc_get_table(AV_CRC_32_IEEE_LE);
    unsigned int crc_local = av_crc2(crc_ctx, -1, license->key, AES128_KEY_LEN );
    if (crc_local!=license->crc){
        av_log(NULL, AV_LOG_ERROR, "check crc invalid, recv=0x%08x, local=0x%08x\n", license->crc, crc_local);
        return -30;
    }
    return 0;
}




static int open_input(HLSContext *c, struct playlist *pls, struct segment *seg)
{
    AVDictionary *opts = NULL;
    int ret;
    int is_http = 0;
    
    if (c->http_persistent)
        av_dict_set(&opts, "multiple_requests", "1", 0);
    
    if (c->use_redirect_ip)
        av_dict_set(&opts, "use_redirect_ip", "1", 0);
	
	URLStartStatus* pUSS = c->uss_default_segment;
	if (c->parallel_open && pls->_type == AVMEDIA_TYPE_AUDIO){
		pUSS = c->uss_alt_segment;
	}
	//pUSS->path_type = ffg_get_http_path_info(seg->url);
	av_dict_set_int(&opts, "URLStartStatus", (int64_t)(intptr_t)pUSS, 0);

    // broker prior HTTP options that should be consistent across requests
    av_dict_set(&opts, "user-agent", c->user_agent, 0);
    av_dict_set(&opts, "cookies", c->cookies, 0);
    av_dict_set(&opts, "headers", c->headers, 0);
    av_dict_set(&opts, "http_proxy", c->http_proxy, 0);
    av_dict_set(&opts, "seekable", "0", 0);

    if (seg->size >= 0) {
        /* try to restrict the HTTP request to the part we want
         * (if this is in fact a HTTP request) */
        av_dict_set_int(&opts, "offset", seg->url_offset, 0);
        av_dict_set_int(&opts, "end_offset", seg->url_offset + seg->size, 0);
    }

    av_log(pls->parent, AV_LOG_INFO, "HLS request for url '%s', offset %"PRId64", playlist %d, curseq=%d, startseq=%d\n",
           seg->url, seg->url_offset, pls->index, pls->cur_seq_no, pls->start_seq_no );

    if (seg->key_type == KEY_NONE) {
		if(c->app_ctx && (!c->app_ctx->pss->complete)){
			if(c->parallel_open){
				if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", DRM_NONE);
				}
				else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type_audio = %d", DRM_NONE);
				}
			}
			else{
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", DRM_NONE);
			}
		}
     
        ret = open_url(pls->parent, &pls->input, seg->url, c->avio_opts, opts, &is_http);
    } else if (seg->key_type == KEY_AES_128) {
        char iv[33], key[33], url[MAX_URL_SIZE];
        AVDictionary *opts2 = NULL;
        if (strcmp(seg->key, pls->key_url)) {
            AVIOContext *pb;
            int key_error_code = 0;
            if (strstr(seg->key,INTERFACE_LICENSE)==NULL) {
				if(c->app_ctx && (!c->app_ctx->pss->complete)){
					if(c->parallel_open){
						if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
							startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", DRM_AES128);
						}
						else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
							startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type_audio = %d", DRM_AES128);
						}
					}
					else{
						startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", DRM_AES128);
					}
				}
				
                if ((ret=open_url(pls->parent, &pb, seg->key, c->avio_opts, opts, NULL)) == 0) {
                    ret = avio_read(pb, pls->key, sizeof(pls->key));
                    if (ret != sizeof(pls->key)) {
                        av_log(NULL, AV_LOG_ERROR, "Unable to read key file %s\n",seg->key);
                    }
                    ff_format_io_close(pls->parent, &pb);
                }
            }
            else{
                //get license from server
				if(c->app_ctx && (!c->app_ctx->pss->complete)){
					if(c->parallel_open){
						if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
							startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", DRM_STAR);
						}
						else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
							startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type_audio = %d", DRM_STAR);
						}
					}
					else{
						startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", DRM_STAR);
					}
				}
				
                AVDictionary *opts_license = NULL;
                char key_url[MAX_URL_SIZE]={0};
                ret = make_license_key_url(c, key_url, seg->key, &opts_license, opts );
                if (!ret) {
                    int license_try_count = 0;
                    while (license_try_count++<3) {
                        av_log(NULL, AV_LOG_DEBUG, "try to read license, url=%s, try=%d\n", seg->key, license_try_count);
                        if ((ret=open_url(pls->parent, &pb, key_url, c->avio_opts, opts_license, NULL)) == 0) {
                            char licence_str[MAX_LICENSE_CONTENT_LEN] = {0};
                            ret = avio_read(pb, licence_str, sizeof(licence_str));
                            if (ret>0) {
                                struct stLicenseInfo license;
                                memset(&license, 0, sizeof(license));
                                ret = parse_license(c, &license, licence_str);
                                if (ret==0) {
                                    memcpy(pls->key, license.key, sizeof(pls->key));
                                    break;
                                }
                                else{
                                    key_error_code = ERROR_KEY_PARSE_FAIL;
                                    av_log(NULL, AV_LOG_ERROR, "fail to parse license, url=%s\n",seg->key);
                                }
                            }else{
                                //detail error code in http/tcp module
                                av_log(NULL, AV_LOG_ERROR, "fail to read license, url=%s\n",seg->key);
                            }
                            ff_format_io_close(pls->parent, &pb);
                        }
                    }
                    if (opts_license)
                        av_dict_free(&opts_license);
                }
                else{
                    key_error_code = ERROR_KEY_URL_FAIL;
                    av_log(NULL, AV_LOG_ERROR, "fail to make license url, url=%s\n",seg->key);
                }
            }
            if(ret<0){
                //add chenwq, interupt play when read key error, only when starting
                av_log(NULL, AV_LOG_ERROR, "Unable to get key, url=%s, ret=%d\n", seg->key, ret);
				if(c->app_ctx && (!c->app_ctx->pss->complete)){
					if (0!=key_error_code) {
                        if(c->parallel_open){
							if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
								startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", key_error_code );
								startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret );
							}
							else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
								startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", key_error_code );
								startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret );
							}
						}
						else{
							startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", key_error_code );
							startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret );
						}
                    }
					ret = AVERROR_FAIL_ACCESS_AES_KEY;
						
				}
				goto cleanup;
            }
            av_strlcpy(pls->key_url, seg->key, sizeof(pls->key_url));
        }
        ff_data_to_hex(iv, seg->iv, sizeof(seg->iv), 0);
        ff_data_to_hex(key, pls->key, sizeof(pls->key), 0);
        iv[32] = key[32] = '\0';
        if (strstr(seg->url, "://"))
            snprintf(url, sizeof(url), "crypto+%s", seg->url);
        else
            snprintf(url, sizeof(url), "crypto:%s", seg->url);

        av_dict_copy(&opts2, c->avio_opts, 0);
        av_dict_set(&opts2, "key", key, 0);
        av_dict_set(&opts2, "iv", iv, 0);
        ret = open_url(pls->parent, &pls->input, url, opts2, opts, &is_http);

        av_dict_free(&opts2);

        if (ret < 0) {
            goto cleanup;
        }
        ret = 0;
    } else if (seg->key_type == KEY_SAMPLE_AES) {
        av_log(pls->parent, AV_LOG_ERROR,
               "SAMPLE-AES encryption is not supported yet\n");
        ret = AVERROR_PATCHWELCOME;
    } else if (seg->key_type == KEY_STAR_CRYPT) {
		if(c->app_ctx && (!c->app_ctx->pss->complete)){
			if(c->parallel_open){
				if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", seg->key_type);
				}
				else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type_audio = %d", seg->key_type);
				}
			}
			else{
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "drm_type = %d", seg->key_type);
			}
		}
		
        ret = open_url(pls->parent, &pls->input, seg->url, c->avio_opts, opts, &is_http);
    }
    else
      ret = AVERROR(ENOSYS);

    /* Seek to the requested position. If this was a HTTP request, the offset
     * should already be where want it to, but this allows e.g. local testing
     * without a HTTP server.
     *
     * This is not done for HTTP at all as avio_seek() does internal bookkeeping
     * of file offset which is out-of-sync with the actual offset when "offset"
     * AVOption is used with http protocol, causing the seek to not be a no-op
     * as would be expected. Wrong offset received from the server will not be
     * noticed without the call, though.
     */
    if (ret == 0 && !is_http && seg->key_type == KEY_NONE && seg->url_offset) {
        int64_t seekret = avio_seek(pls->input, seg->url_offset, SEEK_SET);
        if (seekret < 0) {
            av_log(pls->parent, AV_LOG_ERROR, "Unable to seek to offset %"PRId64" of HLS segment '%s'\n", seg->url_offset, seg->url);
            ret = seekret;
            ff_format_io_close(pls->parent, &pls->input);
        }
    }

cleanup:
    av_dict_free(&opts);
    pls->cur_seg_offset = 0;
    return ret;
}


static int decrypt_init_section_data(struct playlist *pls, struct segment *seg){
    int ret = 0;
    HLSContext *c = pls->parent->priv_data;
    if (seg->key_initsec && seg->key_src) {
        AVCustomAlgOpt opt;
        ret = customkey_get_alg(&opt, seg->key_initsec, seg->key_src);
        if(ret==0){
            switch (opt.alg) {
                case ALG_BLOWFISH32:{
                    BLOWFISH_CTX bfctx;
                    blowfish_init(opt.key, sizeof(opt.key), opt.factor, &bfctx);
                    ret = blowfish_decrypt(&bfctx, pls->init_sec_buf, pls->init_sec_buf, pls->init_sec_data_len/BLOWFISH_BLOCK_SIZE);
                    av_hex_dump_log(NULL, AV_LOG_DEBUG, pls->init_sec_buf, 16);
                    break;
                }
                case ALG_AES128:{
                    struct AVAES* aesctx = av_aes_alloc();
                    ret = av_aes_init(aesctx, opt.key, sizeof(opt.key)*8, 1);
                    av_aes_crypt(aesctx, pls->init_sec_buf, pls->init_sec_buf, pls->init_sec_data_len/16, NULL, 1);
                    av_free(aesctx);
                    av_hex_dump_log(NULL, AV_LOG_DEBUG, pls->init_sec_buf, 16);
                    break;
                }
                default:
                    ret = -1;
                    av_log(NULL, AV_LOG_ERROR, "starcrypt, init section data invalid alg, alg=%s\n", seg->key_initsec);
                    break;
            }
        }
        if(ret!=0){
            av_log(NULL, AV_LOG_ERROR, "starcrypt, decrypt init section data fail, alg=%s, ret=%d, seclen=%d\n", seg->key_initsec, ret, pls->init_sec_data_len);
            if(c->app_ctx && (!c->app_ctx->pss->complete)){
				if(c->parallel_open){
					if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
						startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_PARSE_INIT_FAIL );
						startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret );
					}
					else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
						startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", ERROR_KEY_PARSE_INIT_FAIL );
						startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret );
					}
				}
				else{
					startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_PARSE_INIT_FAIL );
					startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret );
				}
			}
			
            return AVERROR_FAIL_UNSUPPORT_CRYPT_ALG;
        }else{
            av_log(NULL, AV_LOG_DEBUG, "starcrypt, decrypt init section data success, index=%d, alg=%d, factor=%d, seclen=%d\n", opt.index, opt.alg, opt.factor, pls->init_sec_data_len);
            if(c->app_ctx && (!c->app_ctx->pss->complete)){
				if(c->parallel_open){
					if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
						startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_drm = %d", opt.alg);
					}
					else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
						startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_drm_audio = %d", opt.alg);
					}
				}
				else{
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_drm = %d", opt.alg);
				}
			}
			
        }
    }
    return 0;
}


static int update_init_section_use_init_data(struct playlist *pls, struct segment *seg)
{
	HLSContext *c = pls->parent->priv_data;
	if(c->app_ctx && (!c->app_ctx->pss->complete)){
		if(c->parallel_open){
			if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_optimize_begin = %lld",av_gettime()/1000);
			}
			else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_optimize_begin_audio = %lld",av_gettime()/1000);
			}
		}
		else{
			startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_optimize_begin = %lld",av_gettime()/1000);
		}
	}
    
    av_log(NULL, AV_LOG_DEBUG, "star_init_optimize original:data=%s, ret=%d\n",seg->star_init_data,strlen(seg->star_init_data));
	
    char base64_data[MAX_STAR_INIT_DATA] = {0};
	int ret = av_base64_decode(base64_data,seg->star_init_data,sizeof(base64_data));
	if (ret<=0)
	{
		av_log(NULL, AV_LOG_ERROR, "star_init_optimize:fail to base64 decode init data, ret=%d\n", ret);
        return -1;
	}
	av_log(NULL, AV_LOG_DEBUG, "star_init_optimize:success to base64 decode init data,data=%s,ret=%d\n",base64_data, ret);
  
    
#if CONFIG_ZLIB
    z_stream inflate_stream = {0};
    inflate_stream.zalloc = Z_NULL;
    inflate_stream.zfree  = Z_NULL;
    inflate_stream.opaque = Z_NULL;
    inflate_stream.next_in  = base64_data;
    inflate_stream.avail_in = ret;
    
    pls->init_sec_buf = av_malloc(MAX_STAR_INIT_DATA);
    memset(pls->init_sec_buf, 0, sizeof(pls->init_sec_buf));
    inflate_stream.avail_out = MAX_STAR_INIT_DATA;
    inflate_stream.next_out  = pls->init_sec_buf;
    //av_log(NULL, AV_LOG_ERROR, "star_init_optimize:into inflateInit \n");
    ret = inflateInit(&inflate_stream);
	//av_log(NULL, AV_LOG_ERROR, "star_init_optimize:end inflateInit , ret=%d \n", ret);
    if ( ret != Z_OK)
    {
        av_log(NULL, AV_LOG_ERROR, "star_init_optimize:fail to inflateInit , ret=%d \n", ret);
        av_freep(pls->init_sec_buf);
        return -1;
    }
    
    ret = inflate(&inflate_stream, Z_SYNC_FLUSH);
    inflateEnd(&inflate_stream);
    if (ret != Z_OK && ret != Z_STREAM_END)
    {
        av_log(NULL, AV_LOG_ERROR, "star_init_optimize:fail to inflate init data, ret=%d, flate_stream.msg=%s\n", ret,inflate_stream.msg);
        av_freep(pls->init_sec_buf);
        return -1;
    }
    
    av_log(NULL, AV_LOG_DEBUG, "star_init_optimize:inflate data success ret=%d\n",ret);
    
    pls->cur_init_section = seg;
    pls->init_sec_data_len = inflate_stream.total_out;
    pls->init_sec_buf_read_offset = 0;
    
    ret = decrypt_init_section_data(pls, seg);
    if (ret!=0){
        return ret;
    }

    /* spec says audio elementary streams do not have media initialization
     * sections, so there should be no ID3 timestamps */
    pls->is_id3_timestamped = 0;
	if(c->app_ctx && (!c->app_ctx->pss->complete)){
		if(c->parallel_open){
			if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_optimize_finish = %lld",av_gettime()/1000);
			}
			else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_optimize_finish_audio = %lld",av_gettime()/1000);
			}
		}
		else{
			startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "star_init_optimize_finish = %lld",av_gettime()/1000);
		}
	}
    
    return 0;
#endif /* CONFIG_ZLIB */

    return -1;
}


static int update_init_section(struct playlist *pls, struct segment *seg)
{
    static const int max_init_section_size = 1024*1024;
    HLSContext *c = pls->parent->priv_data;
    int64_t sec_size;
    int64_t urlsize;
    int ret;

    if (seg->init_section == pls->cur_init_section)
        return 0;

    pls->cur_init_section = NULL;

    if (!seg->init_section)
        return 0;
	
	if (seg->init_section->star_init_data)
    {
		ret = update_init_section_use_init_data(pls,seg->init_section);
		av_log(NULL, AV_LOG_DEBUG, "star_init_optimize  update_init_section ret = %d, time=%lld\n", ret, av_gettime()/1000);
		if (ret == 0){
			return 0;
		}
	}

    ret = open_input(c, pls, seg->init_section);
    if (ret < 0) {
        av_log(pls->parent, AV_LOG_WARNING,
               "Failed to open an initialization section in playlist %d\n",
               pls->index);
        return ret;
    }

    if (seg->init_section->size >= 0)
        sec_size = seg->init_section->size;
    else if ((urlsize = avio_size(pls->input)) >= 0)
        sec_size = urlsize;
    else
        sec_size = max_init_section_size;

    av_log(pls->parent, AV_LOG_DEBUG,
           "Downloading an initialization section of size %"PRId64"\n",
           sec_size);

    sec_size = FFMIN(sec_size, max_init_section_size);

    av_fast_malloc(&pls->init_sec_buf, &pls->init_sec_buf_size, sec_size);

    ret = read_from_url(pls, seg->init_section, pls->init_sec_buf,
                        pls->init_sec_buf_size, READ_COMPLETE);
    if (ret<0){
        return ret;
    }
    ff_format_io_close(pls->parent, &pls->input);
    
    pls->cur_init_section = seg->init_section;
    pls->init_sec_data_len = ret;
    pls->init_sec_buf_read_offset = 0;
    
    ret = decrypt_init_section_data(pls, seg->init_section);
    if (ret!=0) {
        return ret;
    }

    /* spec says audio elementary streams do not have media initialization
     * sections, so there should be no ID3 timestamps */
    pls->is_id3_timestamped = 0;

    return 0;
}


static int is_variant_url(HLSContext* c, const char* url){
    for (int i = 0; i < c->n_variants; ++i)
    {
        if (c->variants[i]->playlists!=NULL)
        {
            char* variant_url = c->variants[i]->playlists[0];
            if(strcmp(variant_url, url)==0){
                return 1;
            }
        }
        
    }
    return 0;
}

static void retry_read_waiting(HLSContext* c, int ret){
    if(c->retry_interval_time==0){
        c->retry_interval_time = MIN_SLEEP_INTETVAL*5;
    }
    av_log(NULL, AV_LOG_WARNING, "open input fail, %s, retry_interval=%dms\n", av_err2str(ret), c->retry_interval_time/1000);
    int sleep_count = c->retry_interval_time/MIN_SLEEP_INTETVAL;
    while (!ff_check_interrupt(c->interrupt_callback)&&sleep_count-->0) {
        av_usleep(MIN_SLEEP_INTETVAL);
    }
    c->retry_interval_time *= 3;
}

static void retry_normal_waiting(HLSContext* c, int seconds){
    int count = seconds*10;
    while (!ff_check_interrupt(c->interrupt_callback)&&count-->0) {
        av_usleep(MIN_SLEEP_INTETVAL);
    }
}


//callback for AVIOConext read_packet
static int read_data(void *opaque, uint8_t *buf, int buf_size)
{
    struct playlist *v = opaque;
    HLSContext *c = v->parent->priv_data;
    
    // init varaint
    if (c && c->n_variants > 1 && is_bitrate_inited(c->app_ctx) == 0)
    {
        if(bitrate_init_varaints(c->app_ctx, c->n_variants)==0){
            for (int i = 0; i < c->n_variants; i++)
            {
                bitrate_insert_varaint(c->app_ctx, i, c->variants[i]->playlists[0]->url, c->variants[i]->bandwidth);
            }
        }
    }

    int ret, i;
    int just_opened = 0;
    static int64_t download_begin_time = 0;
restart:
    if (!v->needed)
        return AVERROR_EOF;

    if (!v->input || (c->http_persistent && v->input_read_done)) {
        int64_t reload_interval;
        struct segment *seg;

        /* Check that the playlist is still needed before opening a new
         * segment. */
        if (v->ctx && v->ctx->nb_streams &&
            v->parent->nb_streams >= v->stream_offset + v->ctx->nb_streams) {
            v->needed = 0;
            for (i = v->stream_offset; i < v->stream_offset + v->ctx->nb_streams;
                i++) {
                if (v->parent->streams[i]->discard < AVDISCARD_ALL)
                    v->needed = 1;
            }
        }
        if (!v->needed) {
            av_log(v->parent, AV_LOG_INFO, "No longer receiving playlist %d\n",
                v->index);
            return AVERROR_EOF;
        }

        /* If this is a live stream and the reload interval has elapsed since
         * the last playlist reload, reload the playlists now. */
		reload_interval = default_reload_interval(v);

reload:
        if (!v->finished &&
            av_gettime_relative() - v->last_load_time >= reload_interval) {
            if ((ret = parse_playlist(c, v->url, v, NULL)) < 0) {
                av_log(v->parent, AV_LOG_WARNING, "Failed to reload playlist %d\n",
                       v->index);
                //chenwq: looply reload m3u8 if fail for http keepalive
                //fix bug of long time pause when playing live stream
                if(c->app_ctx && c->app_ctx->lss->download_ts_data>0){
                    if (ff_check_interrupt(c->interrupt_callback)) {
                        return ret;
                    }
                    
                    if (ret == AVERROR_HTTP_FORBIDDEN || ret == AVERROR_HTTP_UNAUTHORIZED) {
                        retry_read_waiting(c, ret);
                    }
                    retry_normal_waiting(c, 1);
                    
                    if(c->app_ctx)
                    {
                        URLStartStatus* pUSS = c->uss_default;
                        if (c->parallel_open && v->_type == AVMEDIA_TYPE_AUDIO){
                            pUSS = c->uss_alt;
                        }
                        
                        if(pUSS->fls->last_download_fail_timestamp==0 || (pUSS->fls->last_download_fail_timestamp>0 && (av_gettime()/1000-pUSS->fls->last_download_fail_timestamp)>5000))
                        {
                            add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_ERROR_CODE,ret);
                            add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_FINISH,av_gettime()/1000);
                            pUSS->fls->last_download_fail_timestamp =av_gettime()/1000;
                        }
                    }
                    
                    goto reload;
                }
                return ret;
            }
            
            /* If we need to reload the playlist again below (if
             * there's still no more segments), switch to a reload
             * interval of half the target duration. */
			if(c && c->des_retry_interval > 0){
				reload_interval = c->des_retry_interval * 1000;
			}
			else{
				reload_interval = v->target_duration / 2;
			}
            
            c->retry_interval_time = 0;
        }

        
        if (v->cur_seq_no < v->start_seq_no) {
            av_log(NULL, AV_LOG_WARNING,
                      "skipping %d segments ahead, expired from playlists, cur=%d, start=%d\n",
                      v->start_seq_no - v->cur_seq_no, v->start_seq_no, v->cur_seq_no);
            v->cur_seq_no = v->start_seq_no;
        }
        if (v->cur_seq_no >= v->start_seq_no + v->n_segments) {
            if (v->finished)
                return AVERROR_EOF;
            while (av_gettime_relative() - v->last_load_time < reload_interval) {
                if (ff_check_interrupt(c->interrupt_callback))
                    return AVERROR_EXIT;
                av_usleep(100*1000);
            }
            /* Enough time has elapsed since the last reload */
            goto reload;
        }

        //if it is VOD, use the segment of playlist which is better for the current bandwidth. we will copy the segment from the backups.
        //if it is live, because the url is changed, the segment will be updated in the parse_playlist function.
        if( is_bitrate_inited(c->app_ctx) && is_bitrate_updated && v->needed && is_variant_url(c, v->url))
        {
        	if (c->n_variants > 1 ) {
                struct playlist *pls = c->variants[get_current_bitrate_index(c->app_ctx)]->playlists[0];
        		if( pls && pls->finished == 1 )
        		{
        			for (int i = 0; i < pls->original_n_segments; i++) {
                        av_log(NULL, AV_LOG_DEBUG, "update bitrate playlist segment, cur=%s, better=%s\n", v->segments[i]->url, pls->original_segments[i]->url);
        				av_freep(&v->segments[i]->key);
        				av_freep(&v->segments[i]->url);
						av_freep(&v->segments[i]->star_init_data);
        				v->segments[i]->url = av_strdup(pls->original_segments[i]->url);
        				v->segments[i]->key = av_strdup(pls->original_segments[i]->key);
						v->segments[i]->star_init_data = av_strdup(pls->original_segments[i]->star_init_data);
                        
        			}
        		}
        	}
        }

        v->input_read_done = 0;
        seg = current_segment(v);

        /* load/update Media Initialization Section, if any */
        ret = update_init_section(v, seg);
        if (ret)
            return ret;
        //zy add
		if(c->app_ctx && (!c->app_ctx->pss->complete)){
			if(c->parallel_open){
				if((!c->uss_default->complete) && v->_type == AVMEDIA_TYPE_VIDEO ){
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_begin = %lld",av_gettime()/1000);
					c->app_ctx->lss->download_ts_data=0;
				}
				else if((!c->uss_alt->complete) && v->_type == AVMEDIA_TYPE_AUDIO){
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_begin_audio = %lld",av_gettime()/1000);
					c->app_ctx->lss->download_ts_data_audio = 0;
				}
			}
			else{
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_begin = %lld",av_gettime()/1000);
				c->app_ctx->lss->download_ts_data=0;
			}
		}
        
        bitrate_begin_calculate(c->app_ctx);
        ///////////////////////////////
        download_begin_time = av_gettime()/1000;
        ret = open_input(c, v, seg);
        if (ret < 0) {
            if (ff_check_interrupt(c->interrupt_callback))
                return AVERROR_EXIT;
            if ( ret==AVERROR_FAIL_ACCESS_AES_KEY || ret==AVERROR_FAIL_UNSUPPORT_CRYPT_ALG )
                return ret;
            av_log(v->parent, AV_LOG_WARNING, "Failed to open segment of playlist %d\n",
                   v->index);
            //zy add
            //v->cur_seq_no += 1;
            if( ret == AVERROR_HTTP_NOT_FOUND )
            {
                av_log(v->parent, AV_LOG_WARNING, "ret= %d %s\n", ret, av_err2str(ret));
                v->cur_seq_no += 1;
            }else if (ret == AVERROR_HTTP_FORBIDDEN || ret == AVERROR_HTTP_UNAUTHORIZED) {
                retry_read_waiting(c, ret);
            }
            retry_normal_waiting(c, 1);
            
            if(c->app_ctx)
            {
				URLStartStatus* pUSS = c->uss_default;
				if (c->parallel_open && v->_type == AVMEDIA_TYPE_AUDIO){
					pUSS = c->uss_alt;
				}
				
                if(pUSS->fls->last_download_fail_timestamp==0 || (pUSS->fls->last_download_fail_timestamp>0 && (av_gettime()/1000-pUSS->fls->last_download_fail_timestamp)>5000)){
                    add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_ERROR_CODE,ret);
                    add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_FINISH,av_gettime()/1000);
                    pUSS->fls->last_download_fail_timestamp=av_gettime()/1000;
                }
            }
            goto reload;
        }
        just_opened = 1;
    }

    c->retry_interval_time = 0;
    
    

    if (v->init_sec_buf_read_offset < v->init_sec_data_len) {
        /* Push init section out first before first actual segment */
        int copy_size = FFMIN(v->init_sec_data_len - v->init_sec_buf_read_offset, buf_size);
        memcpy(buf, v->init_sec_buf, copy_size);
        v->init_sec_buf_read_offset += copy_size;
        return copy_size;
    }

    av_log(NULL, AV_LOG_TRACE, "chenwq: try to read ts data from io buffer, bufsize=%d\n", buf_size);
    struct segment *cseg = current_segment(v);
    ret = read_from_url(v, cseg, buf, buf_size, READ_NORMAL);

    if (ret > 0) {
        if (just_opened && v->is_id3_timestamped != 0) {
            /* Intercept ID3 tags here, elementary audio streams are required
             * to convey timestamps using them in the beginning of each segment. */
            intercept_id3(v, buf, buf_size, &ret);
        }
		
		if (c->app_ctx && (!c->app_ctx->pss->complete)){
			if(c->parallel_open){
				if((!c->uss_default->complete) && v->_type == AVMEDIA_TYPE_VIDEO ){
					c->app_ctx->lss->download_ts_data += ret;
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_data = %d", c->app_ctx->lss->download_ts_data);					
				}
				else if((!c->uss_alt->complete) && v->_type == AVMEDIA_TYPE_AUDIO){
					c->app_ctx->lss->download_ts_data_audio += ret;
					startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_data_audio = %d", c->app_ctx->lss->download_ts_data_audio);
				}
			}
			else{
				c->app_ctx->lss->download_ts_data += ret;
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_data = %d", c->app_ctx->lss->download_ts_data);
			}
			
		}
        
        bitrate_add_download_data(c->app_ctx, ret);
        return ret;
    }
    
    
    if( strrchr(current_segment(v)->url, '/') != NULL )
    {
      av_log(NULL, AV_LOG_DEBUG, "download ts escape time=%lld, file=%s\n", av_gettime()/1000-download_begin_time,(strrchr(current_segment(v)->url, '/')+1));
    }
    
  
    if (c->http_persistent && cseg->key_type == KEY_NONE && av_strstart(cseg->url, "http", NULL)) {
        v->input_read_done = 1;
    } else {
        ff_format_io_close(v->parent, &v->input);
    }
    
    v->cur_seq_no++;
    c->cur_seq_no = v->cur_seq_no;
	
	if(c->app_ctx && (!c->app_ctx->pss->complete)){
		if(c->parallel_open){
			if (c->uss_default->complete && c->uss_alt->complete){
				c->app_ctx->pss->complete=1;
			}
			
			if((!c->uss_default->complete) && v->_type == AVMEDIA_TYPE_VIDEO ){
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_finish = %lld",av_gettime()/1000);
				c->uss_default->complete = 1;
			}
			else if((!c->uss_alt->complete) && v->_type == AVMEDIA_TYPE_AUDIO){
				startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_finish_audio = %lld",av_gettime()/1000);
				c->uss_alt->complete = 1;
			}
			
			if (c->uss_default->complete && c->uss_alt->complete){
				c->app_ctx->pss->complete=1;
			}			
		}
		else{
			startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN, "download_ts1_finish = %lld",av_gettime()/1000);
			c->uss_default->complete = 1;
			c->app_ctx->pss->complete=1;
		}
		
	}
	
    bitrate_finish_calculate(c->app_ctx);
	//////////////////////
	// data loading is finished. Looking for stream for current bandwidth and if it's differ from current, switch to new stream
    char* better_url = find_better_bitrate(c->app_ctx);
    if ( better_url!=NULL && !is_current_bitrate_url(c->app_ctx, v->url) && is_variant_url(c, v->url))
    {
        av_log(NULL, AV_LOG_DEBUG, "update bitrate url, cur=%s, better=%s\n", v->url, better_url);
        strcpy(v->url, better_url);
        is_bitrate_updated = 1;
    }
    goto restart;
}


static int playlist_in_multiple_variants(HLSContext *c, struct playlist *pls)
{
    int variant_count = 0;
    int i, j;

    for (i = 0; i < c->n_variants && variant_count < 2; i++) {
        struct variant *v = c->variants[i];

        for (j = 0; j < v->n_playlists; j++) {
            if (v->playlists[j] == pls) {
                variant_count++;
                break;
            }
        }
    }

    return variant_count >= 2;
}

static void add_renditions_to_variant(HLSContext *c, struct variant *var,
                                      enum AVMediaType type, const char *group_id)
{
    int i;

    for (i = 0; i < c->n_renditions; i++) {
        struct rendition *rend = c->renditions[i];

        if (rend->type == type && !strcmp(rend->group_id, group_id)) {

            if (rend->playlist)
                /* rendition is an external playlist
                 * => add the playlist to the variant */
                dynarray_add(&var->playlists, &var->n_playlists, rend->playlist);
            else
                /* rendition is part of the variant main Media Playlist
                 * => add the rendition to the main Media Playlist */
                dynarray_add(&var->playlists[0]->renditions,
                             &var->playlists[0]->n_renditions,
                             rend);
        }
    }
}

static void add_metadata_from_renditions(AVFormatContext *s, struct playlist *pls,
                                         enum AVMediaType type)
{
    int rend_idx = 0;
    int i;

    for (i = 0; i < pls->ctx->nb_streams; i++) {
        AVStream *st = s->streams[pls->stream_offset + i];

        if (st->codecpar->codec_type != type)
            continue;

        for (; rend_idx < pls->n_renditions; rend_idx++) {
            struct rendition *rend = pls->renditions[rend_idx];

            if (rend->type != type)
                continue;

            if (rend->language[0])
                av_dict_set(&st->metadata, "language", rend->language, 0);
            if (rend->name[0])
                av_dict_set(&st->metadata, "comment", rend->name, 0);

            st->disposition |= rend->disposition;
        }
        if (rend_idx >=pls->n_renditions)
            break;
    }
}

/* if timestamp was in valid range: returns 1 and sets seq_no
 * if not: returns 0 and sets seq_no to closest segment */
static int find_timestamp_in_playlist(HLSContext *c, struct playlist *pls,
                                      int64_t timestamp, int *seq_no)
{
    int i;
    int64_t pos = c->first_timestamp == AV_NOPTS_VALUE ?
                  0 : c->first_timestamp;

    if (timestamp < pos) {
        *seq_no = pls->start_seq_no;
        return 0;
    }

    for (i = 0; i < pls->n_segments; i++) {
        int64_t diff = pos + pls->segments[i]->duration - timestamp;
        if (diff > 0) {
            *seq_no = pls->start_seq_no + i;
            return 1;
        }
        pos += pls->segments[i]->duration;
    }

    *seq_no = pls->start_seq_no + pls->n_segments - 1;

    return 0;
}

static int select_cur_seq_no(HLSContext *c, struct playlist *pls)
{
    int seq_no;

    if (!pls->finished && !c->first_packet &&
        av_gettime_relative() - pls->last_load_time >= default_reload_interval(pls))
        /* reload the playlist since it was suspended */
        parse_playlist(c, pls->url, pls, NULL);

    /* If playback is already in progress (we are just selecting a new
     * playlist) and this is a complete file, find the matching segment
     * by counting durations. */
    if (pls->finished && c->cur_timestamp != AV_NOPTS_VALUE) {
        find_timestamp_in_playlist(c, pls, c->cur_timestamp, &seq_no);
        return seq_no;
    }

    if (!pls->finished) {
        if (!c->first_packet && /* we are doing a segment selection during playback */
            c->cur_seq_no >= pls->start_seq_no &&
            c->cur_seq_no < pls->start_seq_no + pls->n_segments)
            /* While spec 3.4.3 says that we cannot assume anything about the
             * content at the same sequence number on different playlists,
             * in practice this seems to work and doing it otherwise would
             * require us to download a segment to inspect its timestamps. */
            return c->cur_seq_no;

        /* If this is a live stream, start live_start_index segments from the
         * start or end */
        if (c->live_start_index < 0){
            int seq = pls->start_seq_no + FFMAX(pls->n_segments + c->live_start_index, 0);
            av_log(NULL, AV_LOG_DEBUG,"hls start segment %d, startindex %d\n", seq, c->live_start_index);
            return pls->start_seq_no + FFMAX(pls->n_segments + c->live_start_index, 0);
        }
        else
            return pls->start_seq_no + FFMIN(c->live_start_index, pls->n_segments - 1);
    }

    /* Otherwise just start on the first segment. */
    return pls->start_seq_no;
}

static int save_avio_options(AVFormatContext *s)
{
    HLSContext *c = s->priv_data;
    static const char *opts[] = {
        "headers", "http_proxy", "user_agent", "user-agent", "cookies", "timeout", "ijkapplication", "tcp_open_timeout", "reconnect_count", NULL };
    const char **opt = opts;
    uint8_t *buf;
    int ret = 0;

    while (*opt) {
        if (av_opt_get(s->pb, *opt, AV_OPT_SEARCH_CHILDREN | AV_OPT_ALLOW_NULL, &buf) >= 0) {
            ret = av_dict_set(&c->avio_opts, *opt, buf,
                              AV_DICT_DONT_STRDUP_VAL);
            if (ret < 0)
                return ret;
        }
        opt++;
    }

    return ret;
}

static int nested_io_open(AVFormatContext *s, AVIOContext **pb, const char *url,
                          int flags, AVDictionary **opts)
{
    av_log(s, AV_LOG_ERROR,
           "A HLS playlist item '%s' referred to an external file '%s'. "
           "Opening this file was forbidden for security reasons\n",
           s->filename, url);
    return AVERROR(EPERM);
}

static void *open_m3u8_threadproc(void* paramlist){
    long* pParamList = (long*)paramlist;
    struct playlist* pls = (struct playlist*)pParamList[0];
    struct HLSContext* c = (struct HLSContext*)pParamList[1];
    
    if (c->parallel_open && (!c->uss_default->m3u8_complete) && pls->_type == AVMEDIA_TYPE_VIDEO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"download_m3u8_begin = %lld", av_gettime() / 1000);
    }
    
    if (c->parallel_open && (!c->uss_alt->m3u8_complete) && pls->_type == AVMEDIA_TYPE_AUDIO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"download_m3u8_begin_audio = %lld", av_gettime() / 1000);
    }
    
    int ret = parse_playlist(c, pls->url, pls, NULL);
    
    
    if (ret < 0) {
		URLStartStatus* pUSS = c->uss_default;
		if (c->parallel_open && pls->_type == AVMEDIA_TYPE_AUDIO){
			pUSS = c->uss_alt;
		}
		add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_ERROR_CODE,ret);
		add_flow_log(c->app_ctx,pUSS,FL_DOWNLOAD_FINISH,av_gettime()/1000);
		
		pthread_exit((void *)ret);
    }
	
	if (c->parallel_open && (!c->uss_default->m3u8_complete) && pls->_type == AVMEDIA_TYPE_VIDEO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"download_m3u8_finish = %lld", av_gettime() / 1000);
		c->uss_default->m3u8_complete = 1;
    }
    
    if (c->app_ctx && (!c->uss_alt->m3u8_complete) && pls->_type == AVMEDIA_TYPE_AUDIO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"download_m3u8_finish_audio = %lld", av_gettime() / 1000);     
		c->uss_alt->m3u8_complete = 1;
    }

	pthread_exit((void *)ret);
}

static void *open_demuxer_threadproc(void* paramlist){
    int ret = 0, j;
    
    long* pParamList = (long*)paramlist;
    struct playlist* pls = (struct playlist*)pParamList[0];
    struct HLSContext* c = (struct HLSContext*)pParamList[1];
    struct AVFormatContext *s = (struct AVFormatContext*)pParamList[2];
    int i = (int)pParamList[3];
    
    AVInputFormat *in_fmt = NULL;
    
    if (!(pls->ctx = avformat_alloc_context())) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    
    if (pls->n_segments == 0)
        return ((void *)0);
    
    pls->index  = i;
    pls->needed = 1;
    pls->parent = s; //m3u8 AvforamtContext
    pls->cur_seq_no = select_cur_seq_no(c, pls);
    
    pls->read_buffer = av_malloc(INITIAL_BUFFER_SIZE);
    if (!pls->read_buffer){
        ret = AVERROR(ENOMEM);
        avformat_free_context(pls->ctx);
        pls->ctx = NULL;
        goto fail;
    }
    ffio_init_context(&pls->pb, pls->read_buffer, INITIAL_BUFFER_SIZE, 0, pls,
                      read_data, NULL, NULL);
    pls->pb.seekable = 0;
	
	AVDictionary *opts_crypt = NULL;
	if (pls->segments[0]->key) {
		pls->pb.customkey_alg = av_strdup(pls->segments[0]->key);
		pls->pb.customkey_src = av_strdup(pls->segments[0]->key_src);
		av_dict_set(&opts_crypt, CUSTOMKEY_ALG, pls->pb.customkey_alg, 0);
		av_dict_set(&opts_crypt, CUSTOMKEY_SRC, pls->pb.customkey_src, 0);
	}
	
	int check_key_ret = 0;
	if (pls->pb.customkey_alg&&pls->pb.customkey_src) {
		AVCustomAlgOpt opt;
		memset(&opt, 0, sizeof(opt));
		check_key_ret = customkey_get_alg(&opt, pls->pb.customkey_alg, pls->pb.customkey_src);
	}
	
    ret = av_probe_input_buffer(&pls->pb, &in_fmt, pls->segments[0]->url,
                                NULL, 0, 0);
    if (ret < 0) {
        /* Free the ctx - it isn't initialized properly at this point,
         * so avformat_close_input shouldn't be called. If
         * avformat_open_input fails below, it frees and zeros the
         * context, so it doesn't need any special treatment like this. */
        //zy add
        // TODO : loading first segment error code! add by tao
        //startimes_error_log(NULL, STAR_LOG_MAIN, "error_code = %d download first ts failed",ret);
        /////////////////////////
        av_log(s, AV_LOG_ERROR, "Error when loading first segment '%s'\n", pls->segments[0]->url);
        avformat_free_context(pls->ctx);
        pls->ctx = NULL;
		
		if (check_key_ret!=0) {
			ret = AVERROR_FAIL_UNSUPPORT_CRYPT_ALG;
			if(c->parallel_open){
				if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
					startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_PARSE_STREAM_FAIL );
					startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", check_key_ret );
				}
				else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
					startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", ERROR_KEY_PARSE_STREAM_FAIL );
					startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", check_key_ret );
				}
			}
			else{
				startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_PARSE_STREAM_FAIL );
				startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", check_key_ret );
			}
		}
        goto fail;
    }
    pls->ctx->pb       = &pls->pb;
    pls->ctx->io_open  = nested_io_open;
    
    
    if ((ret = ff_copy_whiteblacklists(pls->ctx, s)) < 0)
        goto fail;
    
    ret = avformat_open_input(&pls->ctx, pls->segments[0]->url, in_fmt, &opts_crypt);
	av_freep(&opts_crypt);
    if (ret < 0)
        goto fail;
    
    if (pls->id3_deferred_extra && pls->ctx->nb_streams == 1) {
        ff_id3v2_parse_apic(pls->ctx, &pls->id3_deferred_extra);
        avformat_queue_attached_pictures(pls->ctx);
        ff_id3v2_free_extra_meta(&pls->id3_deferred_extra);
        pls->id3_deferred_extra = NULL;
    }
    pls->ctx->ctx_flags &= ~AVFMTCTX_NOHEADER;
    
    //make find stream info of fmp4 fast
    if (strstr(pls->segments[0]->url, ".m4s")) {
        pls->ctx->max_analyze_duration = AV_TIME_BASE;
    }
    
    if (c->app_ctx && pls->_type == AVMEDIA_TYPE_VIDEO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"find_stream_info_begin = %lld", av_gettime() / 1000);
        c->app_ctx->lss->find_stream_info=0;
    }
    
    if (c->app_ctx && pls->_type == AVMEDIA_TYPE_AUDIO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"find_stream_info_begin_audio = %lld", av_gettime() / 1000);
        c->app_ctx->lss->find_stream_info=0;
    }

    ret = avformat_find_stream_info(pls->ctx, NULL);
    
    if (c->app_ctx && pls->_type == AVMEDIA_TYPE_VIDEO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"find_stream_info_finish = %lld", av_gettime() / 1000);
    }
    
    if (c->app_ctx && pls->_type == AVMEDIA_TYPE_AUDIO ) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_MAIN,"find_stream_info_finish_audio = %lld", av_gettime() / 1000);
    }
    
    if (ret < 0)
        goto fail;
    
	pthread_exit((void *)0);
fail:
	pthread_exit((void *)ret);
}

static int hls_read_header(AVFormatContext *s)
{
    void *u = (s->flags & AVFMT_FLAG_CUSTOM_IO) ? NULL : s->pb;
    HLSContext *c = s->priv_data;
    int ret = 0, i, j, stream_offset = 0;
	
	av_log(NULL, AV_LOG_DEBUG, "player_run:ffmpeg:firebase des_regular_rate:%d,des_retry_interval:%d\n", 
		   c->des_regular_rate, c->des_retry_interval);
    
    if(s->app_ctx_intptr)
    {
        c->app_ctx = (AVApplicationContext *)(intptr_t)s->app_ctx_intptr;
		if(c->app_ctx){
			c->uss_default = c->app_ctx->uss_default;
			c->uss_alt = c->app_ctx->uss_alt;
            c->uss_default_segment = c->app_ctx->uss_default_segment;
            c->uss_alt_segment = c->app_ctx->uss_alt_segment;
		}
		
    }

    c->ctx                = s;
    c->interrupt_callback = &s->interrupt_callback;
    c->strict_std_compliance = s->strict_std_compliance;

    c->first_packet = 1;
    c->first_timestamp = AV_NOPTS_VALUE;
    c->cur_timestamp = AV_NOPTS_VALUE;

    if (u) {
        // get the previous user agent & set back to null if string size is zero
        update_options(&c->user_agent, "user-agent", u);

        // get the previous cookies & set back to null if string size is zero
        update_options(&c->cookies, "cookies", u);

        // get the previous headers & set back to null if string size is zero
        update_options(&c->headers, "headers", u);

        // get the previous http proxt & set back to null if string size is zero
        update_options(&c->http_proxy, "http_proxy", u);
    }

    if ((ret = parse_playlist(c, s->filename, NULL, s->pb)) < 0)
        goto fail;

    if ((ret = save_avio_options(s)) < 0)
        goto fail;

    /* Some HLS servers don't like being sent the range header */
    av_dict_set(&c->avio_opts, "seekable", "0", 0);
    
    if(c->rw_timeout > 0 && !av_dict_get(c->avio_opts, "timeout", NULL, 0))
        av_dict_set_int(&c->avio_opts, "timeout", c->rw_timeout, 0);
    
    if(c->open_timeout > 0 && !av_dict_get(c->avio_opts, "tcp_open_timeout", NULL, 0))
        av_dict_set_int(&c->avio_opts, "tcp_open_timeout", c->open_timeout, 0);
    
    if(c->reconnect_count > 0 && !av_dict_get(c->avio_opts, "reconnect_count", NULL, 0))
        av_dict_set_int(&c->avio_opts, "reconnect_count", c->reconnect_count, 0);

    if (c->n_variants == 0) {
        av_log(NULL, AV_LOG_WARNING, "Empty playlist\n");
        ret = AVERROR_EOF;
        goto fail;
    }
    /* If the playlist only contained playlists (Master Playlist),
     * parse each individual playlist. */
    URLContext* url_ctx = ffio_geturlcontext(s->pb);
	c->parallel_open = 0;
	if( url_ctx && url_ctx->args.info != NULL && c->n_playlists == 2 ){
		struct playlist *pls0 = c->playlists[0];
		struct playlist *pls1 = c->playlists[1];
		
		//There should be one audio and one video
		if((pls0->_type == AVMEDIA_TYPE_VIDEO && pls1->_type == AVMEDIA_TYPE_AUDIO) || 
				(pls0->_type == AVMEDIA_TYPE_AUDIO && pls1->_type == AVMEDIA_TYPE_VIDEO)){
			c->parallel_open = 1;
		}
	}
	
    if( c->parallel_open)
    {
        //parallel open video and audio demuxer
        av_log(NULL, AV_LOG_INFO, "parallel open hls m3u8 in threads\n");
		
        pthread_t threads_m3u8[2];
        long paramlist_m3u8[2][2]={0};
        void *tret_m3u8[2];
		int audio_index = -1;
		int video_index = -1;
		
        if (c->n_playlists > 1 || c->playlists[0]->n_segments == 0) {
            for (i = 0; i < c->n_playlists; i++) {
                struct playlist *pls = c->playlists[i];
				if (pls->_type == AVMEDIA_TYPE_VIDEO){
					video_index = i;
				}
				else if (pls->_type == AVMEDIA_TYPE_AUDIO){
					audio_index = i;
				}
				else{
					 av_log(NULL, AV_LOG_ERROR, "parallel open hls error type %d\n",pls->_type);
				}
				
				
                paramlist_m3u8[i][0] = (long)pls;
                paramlist_m3u8[i][1] = (long)c;
                pthread_create(&threads_m3u8[i], NULL, open_m3u8_threadproc, paramlist_m3u8[i]);
            }
        }
        
        for (int i=0; i<2; i++) {
            pthread_join(threads_m3u8[i], &tret_m3u8[i]);
        }
		
		//return video error first
		if( video_index >= 0 && (int)tret_m3u8[video_index] < 0)
		{
			ret = (int)tret_m3u8[video_index];
			goto fail;
		}
		else if(audio_index >= 0 && (int)tret_m3u8[audio_index] < 0){
			ret = (int)tret_m3u8[audio_index];
			goto fail;
		}
		else{
			c->app_ctx->pss->m3u8_complete = 1;
		}
		
    }
    else
    {
        //serial open video and audio demuxer
        av_log(NULL, AV_LOG_INFO, "serial open hls m3u8\n");
        if (c->n_playlists > 1 || c->playlists[0]->n_segments == 0) {
            for (i = 0; i < c->n_playlists; i++) {
                struct playlist *pls = c->playlists[i];
                if ((ret = parse_playlist(c, pls->url, pls, NULL)) < 0)
                    goto fail;
            }
        }
    }
    
    if (c->variants[0]->playlists[0]->n_segments == 0) {
        av_log(NULL, AV_LOG_WARNING, "Empty playlist\n");
        ret = AVERROR_EOF;
        goto fail;
    }

    /* If this isn't a live stream, calculate the total duration of the
     * stream. */
    if (c->variants[0]->playlists[0]->finished) {
        int64_t duration = 0;
		
		if (c->variants[0]->playlists[0]->m3u8_optimize && c->variants[0]->playlists[0]->m3u8_optimize->optimize_valid)
		{
			duration = c->variants[0]->playlists[0]->m3u8_optimize->segment_total_duration * AV_TIME_BASE;
		}
		else
		{
			for (i = 0; i < c->variants[0]->playlists[0]->n_segments; i++)
			{
				duration += c->variants[0]->playlists[0]->segments[i]->duration;
			}
		}
		
        s->duration = duration;
    }
    
    if( c->parallel_open) {
        for (i = 0; i < c->n_playlists; i++) {
            struct playlist *pls = c->playlists[i];
            if (c->app_ctx && (!c->app_ctx->pss->complete) && pls->_type == AVMEDIA_TYPE_AUDIO  ) {
                startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "m3u8_have_finish_audio = %d", pls->finished);
                startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "m3u8_have_segcnt_audio = %d", pls->n_segments);
                av_log(NULL, AV_LOG_DEBUG, "m3u8 read result: finish=%d, seg_count=%d\n", pls->finished, pls->n_segments);
            }
            
            if (c->app_ctx && (!c->app_ctx->pss->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ) {
                startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "m3u8_have_finish = %d", pls->finished);
                startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "m3u8_have_segcnt = %d", pls->n_segments);
                av_log(NULL, AV_LOG_DEBUG, "m3u8 read result: finish=%d, seg_count=%d\n", pls->finished, pls->n_segments);
            }
        }
    }
    else if (c->app_ctx && (!c->app_ctx->pss->complete)) {
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "m3u8_have_finish = %d", c->variants[0]->playlists[0]->finished);
        startimes_start_log(c->app_ctx, STAR_TIME_LOG_TCP, "m3u8_have_segcnt = %d", c->variants[0]->playlists[0]->n_segments);
        av_log(NULL, AV_LOG_DEBUG, "m3u8 read result: finish=%d, seg_count=%d\n", c->variants[0]->playlists[0]->finished, c->variants[0]->playlists[0]->n_segments);
    }
    
    /* Associate renditions with variants */
    for (i = 0; i < c->n_variants; i++) {
        struct variant *var = c->variants[i];

        if (var->audio_group[0])
            add_renditions_to_variant(c, var, AVMEDIA_TYPE_AUDIO, var->audio_group);
        if (var->video_group[0])
            add_renditions_to_variant(c, var, AVMEDIA_TYPE_VIDEO, var->video_group);
        if (var->subtitles_group[0])
            add_renditions_to_variant(c, var, AVMEDIA_TYPE_SUBTITLE, var->subtitles_group);
    }

    /* Open the demuxer for each playlist */
//    //In order to star the play quickly, we only analyze the first ts segment of the first playlist.
//    int n_playlists = 1;
//    if( global_adaptive_bitrate_switching && c->n_variants > 1 )
//    {
//    	n_playlists = 1;
//    }
//    else
//    {
//    	n_playlists = c->n_playlists;
//    }

    
    if( c->parallel_open)
    {
        //parallel open video and audio demuxer
        av_log(NULL, AV_LOG_INFO, "parallel open hls video and audio demuxer in threads\n");
        pthread_t threads[2];
        long paramlist[2][4]={0};
        void *tret[2];
		int audio_index = -1;
		int video_index = -1;
        
        for (i = 0; i < c->n_playlists; i++) {
            struct playlist *pls = c->playlists[i];
			if (pls->_type == AVMEDIA_TYPE_VIDEO){
				video_index = i;
			}
			else if (pls->_type == AVMEDIA_TYPE_AUDIO){
				audio_index = i;
			}
			else{
				av_log(NULL, AV_LOG_ERROR, "parallel open hls error type %d\n",pls->_type);
			}
			
            paramlist[i][0] = (long)pls;
            paramlist[i][1] = (long)c;
            paramlist[i][2] = (long)s;
            paramlist[i][3] = (long)i;
            pthread_create(&threads[i], NULL, open_demuxer_threadproc, paramlist[i]);
        }
        
        for (int i=0; i<2; i++) {
            pthread_join(threads[i], &tret[i]);
        }
		
		//return video error first
		if( video_index >= 0 && (int)tret[video_index] < 0)
		{
			ret = (int)tret[video_index];
			goto fail;
		}
		else if(audio_index >= 0 && (int)tret[audio_index] < 0){
			ret = (int)tret[audio_index];
			goto fail;
		}
        
        
        for (i = 0; i < c->n_playlists; i++) {
			 struct playlist *pls = c->playlists[i];
			
			if (pls->is_id3_timestamped == -1)
				av_log(s, AV_LOG_WARNING, "No expected HTTP requests have been made\n");
			
			/* Create new AVStreams for each stream in this playlist,avformat_new_stream is not thread safe */
			for (j = 0; j < pls->ctx->nb_streams; j++) {
				AVStream *st = avformat_new_stream(s, NULL);
				AVStream *ist = pls->ctx->streams[j];
				if (!st) {
					ret = AVERROR(ENOMEM);
					goto fail;
				}
				st->id = i;
				
				avcodec_parameters_copy(st->codecpar, pls->ctx->streams[j]->codecpar);
				
				//add chenwq
				av_dict_copy(&st->metadata,pls->ctx->streams[j]->metadata,0);
				
				if (pls->is_id3_timestamped) /* custom timestamps via id3 */
					avpriv_set_pts_info(st, 33, 1, MPEG_TIME_BASE);
				else
					avpriv_set_pts_info(st, ist->pts_wrap_bits, ist->time_base.num, ist->time_base.den);
			}
			
			add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_AUDIO);
			add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_VIDEO);
			add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_SUBTITLE);
			
            pls->stream_offset = stream_offset;
            stream_offset += pls->ctx->nb_streams;
        }
      
    }
    else
    {
        //serial open video and audio demuxer
        av_log(NULL, AV_LOG_INFO, "serial open hls video and audio demuxer\n");
        for (i = 0; i < c->n_playlists; i++) {
            struct playlist *pls = c->playlists[i];
            AVInputFormat *in_fmt = NULL;

            if (!(pls->ctx = avformat_alloc_context())) {
                ret = AVERROR(ENOMEM);
                goto fail;
            }

            if (pls->n_segments == 0)
                continue;
            
            pls->index  = i;
            pls->needed = 1;
            pls->parent = s; //m3u8 AvforamtContext
            pls->cur_seq_no = select_cur_seq_no(c, pls);

            pls->read_buffer = av_malloc(INITIAL_BUFFER_SIZE);
            if (!pls->read_buffer){
                ret = AVERROR(ENOMEM);
                avformat_free_context(pls->ctx);
                pls->ctx = NULL;
                goto fail;
            }
            ffio_init_context(&pls->pb, pls->read_buffer, INITIAL_BUFFER_SIZE, 0, pls, read_data, NULL, NULL);
            pls->pb.seekable = 0;
            
            AVDictionary *opts_crypt = NULL;
            if (pls->segments[0]->key) {
                pls->pb.customkey_alg = av_strdup(pls->segments[0]->key);
                pls->pb.customkey_src = av_strdup(pls->segments[0]->key_src);
                av_dict_set(&opts_crypt, CUSTOMKEY_ALG, pls->pb.customkey_alg, 0);
                av_dict_set(&opts_crypt, CUSTOMKEY_SRC, pls->pb.customkey_src, 0);
            }
            
            int check_key_ret = 0;
            if (pls->pb.customkey_alg&&pls->pb.customkey_src) {
                AVCustomAlgOpt opt;
                memset(&opt, 0, sizeof(opt));
                check_key_ret = customkey_get_alg(&opt, pls->pb.customkey_alg, pls->pb.customkey_src);
            }
            
            ret = av_probe_input_buffer(&pls->pb, &in_fmt, pls->segments[0]->url, NULL, 0, 0);
            if (ret < 0) {
                /* Free the ctx - it isn't initialized properly at this point,
                 * so avformat_close_input shouldn't be called. If
                 * avformat_open_input fails below, it frees and zeros the
                 * context, so it doesn't need any special treatment like this. */
                //zy add
                // TODO : loading first segment error code! add by tao
                //startimes_error_log(NULL, STAR_LOG_MAIN, "error_code = %d download first ts failed",ret);
                /////////////////////////
                av_log(s, AV_LOG_ERROR, "Error when loading first segment '%s'\n", pls->segments[0]->url);
                avformat_free_context(pls->ctx);
                pls->ctx = NULL;
                if (check_key_ret!=0) {
                    ret = AVERROR_FAIL_UNSUPPORT_CRYPT_ALG;
					if(c->parallel_open){
						if((!c->uss_default->complete) && pls->_type == AVMEDIA_TYPE_VIDEO ){
							startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_PARSE_STREAM_FAIL );
							startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", check_key_ret );
						}
						else if((!c->uss_alt->complete) && pls->_type == AVMEDIA_TYPE_AUDIO){
							startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", ERROR_KEY_PARSE_STREAM_FAIL );
							startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", check_key_ret );
						}
					}
					else{
						startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_PARSE_STREAM_FAIL );
						startimes_error_log(c->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", check_key_ret );
					}
					
                }
                goto fail;
            }
            pls->ctx->pb       = &pls->pb;
            pls->ctx->io_open  = nested_io_open;
            pls->stream_offset = stream_offset;

            if ((ret = ff_copy_whiteblacklists(pls->ctx, s)) < 0)
                goto fail;

            ret = avformat_open_input(&pls->ctx, pls->segments[0]->url, in_fmt, &opts_crypt);
            av_freep(&opts_crypt);
            if (ret < 0)
                goto fail;

            if (pls->id3_deferred_extra && pls->ctx->nb_streams == 1) {
                ff_id3v2_parse_apic(pls->ctx, &pls->id3_deferred_extra);
                avformat_queue_attached_pictures(pls->ctx);
                ff_id3v2_free_extra_meta(&pls->id3_deferred_extra);
                pls->id3_deferred_extra = NULL;
            }
            pls->ctx->ctx_flags &= ~AVFMTCTX_NOHEADER;
            
            //make find stream info of fmp4 fast
            if (strstr(pls->segments[0]->url, ".m4s")) {
                pls->ctx->max_analyze_duration = AV_TIME_BASE;
            }
            
            ret = avformat_find_stream_info(pls->ctx, NULL);
            if (ret < 0)
                goto fail;
            if (pls->is_id3_timestamped == -1)
                av_log(s, AV_LOG_WARNING, "No expected HTTP requests have been made\n");

            /* Create new AVStreams for each stream in this playlist */
            for (j = 0; j < pls->ctx->nb_streams; j++) {
                AVStream *st = avformat_new_stream(s, NULL);
                AVStream *ist = pls->ctx->streams[j];
                if (!st) {
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
                st->id = i;

                avcodec_parameters_copy(st->codecpar, pls->ctx->streams[j]->codecpar);
            
            //add chenwq
                av_dict_copy(&st->metadata,pls->ctx->streams[j]->metadata,0);

                if (pls->is_id3_timestamped) /* custom timestamps via id3 */
                    avpriv_set_pts_info(st, 33, 1, MPEG_TIME_BASE);
                else
                    avpriv_set_pts_info(st, ist->pts_wrap_bits, ist->time_base.num, ist->time_base.den);
            }

            add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_AUDIO);
            add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_VIDEO);
            add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_SUBTITLE);

            stream_offset += pls->ctx->nb_streams;
        }
    }

    /* Create a program for each variant */
    //In order to star the play quickly, we only create the program for the first of variant.
//    int n_variants = 1;
//    if( global_adaptive_bitrate_switching && c->n_variants > 1 )
//    {
//    	n_variants = 1;
//    }
//    else
//    {
//    	n_variants = c->n_variants;
//    }

    for (i = 0; i < c->n_variants; i++) {
        struct variant *v = c->variants[i];
        AVProgram *program;

        program = av_new_program(s, i);
        if (!program)
            goto fail;
        av_dict_set_int(&program->metadata, "variant_bitrate", v->bandwidth, 0);

        for (j = 0; j < v->n_playlists; j++) {
            struct playlist *pls = v->playlists[j];
            int is_shared = playlist_in_multiple_variants(c, pls);
            int k;

            for (k = 0; k < pls->ctx->nb_streams; k++) {
                struct AVStream *st = s->streams[pls->stream_offset + k];

                av_program_add_stream_index(s, i, pls->stream_offset + k);

                /* Set variant_bitrate for streams unique to this variant */
                if (!is_shared && v->bandwidth)
                    av_dict_set_int(&st->metadata, "variant_bitrate", v->bandwidth, 0);
            }
        }
    }
    return 0;
fail:
    free_playlist_list(c);
    free_variant_list(c);
    free_rendition_list(c);
    return ret;
}

static int recheck_discard_flags(AVFormatContext *s, int first)
{
    HLSContext *c = s->priv_data;
    int i, changed = 0;

    /* Check if any new streams are needed */
    for (i = 0; i < c->n_playlists; i++)
        c->playlists[i]->cur_needed = 0;

    for (i = 0; i < s->nb_streams; i++) {
        AVStream *st = s->streams[i];
        struct playlist *pls = c->playlists[s->streams[i]->id];
        if (st->discard < AVDISCARD_ALL)
            pls->cur_needed = 1;
    }
    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        if (pls->cur_needed && !pls->needed) {
            pls->needed = 1;
            changed = 1;
            pls->cur_seq_no = select_cur_seq_no(c, pls);
            pls->pb.eof_reached = 0;
            if (c->cur_timestamp != AV_NOPTS_VALUE) {
                /* catch up */
                pls->seek_timestamp = c->cur_timestamp;
                pls->seek_flags = AVSEEK_FLAG_ANY;
                pls->seek_stream_index = -1;
            }
            av_log(s, AV_LOG_INFO, "Now receiving playlist %d, segment %d\n", i, pls->cur_seq_no);
        } else if (first && !pls->cur_needed && pls->needed) {
            if (pls->input){
                ff_format_io_close(pls->parent, &pls->input);

            }
            pls->input_read_done = 0;
            pls->needed = 0;
            changed = 1;
            av_log(s, AV_LOG_INFO, "No longer receiving playlist %d\n", i);
        }
    }
    return changed;
}

static void fill_timing_for_id3_timestamped_stream(struct playlist *pls)
{
    if (pls->id3_offset >= 0) {
        pls->pkt.dts = pls->id3_mpegts_timestamp +
                                 av_rescale_q(pls->id3_offset,
                                              pls->ctx->streams[pls->pkt.stream_index]->time_base,
                                              MPEG_TIME_BASE_Q);
        if (pls->pkt.duration)
            pls->id3_offset += pls->pkt.duration;
        else
            pls->id3_offset = -1;
    } else {
        /* there have been packets with unknown duration
         * since the last id3 tag, should not normally happen */
        pls->pkt.dts = AV_NOPTS_VALUE;
    }

    if (pls->pkt.duration)
        pls->pkt.duration = av_rescale_q(pls->pkt.duration,
                                         pls->ctx->streams[pls->pkt.stream_index]->time_base,
                                         MPEG_TIME_BASE_Q);

    pls->pkt.pts = AV_NOPTS_VALUE;
}

static AVRational get_timebase(struct playlist *pls)
{
    if (pls->is_id3_timestamped)
        return MPEG_TIME_BASE_Q;

    return pls->ctx->streams[pls->pkt.stream_index]->time_base;
}

static int compare_ts_with_wrapdetect(int64_t ts_a, struct playlist *pls_a,
                                      int64_t ts_b, struct playlist *pls_b)
{
    int64_t scaled_ts_a = av_rescale_q(ts_a, get_timebase(pls_a), MPEG_TIME_BASE_Q);
    int64_t scaled_ts_b = av_rescale_q(ts_b, get_timebase(pls_b), MPEG_TIME_BASE_Q);

    return av_compare_mod(scaled_ts_a, scaled_ts_b, 1LL << 33);
}

static int hls_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    HLSContext *c = s->priv_data;
    int ret, i, minplaylist = -1;

    recheck_discard_flags(s, c->first_packet);
    c->first_packet = 0;

    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        /* Make sure we've got one buffered packet from each open playlist
         * stream */
        if (pls->needed && !pls->pkt.data) {
            while (1) {
                int64_t ts_diff;
                AVRational tb;
                ret = av_read_frame(pls->ctx, &pls->pkt);
                if (ret < 0) {
                    if (!avio_feof(&pls->pb) && ret != AVERROR_EOF)
                        return ret;
                    reset_packet(&pls->pkt);
                    break;
                } else {
                    /* stream_index check prevents matching picture attachments etc. */
                    if (pls->is_id3_timestamped && pls->pkt.stream_index == 0) {
                        /* audio elementary streams are id3 timestamped */
                        fill_timing_for_id3_timestamped_stream(pls);
                    }

                    if (c->first_timestamp == AV_NOPTS_VALUE &&
                        pls->pkt.dts       != AV_NOPTS_VALUE)
                        c->first_timestamp = av_rescale_q(pls->pkt.dts,
                            get_timebase(pls), AV_TIME_BASE_Q);
                }

                if (pls->seek_timestamp == AV_NOPTS_VALUE)
                    break;

                if (pls->seek_stream_index < 0 ||
                    pls->seek_stream_index == pls->pkt.stream_index) {

                    if (pls->pkt.dts == AV_NOPTS_VALUE) {
                        pls->seek_timestamp = AV_NOPTS_VALUE;
                        break;
                    }

                    tb = get_timebase(pls);
                    ts_diff = av_rescale_rnd(pls->pkt.dts, AV_TIME_BASE,
                                            tb.den, AV_ROUND_DOWN) -
                            pls->seek_timestamp;
                    /* If AVSEEK_FLAG_ANY, keep reading until ts_diff is greater than 0
                     * otherwise return the first keyframe encountered */
                    if (ts_diff >= 0 && (pls->seek_flags & AVSEEK_FLAG_ANY || pls->pkt.flags & AV_PKT_FLAG_KEY)) {
                        pls->seek_timestamp = AV_NOPTS_VALUE;
                        break;
                    }
                }
                
                //fix bug of hls+fmp4 which is audio first fmp4
                if (strstr(pls->ctx->filename, ".m4s")){
                    if (pls->pkt.dts == AV_NOPTS_VALUE) {
                        pls->seek_timestamp = AV_NOPTS_VALUE;
                        break;
                    }
                    tb = get_timebase(pls);
                    ts_diff = av_rescale_rnd(pls->pkt.dts, AV_TIME_BASE, tb.den, AV_ROUND_DOWN)-pls->seek_timestamp;
                    if (ts_diff >= 0 && (pls->seek_flags & AVSEEK_FLAG_ANY || pls->pkt.flags & AV_PKT_FLAG_KEY)) {
                        break;
                    }
                }
                av_packet_unref(&pls->pkt);
                reset_packet(&pls->pkt);
            }
        }
        /* Check if this stream has the packet with the lowest dts */
        if (pls->pkt.data) {
            struct playlist *minpls = minplaylist < 0 ?
                                     NULL : c->playlists[minplaylist];
            if (minplaylist < 0) {
                minplaylist = i;
            } else {
                int64_t dts     =    pls->pkt.dts;
                int64_t mindts  = minpls->pkt.dts;

                if (dts == AV_NOPTS_VALUE ||
                    (mindts != AV_NOPTS_VALUE && compare_ts_with_wrapdetect(dts, pls, mindts, minpls) < 0))
                    minplaylist = i;
            }
        }
    }

    /* If we got a packet, return it */
    if (minplaylist >= 0) {
        struct playlist *pls = c->playlists[minplaylist];
        *pkt = pls->pkt;
        pkt->stream_index += pls->stream_offset;
        reset_packet(&c->playlists[minplaylist]->pkt);

        if (pkt->dts != AV_NOPTS_VALUE)
            c->cur_timestamp = av_rescale_q(pkt->dts,
                                            pls->ctx->streams[pls->pkt.stream_index]->time_base,
                                            AV_TIME_BASE_Q);

        if (c->playlists[minplaylist]->finished) {
            struct playlist *pls = c->playlists[minplaylist];
            int seq_no = pls->cur_seq_no - pls->start_seq_no;
            if (seq_no < pls->n_segments && s->streams[pkt->stream_index]) {
                struct segment *seg = pls->segments[seq_no];
                int64_t pred = av_rescale_q(seg->previous_duration,
                                            AV_TIME_BASE_Q,
                                            s->streams[pkt->stream_index]->time_base);
                int64_t max_ts = av_rescale_q(seg->start_time + seg->duration,
                                              AV_TIME_BASE_Q,
                                              s->streams[pkt->stream_index]->time_base);
                /* EXTINF duration is not precise enough */
                max_ts += 2 * AV_TIME_BASE;
                if (s->start_time > 0) {
                    max_ts += av_rescale_q(s->start_time,
                                           AV_TIME_BASE_Q,
                                           s->streams[pkt->stream_index]->time_base);
                }
                if (pkt->dts != AV_NOPTS_VALUE && pkt->dts + pred < max_ts) pkt->dts += pred;
                if (pkt->pts != AV_NOPTS_VALUE && pkt->pts + pred < max_ts) pkt->pts += pred;
            }
        }
        return 0;
    }
    return AVERROR_EOF;
}

static int hls_close(AVFormatContext *s)
{
	HLSContext *c = s->priv_data;

    bitrate_uninit_varaints(c->app_ctx);
    is_bitrate_updated = 0;

    free_playlist_list(c);
    free_variant_list(c);
    free_rendition_list(c);

    av_dict_free(&c->avio_opts);
	
    ff_format_io_close(c->ctx, &c->playlist_pb);
    ff_format_io_close(c->ctx, &c->playlist_pb_audio);

    return 0;
}

static int hls_read_seek(AVFormatContext *s, int stream_index,
                               int64_t timestamp, int flags)
{
    HLSContext *c = s->priv_data;
    struct playlist *seek_pls = NULL;
    int i, seq_no;
    int64_t first_timestamp, seek_timestamp, duration;

    if ((flags & AVSEEK_FLAG_BYTE) ||
        !(c->variants[0]->playlists[0]->finished || c->variants[0]->playlists[0]->type == PLS_TYPE_EVENT))
        return AVERROR(ENOSYS);

    first_timestamp = c->first_timestamp == AV_NOPTS_VALUE ?
                      0 : c->first_timestamp;

    seek_timestamp = av_rescale_rnd(timestamp, AV_TIME_BASE,
                                    s->streams[stream_index]->time_base.den,
                                    flags & AVSEEK_FLAG_BACKWARD ?
                                    AV_ROUND_DOWN : AV_ROUND_UP);

    duration = s->duration == AV_NOPTS_VALUE ?
               0 : s->duration;

    if (0 < duration && duration < seek_timestamp - first_timestamp)
        return AVERROR(EIO);

    /* find the playlist with the specified stream */
    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        if (stream_index >= pls->stream_offset &&
            stream_index - pls->stream_offset < pls->ctx->nb_streams) {
            seek_pls = pls;
            break;
        }
    }
    /* check if the timestamp is valid for the playlist with the
     * specified stream index */
    if (!seek_pls || !find_timestamp_in_playlist(c, seek_pls, seek_timestamp, &seq_no))
        return AVERROR(EIO);

    /* set segment now so we do not need to search again below */
    seek_pls->cur_seq_no = seq_no;
    seek_pls->seek_stream_index = stream_index - seek_pls->stream_offset;

    for (i = 0; i < c->n_playlists; i++) {
        /* Reset reading */
        struct playlist *pls = c->playlists[i];
        if (pls->input){
            ff_format_io_close(pls->parent, &pls->input);
        }
        pls->input_read_done = 0;
        av_packet_unref(&pls->pkt);
        reset_packet(&pls->pkt);
        pls->pb.eof_reached = 0;
        /* Clear any buffered data */
        pls->pb.buf_end = pls->pb.buf_ptr = pls->pb.buffer;
        /* Reset the pos, to let the mpegts demuxer know we've seeked. */
        pls->pb.pos = 0;
        /* Flush the packet queue of the subdemuxer. */
        if (pls->ctx!=NULL) {
            ff_read_frame_flush(pls->ctx);
        }
        pls->seek_timestamp = seek_timestamp;
        pls->seek_flags = flags;

        if (pls != seek_pls) {
            /* set closest segment seq_no for playlists not handled above */
            find_timestamp_in_playlist(c, pls, seek_timestamp, &pls->cur_seq_no);
            /* seek the playlist to the given position without taking
             * keyframes into account since this playlist does not have the
             * specified stream where we should look for the keyframes */
            pls->seek_stream_index = -1;
            pls->seek_flags |= AVSEEK_FLAG_ANY;
        }
    }

    c->cur_timestamp = seek_timestamp;

    return 0;
}


static int hls_probe(AVProbeData *p)
{
    /* Require #EXTM3U at the start, and either one of the ones below
     * somewhere for a proper match. */
    if (strncmp(p->buf, "#EXTM3U", 7))
        return 0;

    if (strstr(p->buf, "#EXT-X-STREAM-INF:")     ||
        strstr(p->buf, "#EXT-X-TARGETDURATION:") ||
        strstr(p->buf, "#EXT-X-MEDIA-SEQUENCE:"))
        return AVPROBE_SCORE_MAX;
    return 0;
}

#define OFFSET(x) offsetof(HLSContext, x)
#define FLAGS AV_OPT_FLAG_DECODING_PARAM
static const AVOption hls_options[] = {
    {"live_start_index", "segment index to start live streams at (negative values are from the end)",
        OFFSET(live_start_index), AV_OPT_TYPE_INT, {.i64 = -3}, INT_MIN, INT_MAX, FLAGS},
    {"http_persistent", "Use persistent HTTP connections",
        OFFSET(http_persistent), AV_OPT_TYPE_BOOL, {.i64 = 0}, 0, 1, FLAGS },
    {"use_redirect_ip", "Use http redirect ip",
        OFFSET(use_redirect_ip), AV_OPT_TYPE_BOOL, {.i64 = 0}, 0, 1, FLAGS },
	{"use_m3u8_optimize_read", "Use m3u8 read optimize",
        OFFSET(use_m3u8_optimize_read), AV_OPT_TYPE_BOOL, {.i64 = 0}, 0, 1, FLAGS },
	{"des_regular_rate", "the segment read interval rate of des",
        OFFSET(des_regular_rate), AV_OPT_TYPE_INT, {.i64 = 0}, INT_MIN, INT_MAX, FLAGS},
	{"des_retry_interval", "the segment retry read interval,the unit is millisecnd",
        OFFSET(des_retry_interval), AV_OPT_TYPE_INT, {.i64 = 0}, INT_MIN, INT_MAX, FLAGS},
    { "hls_timeout",     "set timeout (in microseconds) of socket I/O operations",
        OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = FLAGS },
    { "hls_tcp_open_timeout", "set tcp open timeout (in microseconds) for tcp connect",
        OFFSET(open_timeout), AV_OPT_TYPE_INT, { .i64 = 5000000 }, 0, INT_MAX, .flags = FLAGS },
    { "hls_reconnect_count", "set tcp reconnect count",
        OFFSET(reconnect_count), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, .flags = FLAGS },
    {NULL}
};

static const AVClass hls_class = {
    .class_name = "hls,applehttp",
    .item_name  = av_default_item_name,
    .option     = hls_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

AVInputFormat ff_hls_demuxer = {
    .name           = "hls,applehttp",
    .long_name      = NULL_IF_CONFIG_SMALL("Apple HTTP Live Streaming"),
    .priv_class     = &hls_class,
    .priv_data_size = sizeof(HLSContext),
    .read_probe     = hls_probe,
    .read_header    = hls_read_header,
    .read_packet    = hls_read_packet,
    .read_close     = hls_close,
    .read_seek      = hls_read_seek,
};
