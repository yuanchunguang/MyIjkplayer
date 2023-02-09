/*
 * copyright (c) 2016 Zhang Rui
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

#ifndef AVUTIL_APPLICATION_H
#define AVUTIL_APPLICATION_H

#include "libavutil/log.h"
#include <pthread.h>

#define AVAPP_EVENT_WILL_HTTP_OPEN  1 //AVAppHttpEvent
#define AVAPP_EVENT_DID_HTTP_OPEN   2 //AVAppHttpEvent
#define AVAPP_EVENT_WILL_HTTP_SEEK  3 //AVAppHttpEvent
#define AVAPP_EVENT_DID_HTTP_SEEK   4 //AVAppHttpEvent
#define AVAPP_EVENT_DID_HTTP_REDIRECTED   5 //AVAppHttpEvent
#define AVAPP_EVENT_DID_HTTP_LOCAL_CACHED_VIDEO   6 //AVAppHttpEvent
#define AVAPP_EVENT_DID_HTTP_REDIRECT_IP   7 //AVAppHttpEvent
#define AVAPP_EVENT_DID_HTTP_M3U8_OPTIMIZE   8 //AVAppHttpEvent
#define AVAPP_EVENT_DID_PARSE_AUDIO_TRAKCS   9 //AVAppAudioTrackEvent

#define AVAPP_EVENT_ASYNC_STATISTIC     0x11000 //AVAppAsyncStatistic
#define AVAPP_EVENT_ASYNC_READ_SPEED    0x11001 //AVAppAsyncReadSpeed
#define AVAPP_EVENT_IO_TRAFFIC          0x12204 //AVAppIOTraffic

#define AVAPP_CTRL_WILL_TCP_OPEN   0x20001 //AVAppTcpIOControl
#define AVAPP_CTRL_DID_TCP_OPEN    0x20002 //AVAppTcpIOControl
#define AVAPP_CTRL_DID_DNS_END     0x20006 //AVAppDNSStatistic

#define AVAPP_CTRL_WILL_HTTP_OPEN  0x20003 //AVAppIOControl
#define AVAPP_CTRL_WILL_LIVE_OPEN  0x20005 //AVAppIOControl

#define AVAPP_CTRL_WILL_CONCAT_SEGMENT_OPEN 0x20007 //AVAppIOControl

#define FLOW_LOG_SIZE 8192   //for play flow log
#define TCP_CONNECTION_LOG_TOTAL_SIZE 4096  //for tcp connect log

#define STAR_MAX_NAME_NUM 1024
#define STAR_MAX_IP_NUM 11
#define STAR_MAX_DOMAIN_NUM 5

/**
 * player options
 */
#define OPT_COOKIES                     "cookies"
#define OPT_LICENSE_PRIVATE_KEY         "private_key"
#define OPT_LICENSE_USER_ID             "user_id"
#define OPT_LICENSE_APP_ID              "app_id"
#define OPT_LICENSE_DEVICE_ID           "device_id"
#define OPT_LICENSE_TOKEN               "token"
#define OPT_PLAYER_EVENT_ID             "event_id"
#define OPT_PLAYER_PLAY_ID              "play_id"
#define OPT_PLAYER_MEDIA_TYPE           "media_type" //value is AVSEPARATE/NOSEPARATE
#define OPT_SPLIT_AV_INFO               "split_av_info" //for save split_av_info

typedef struct AVAppIOControl {
    size_t  size;
    char    url[4096];      /* in, out */
    int     segment_index;  /* in, default = 0 */
    int     retry_counter;  /* in */

    int     is_handled;     /* out, default = false */
    int     is_url_changed; /* out, default = false */
} AVAppIOControl;

typedef struct AVAppTcpIOControl {
    int  error;
    int  family;
    char ip[96];
    int  port;
    int  fd;
    int64_t cur_duration;
    int64_t avg_duration;
} AVAppTcpIOControl;


typedef struct AVAppDNSStatistic {
    int  error;
    char hostname[512];
    int64_t cur_duration;
    int64_t avg_duration;
} AVAppDNSStatistic;

typedef struct AVAppAsyncStatistic {
    size_t  size;
    int64_t buf_backwards;
    int64_t buf_forwards;
    int64_t buf_capacity;
} AVAppAsyncStatistic;

typedef struct AVAppAsyncReadSpeed {
    size_t  size;
    int     is_full_speed;
    int64_t io_bytes;
    int64_t elapsed_milli;
} AVAppAsyncReadSpeed;

typedef struct AVAppHttpEvent
{
    void    *obj;
    char     url[4096];
    int64_t  offset;
    int      error;
    int      http_code;
    int      is_hit_cache;
    char redirect_ip[1024];
} AVAppHttpEvent;

typedef struct AVAppIOTraffic
{
    void   *obj;
    int     bytes;
} AVAppIOTraffic;

typedef struct AVAppAudioTrackEvent
{
    char tracks[1024];  //track list format string like: "eng;fre;chi"
} AVAppAudioTrackEvent;

typedef struct LogShowState {
    int start_time_log_audio_decode;
    int start_time_log_video_decode;
    int start_time_log_video_got_frame;
    int start_time_log_audio_got_frame;
    int first_video_frame_rendered;
    int find_stream_info;
    int download_ts_data;
    int download_ts_data_audio;
    //int start_time_log_count;
    //int start_error_log_count;
    //int64_t last_download_fail_timestamp;
    //char flow_log_info[FLOW_LOG_SIZE];
    //int  flow_log_need_send;
    //char tcp_connection_logs[TCP_CONNECTION_LOG_TOTAL_SIZE];
    //char tcp_rwtimeout_log[512];
}LogShowState;

typedef struct FlowLogStatus{
	int64_t last_download_fail_timestamp;
    char flow_log_info[FLOW_LOG_SIZE];
    int  flow_log_need_send;
    char tcp_connection_logs[TCP_CONNECTION_LOG_TOTAL_SIZE];
    char tcp_rwtimeout_log[512];
}FlowLogStatus;

enum enumMediaType{
    AV_SEPARATE,
    NO_SEPARATE
};

typedef struct PlayerStartStatus
{
    //char path[4096];
    int redirect;
    //int path_type;
    int complete;
    int m3u8_complete;
    char redirect_path[4096];
	enum enumMediaType media_type;
    int master_m3u8_complete; ////av split
	int parse_av_split_info_complete; //av_split_info only needs to be parsed once
	char audio_track[100]; //audio track for av split use
	char audio_track_priority_list[100]; //audio track list for av split use

	
}PlayerStartStatus;

//gloabl options for player
typedef struct PlayerDicOptions{
    pthread_mutex_t mutex;
    AVDictionary* dic;
}PlayerDicOptions;

/*
 * functions to set player start status
 */
enum enumPathType{
	PATH_UNKNOWN = -1,
    PATH_M3U8,
    PATH_TS,
    PATH_KEY,
	PATH_MP4
};

enum enumHlsSegmentType{
    SEGMENT_TS,
    SEGMENT_FMP4
};


typedef struct BitrateInfo {
    int64_t start_loading;
    int64_t end_loading ;
    int64_t loaded_bytes;
    int64_t current_bitrate;
    char** url_array;
    int64_t* bandwidth_array;
    int bandwidth_count;
    char* current_url;
    int current_url_index;
    int64_t current_bandwidth;
    int is_inited;
}BitrateInfo;


typedef struct stDNSStatistic{
    unsigned int dns_counts;
    int64_t dns_totaltime;
    int64_t dns_firsttime;
    int64_t dns_curtime;
    char hostname[256];
}stDNSStatistic;

typedef struct stTcpStatistic{
    unsigned int counts;
    int64_t totaltime;
    int64_t firsttime;
    int64_t curtime;
    char hostname[256];
    char ip[64];
}stTcpStatistic;

/**********for pre dns begin**********/
typedef struct DnsInfo {
    char star_DNS_ip[STAR_MAX_IP_NUM][STAR_MAX_NAME_NUM];
    int num;
} DnsInfo;

typedef struct DnsInfoList {
    DnsInfo list[STAR_MAX_DOMAIN_NUM];
    int num;
} DnsInfoList;


typedef struct preDNS{
    DnsInfoList star_DNS_list;
    int pre_dns_on;
}preDNS;
/**********for pre dns end**********/

typedef struct stCacheSetting
{
	char cache_path[256];
	int cache;
}stCacheSetting;


typedef struct  StreamDemuxInfo{
    unsigned char master[256];
    int slave;
}StreamDemuxInfo;

enum enumStatusType{
	STATUS_TYPE_DEFAULT = 0,
    STATUS_TYPE_ALT  //only for audio when open hls video and audio in parallel
};


typedef struct URLStartStatus
{
    enum enumPathType path_type;
	enum enumStatusType status_type;
    int complete;
	int m3u8_complete;
	FlowLogStatus *fls;
}URLStartStatus;


typedef struct AVApplicationContext AVApplicationContext;
struct AVApplicationContext {
    const AVClass *av_class;    /**< information for av_log(). Set by av_application_open(). */
    void *opaque;               /**< user data. */
    LogShowState *lss;
    PlayerStartStatus *pss;
    PlayerDicOptions *po;
    int adaptive_bitrate_switching;
    BitrateInfo *bi;
    stDNSStatistic *dnss;
    stTcpStatistic *tcps;
    stCacheSetting *caches;
    preDNS  *pre_dns;
    StreamDemuxInfo *demuxer;
	int64_t m3u8_read_size;
	
	URLStartStatus *uss_default;
	URLStartStatus *uss_alt;  //in order to record the audio m3u8 status when open hls video and audio in parallel
    
    URLStartStatus *uss_default_segment;
    URLStartStatus *uss_alt_segment;  //in order to record the audio segment status when open hls video and audio in parallel
	
    int (*func_on_app_event)(AVApplicationContext *h, int event_type ,void *obj, size_t size);
};

int  av_application_alloc(AVApplicationContext **ph, void *opaque);
int  av_application_open(AVApplicationContext **ph, void *opaque);
void av_application_close(AVApplicationContext *h);
void av_application_closep(AVApplicationContext **ph);

void av_application_on_http_event(AVApplicationContext *h, int event_type, AVAppHttpEvent *event);
void av_application_will_http_open(AVApplicationContext *h, void *obj, const char *url);
void av_application_did_http_redirected(AVApplicationContext *h, void *obj, const char *url);
void av_application_did_http_redirect_ip(AVApplicationContext *h, void *obj, const char *redirect_ip);
void av_application_did_http_m3u8_optimize(AVApplicationContext *h, const char *info);
void av_application_did_http_local_cached_video(AVApplicationContext *h, const char *url);
void av_application_did_http_open(AVApplicationContext *h, void *obj, const char *url, int error, int http_code, int is_hit_cache);
void av_application_will_http_seek(AVApplicationContext *h, void *obj, const char *url, int64_t offset);
void av_application_did_http_seek(AVApplicationContext *h, void *obj, const char *url, int64_t offset, int error, int http_code);

void av_application_did_io_tcp_read(AVApplicationContext *h, void *obj, int bytes);

int  av_application_on_io_control(AVApplicationContext *h, int event_type, AVAppIOControl *control);

int av_application_on_tcp_will_open(AVApplicationContext *h);
int av_application_on_tcp_did_open(AVApplicationContext *h, int error, int fd, int64_t curduration, int64_t avgduraiton, char* peer);
int av_application_on_dns_statistic(AVApplicationContext *h, int error, const char* hostname, int64_t curduration, int64_t avgduraiton);

void av_application_on_async_statistic(AVApplicationContext *h, AVAppAsyncStatistic *statistic);
void av_application_on_async_read_speed(AVApplicationContext *h, AVAppAsyncReadSpeed *speed);

void av_application_did_parse_audio_tracks(AVApplicationContext *h, const char* tracks);


#endif /* AVUTIL_APPLICATION_H */
