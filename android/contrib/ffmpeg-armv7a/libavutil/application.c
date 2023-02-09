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

#include "application.h"
#include "libavformat/network.h"
#include "libavutil/avstring.h"
#include "stdint.h"
#include "log.h"

void av_application_on_io_traffic(AVApplicationContext *h, AVAppIOTraffic *event);

int av_application_alloc(AVApplicationContext **ph, void *opaque)
{
    AVApplicationContext *h = NULL;

    h = av_mallocz(sizeof(AVApplicationContext));
    if (!h)
        return AVERROR(ENOMEM);

    h->opaque = opaque;
    
    h->pss=av_mallocz(sizeof(PlayerStartStatus));
    if (!h->pss)
        return AVERROR(ENOMEM);
    
    h->lss=av_mallocz(sizeof(LogShowState));
    if (!h->lss)
        return AVERROR(ENOMEM);
    
    h->po=av_mallocz(sizeof(PlayerDicOptions));
    if (!h->po)
        return AVERROR(ENOMEM);
    
    h->bi=av_mallocz(sizeof(BitrateInfo));
    if (!h->bi)
        return AVERROR(ENOMEM);
    
    h->dnss=av_mallocz(sizeof(stDNSStatistic));
    if (!h->dnss)
        return AVERROR(ENOMEM);
    
    h->tcps=av_mallocz(sizeof(stTcpStatistic));
    if (!h->tcps)
        return AVERROR(ENOMEM);

    h->caches = av_mallocz(sizeof(stCacheSetting));
	if (!h->caches)
		return AVERROR(ENOMEM);
    
    h->pre_dns=av_mallocz(sizeof(preDNS));
    if (!h->pre_dns)
        return AVERROR(ENOMEM);
	
	h->demuxer=av_mallocz(sizeof(StreamDemuxInfo));
	if (!h->demuxer)
		return AVERROR(ENOMEM);
    
    h->uss_default=av_mallocz(sizeof(URLStartStatus));
    if (!h->uss_default){
        return AVERROR(ENOMEM);
	}
	else{
		h->uss_default->status_type = STATUS_TYPE_DEFAULT;
		h->uss_default->fls = av_mallocz(sizeof(FlowLogStatus));
		if (!h->uss_default->fls){
			return AVERROR(ENOMEM);
		}
		
	}
	
	h->uss_alt=av_mallocz(sizeof(URLStartStatus));
    if (!h->uss_alt){
        return AVERROR(ENOMEM);
	}
	else{
		h->uss_alt->status_type = STATUS_TYPE_ALT;
		h->uss_alt->fls = av_mallocz(sizeof(FlowLogStatus));
		if (!h->uss_alt->fls){
			return AVERROR(ENOMEM);
		}
	}
	
    h->uss_default_segment=av_mallocz(sizeof(URLStartStatus));
    if (!h->uss_default_segment){
        return AVERROR(ENOMEM);
    }
    else{
        h->uss_default_segment->status_type = STATUS_TYPE_DEFAULT;
        h->uss_default_segment->path_type = PATH_TS;
        h->uss_default_segment->fls = av_mallocz(sizeof(FlowLogStatus));
        if (!h->uss_default_segment->fls){
            return AVERROR(ENOMEM);
        }
        
    }
    
    h->uss_alt_segment=av_mallocz(sizeof(URLStartStatus));
    if (!h->uss_alt_segment){
        return AVERROR(ENOMEM);
    }
    else{
        h->uss_alt_segment->status_type = STATUS_TYPE_ALT;
        h->uss_alt_segment->path_type = PATH_TS;
        h->uss_alt_segment->fls = av_mallocz(sizeof(FlowLogStatus));
        if (!h->uss_alt_segment->fls){
            return AVERROR(ENOMEM);
        }
    }
    
	h->m3u8_read_size = 0;
    *ph = h;
    return 0;
}

int av_application_open(AVApplicationContext **ph, void *opaque)
{
    int ret = av_application_alloc(ph, opaque);
    if (ret)
        return ret;

    return 0;
}

void av_application_close(AVApplicationContext *h)
{   if (h->pss)
    {
        av_free(h->pss);
    }
    
    if (h->lss)
    {
        av_free(h->lss);
    }
    
    if(h->po)
    {
        av_free(h->po);
    }
    
    if(h->bi)
    {
        av_free(h->bi);
    }
    
    if(h->dnss)
    {
        av_free(h->dnss);
    }
    
    if(h->tcps)
    {
        av_free(h->tcps);
    }

	if (h->caches)
	{
		av_free(h->caches);
	}
    
    if(h->pre_dns)
    {
        av_free(h->pre_dns);
    }
    
    if(h->demuxer)
    {
        av_free(h->demuxer);
    }
	
	if(h->uss_default)
    {
		if(h->uss_default->fls)
			av_free(h->uss_default->fls);
			
        av_free(h->uss_default);
    }
	
	if(h->uss_alt)
    {
		if(h->uss_alt->fls)
			av_free(h->uss_alt->fls);
        av_free(h->uss_alt);
    }
	
    if(h->uss_default_segment)
    {
        if(h->uss_default_segment->fls)
            av_free(h->uss_default_segment->fls);
            
        av_free(h->uss_default_segment);
    }
    
    if(h->uss_alt_segment)
    {
        if(h->uss_alt_segment->fls)
            av_free(h->uss_alt_segment->fls);
        av_free(h->uss_alt_segment);
    }
    
    av_free(h);
}

void av_application_closep(AVApplicationContext **ph)
{
    if (!ph || !*ph)
        return;

    av_application_close(*ph);
    *ph = NULL;
}

void av_application_on_http_event(AVApplicationContext *h, int event_type, AVAppHttpEvent *event)
{
    if (h && h->func_on_app_event)
        h->func_on_app_event(h, event_type, (void *)event, sizeof(AVAppHttpEvent));
}

void av_application_will_http_open(AVApplicationContext *h, void *obj, const char *url)
{
    AVAppHttpEvent event = {0};

    if (!h || !obj || !url)
        return;

    event.obj        = obj;
    av_strlcpy(event.url, url, sizeof(event.url));

    av_application_on_http_event(h, AVAPP_EVENT_WILL_HTTP_OPEN, &event);
}

void av_application_did_http_redirected(AVApplicationContext *h, void *obj, const char *url)
{
    AVAppHttpEvent event = {0};
    
    if (!h || !obj || !url)
        return;
    
    event.obj        = obj;
    av_strlcpy(event.url, url, sizeof(event.url));
    
    av_application_on_http_event(h, AVAPP_EVENT_DID_HTTP_REDIRECTED, &event);
}

void av_application_did_http_redirect_ip(AVApplicationContext *h, void *obj, const char *redirect_ip)
{
    AVAppHttpEvent event = {0};
    
    if (!h || !obj || !redirect_ip)
        return;
    
    event.obj        = obj;
    av_strlcpy(event.redirect_ip, redirect_ip, sizeof(event.redirect_ip));
    
    av_application_on_http_event(h, AVAPP_EVENT_DID_HTTP_REDIRECT_IP, &event);
}

void av_application_did_http_m3u8_optimize(AVApplicationContext *h, const char *info)
{
    AVAppHttpEvent event = {0};
    
    if (!h)
        return;
    
    
    av_application_on_http_event(h, AVAPP_EVENT_DID_HTTP_M3U8_OPTIMIZE, &event);
}


void av_application_did_http_local_cached_video(AVApplicationContext *h, const char *url)
{
    AVAppHttpEvent event = {0};

    if (!h || !url)
        return;

    av_strlcpy(event.url, url, sizeof(event.url));

    av_application_on_http_event(h, AVAPP_EVENT_DID_HTTP_LOCAL_CACHED_VIDEO, &event);
}

void av_application_did_http_open(AVApplicationContext *h, void *obj, const char *url, int error, int http_code, int is_hit_cache)
{
    AVAppHttpEvent event = {0};

    if (!h || !obj || !url)
        return;

    event.obj        = obj;
    av_strlcpy(event.url, url, sizeof(event.url));
    event.error     = error;
    event.http_code = http_code;
    event.is_hit_cache = is_hit_cache;

    av_application_on_http_event(h, AVAPP_EVENT_DID_HTTP_OPEN, &event);
}

void av_application_will_http_seek(AVApplicationContext *h, void *obj, const char *url, int64_t offset)
{
    AVAppHttpEvent event = {0};

    if (!h || !obj || !url)
        return;

    event.obj        = obj;
    event.offset     = offset;
    av_strlcpy(event.url, url, sizeof(event.url));

    av_application_on_http_event(h, AVAPP_EVENT_WILL_HTTP_SEEK, &event);
}

void av_application_did_http_seek(AVApplicationContext *h, void *obj, const char *url, int64_t offset, int error, int http_code)
{
    AVAppHttpEvent event = {0};

    if (!h || !obj || !url)
        return;

    event.obj        = obj;
    event.offset     = offset;
    av_strlcpy(event.url, url, sizeof(event.url));
    event.error     = error;
    event.http_code = http_code;

    av_application_on_http_event(h, AVAPP_EVENT_DID_HTTP_SEEK, &event);
}

void av_application_on_io_traffic(AVApplicationContext *h, AVAppIOTraffic *event)
{
    if (h && h->func_on_app_event)
        h->func_on_app_event(h, AVAPP_EVENT_IO_TRAFFIC, (void *)event, sizeof(AVAppIOTraffic));
}

int  av_application_on_io_control(AVApplicationContext *h, int event_type, AVAppIOControl *control)
{
    if (h && h->func_on_app_event)
        return h->func_on_app_event(h, event_type, (void *)control, sizeof(AVAppIOControl));
    return 0;
}

int av_application_on_tcp_will_open(AVApplicationContext *h)
{
    if (h && h->func_on_app_event) {
        AVAppTcpIOControl control = {0};
        return h->func_on_app_event(h, AVAPP_CTRL_WILL_TCP_OPEN, (void *)&control, sizeof(AVAppTcpIOControl));
    }
    return 0;
}

int av_application_on_dns_statistic(AVApplicationContext *h, int error, const char* hostname, int64_t curduration, int64_t avgduration){
    if (!h || !h->func_on_app_event)
        return 0;
    AVAppDNSStatistic stat = {0};
    stat.error = error;
    if (hostname) {
        memset(stat.hostname, 0, sizeof(stat.hostname));
        av_strlcpy(stat.hostname, hostname, sizeof(stat.hostname));
    }
    stat.cur_duration = curduration;
    stat.avg_duration = avgduration;
    return h->func_on_app_event(h, AVAPP_CTRL_DID_DNS_END, (void *)&stat, sizeof(AVAppDNSStatistic));
}

// only callback returns error
int av_application_on_tcp_did_open(AVApplicationContext *h, int error, int fd, int64_t curduration, int64_t avgduration, char* peer)
{
    struct sockaddr_storage so_stg;
    int       ret = 0;
    socklen_t so_len = sizeof(so_stg);
    int       so_family;
    AVAppTcpIOControl control = {0};
    char      *so_ip_name = control.ip;

    if (!h || !h->func_on_app_event || fd <= 0)
        return 0;

    ret = getpeername(fd, (struct sockaddr *)&so_stg, &so_len);
    control.error = error;
    control.fd = fd;
    control.cur_duration = curduration;
    control.avg_duration = avgduration;
    if(ret){
        if (peer) {
            //use the peer ip that try to connect from tcp_open
            av_strlcpy(control.ip, peer, strlen(peer)+1);
        }
        else{
            av_log(NULL, AV_LOG_WARNING, "av_application_on_tcp_did_open get peer name fail and no peer ip, ret=%d\n",ret);
            return 0;
        }
    }
    else{
        so_family = ((struct sockaddr*)&so_stg)->sa_family;
        switch (so_family) {
            case AF_INET: {
                struct sockaddr_in* in4 = (struct sockaddr_in*)&so_stg;
                if (inet_ntop(AF_INET, &(in4->sin_addr), so_ip_name, sizeof(control.ip))) {
                    control.family = AF_INET;
                    control.port = in4->sin_port;
                }
                break;
            }
            case AF_INET6: {
                struct sockaddr_in6* in6 = (struct sockaddr_in6*)&so_stg;
                if (inet_ntop(AF_INET6, &(in6->sin6_addr), so_ip_name, sizeof(control.ip))) {
                    control.family = AF_INET6;
                    control.port = in6->sin6_port;
                }
                break;
            }
        }
    }
    return h->func_on_app_event(h, AVAPP_CTRL_DID_TCP_OPEN, (void *)&control, sizeof(AVAppTcpIOControl));
}

void av_application_on_async_statistic(AVApplicationContext *h, AVAppAsyncStatistic *statistic)
{
    if (h && h->func_on_app_event)
        h->func_on_app_event(h, AVAPP_EVENT_ASYNC_STATISTIC, (void *)statistic, sizeof(AVAppAsyncStatistic));
}

void av_application_on_async_read_speed(AVApplicationContext *h, AVAppAsyncReadSpeed *speed)
{
    if (h && h->func_on_app_event)
        h->func_on_app_event(h, AVAPP_EVENT_ASYNC_READ_SPEED, (void *)speed, sizeof(AVAppAsyncReadSpeed));
}

void av_application_did_io_tcp_read(AVApplicationContext *h, void *obj, int bytes)
{
    AVAppIOTraffic event = {0};
    if (!h || !obj || bytes <= 0)
        return;

    event.obj        = obj;
    event.bytes      = bytes;

    av_application_on_io_traffic(h, &event);
}

void av_application_did_parse_audio_tracks(AVApplicationContext *h, const char* tracks){
    if (!h || !tracks || strlen(tracks)==0){
        return;
    }
    AVAppAudioTrackEvent event = {0};    
    av_strlcpy(event.tracks, tracks, sizeof(event.tracks));

    if (h && h->func_on_app_event)
        h->func_on_app_event(h, AVAPP_EVENT_DID_PARSE_AUDIO_TRAKCS, (void *)&event, sizeof(AVAppAudioTrackEvent));
}
