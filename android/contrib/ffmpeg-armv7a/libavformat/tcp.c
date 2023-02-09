/*
 * TCP protocol
 * Copyright (c) 2002 Fabrice Bellard
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
#include "avformat.h"
#include "libavutil/avassert.h"
#include "libavutil/parseutils.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/application.h"
#include "libavutil/dns_cache.h"

#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#if HAVE_POLL_H
#include <poll.h>
#endif
#if HAVE_PTHREADS
#include <pthread.h>
#endif

#if HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif
#include "global_variables.h"



typedef struct TCPContext {
    const AVClass *class;
    int fd;
    int listen;
    int open_timeout;
    int rw_timeout;
    int listen_timeout;
    int recv_buffer_size;
    int send_buffer_size;
    int64_t app_ctx_intptr;
    int ipv6_port_workaround;
    int tcp_nodelay;
    //char * app_ctx_intptr;

    int addrinfo_one_by_one;
    int addrinfo_timeout;
    int reconnect_count;
    int64_t dns_cache_timeout;
    int dns_cache_clear;

    AVApplicationContext *app_ctx;
    char uri[1024];
    int fastopen;
    int tcp_connected;
    int fastopen_success;
	int64_t url_start_status_intptr;
    URLStartStatus* url_start_status;
} TCPContext;

#define FAST_OPEN_FLAG 0x20000000

#define OFFSET(x) offsetof(TCPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
    { "listen",          "Listen for incoming connections",  OFFSET(listen),         AV_OPT_TYPE_INT, { .i64 = 0 },     0,       2,       .flags = D|E },
    { "timeout",     "set timeout (in microseconds) of socket I/O operations", OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "connect_timeout",  "set connect timeout (in microseconds) of socket", OFFSET(open_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "listen_timeout",  "Connection awaiting timeout (in milliseconds)",      OFFSET(listen_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                OFFSET(send_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",             OFFSET(recv_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "tcp_nodelay", "Use TCP_NODELAY to disable nagle's algorithm",           OFFSET(tcp_nodelay), AV_OPT_TYPE_BOOL, { .i64 = 0 },             0, 1, .flags = D|E },
    { "ijkapplication",   "AVApplicationContext",                              OFFSET(app_ctx_intptr),   AV_OPT_TYPE_INT64, { .i64 = 0 }, INT64_MIN, INT64_MAX, .flags = D },
	{ "URLStartStatus", "set url start status intptr",                                   OFFSET(url_start_status_intptr), AV_OPT_TYPE_INT64, { .i64 = 0 }, INT64_MIN, INT64_MAX, .flags = D },

    { "ipv6_port_workaround",  "reset port in parsing addrinfo under ipv6",    OFFSET(ipv6_port_workaround), AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "addrinfo_one_by_one",  "parse addrinfo one by one in getaddrinfo()",    OFFSET(addrinfo_one_by_one), AV_OPT_TYPE_INT, { .i64 = 0 },         0, 1, .flags = D|E },
    { "addrinfo_timeout", "set timeout (in microseconds) for getaddrinfo()",   OFFSET(addrinfo_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },       -1, INT_MAX, .flags = D|E },
    { "tcp_open_timeout", "set tcp open timeout (in microseconds) for tcp connect",   OFFSET(open_timeout), AV_OPT_TYPE_INT, { .i64 = 5000000 }, 0, INT_MAX, .flags = D|E },
    { "reconnect_count", "set tcp reconnect count",   OFFSET(reconnect_count), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, .flags = D|E },
 	{ "dns_cache_timeout", "dns cache TTL (in microseconds)",   OFFSET(dns_cache_timeout), AV_OPT_TYPE_INT, { .i64 = 0 },       -1, INT64_MAX, .flags = D|E },
    { "dns_cache_clear", "clear dns cache",   OFFSET(dns_cache_clear), AV_OPT_TYPE_INT, { .i64 = 0},       -1, INT_MAX, .flags = D|E },
    { "fastopen", "enable fastopen",          OFFSET(fastopen), AV_OPT_TYPE_INT, { .i64 = 0},       0, INT_MAX, .flags = D|E },
    { NULL }
};

static const AVClass tcp_class = {
    .class_name = "tcp",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};


#define ASYN_DNS_ON 1

int ijk_tcp_getaddrinfo_nonblock(const char *hostname, const char *servname,
                                 const struct addrinfo *hints, struct addrinfo **res,
                                 int64_t timeout,
                                 const AVIOInterruptCB *int_cb, int one_by_one);
#ifdef HAVE_PTHREADS

typedef struct TCPAddrinfoRequest
{
    AVBufferRef *buffer;

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    AVIOInterruptCB interrupt_callback;

    char            *hostname;
    char            *servname;
    struct addrinfo  hints;
    struct addrinfo *res;

    volatile int     finished;
    int              last_error;
} TCPAddrinfoRequest;

static void tcp_getaddrinfo_request_free(TCPAddrinfoRequest *req)
{
    av_assert0(req);
    if (req->res) {
        freeaddrinfo(req->res);
        req->res = NULL;
    }

    av_freep(&req->servname);
    av_freep(&req->hostname);
    pthread_cond_destroy(&req->cond);
    pthread_mutex_destroy(&req->mutex);
    av_freep(&req);
}

static void tcp_getaddrinfo_request_free_buffer(void *opaque, uint8_t *data)
{
    av_assert0(opaque);
    TCPAddrinfoRequest *req = (TCPAddrinfoRequest *)opaque;
    tcp_getaddrinfo_request_free(req);
}

static int tcp_getaddrinfo_request_create(TCPAddrinfoRequest **request,
                                          const char *hostname,
                                          const char *servname,
                                          const struct addrinfo *hints,
                                          const AVIOInterruptCB *int_cb)
{
    TCPAddrinfoRequest *req = (TCPAddrinfoRequest *) av_mallocz(sizeof(TCPAddrinfoRequest));
    if (!req)
        return AVERROR(ENOMEM);

    if (pthread_mutex_init(&req->mutex, NULL)) {
        av_freep(&req);
        return AVERROR(ENOMEM);
    }

    if (pthread_cond_init(&req->cond, NULL)) {
        pthread_mutex_destroy(&req->mutex);
        av_freep(&req);
        return AVERROR(ENOMEM);
    }

    if (int_cb)
        req->interrupt_callback = *int_cb;

    if (hostname) {
        req->hostname = av_strdup(hostname);
        if (!req->hostname)
            goto fail;
    }

    if (servname) {
        req->servname = av_strdup(servname);
        if (!req->hostname)
            goto fail;
    }

    if (hints) {
        req->hints.ai_family   = hints->ai_family;
        req->hints.ai_socktype = hints->ai_socktype;
        req->hints.ai_protocol = hints->ai_protocol;
        req->hints.ai_flags    = hints->ai_flags;
    }

    req->buffer = av_buffer_create(NULL, 0, tcp_getaddrinfo_request_free_buffer, req, 0);
    if (!req->buffer)
        goto fail;

    *request = req;
    return 0;
fail:
    tcp_getaddrinfo_request_free(req);
    return AVERROR(ENOMEM);
}

static void *tcp_getaddrinfo_worker(void *arg)
{

    TCPAddrinfoRequest *req = arg;

    int ret = getaddrinfo(req->hostname, req->servname, &req->hints, &req->res);
        
	if (ret) {
        req->last_error = ret;
    }
    pthread_mutex_lock(&req->mutex);
    req->finished = 1;
    pthread_cond_signal(&req->cond);
    pthread_mutex_unlock(&req->mutex);
    av_buffer_unref(&req->buffer);
    return NULL;
}

static void *tcp_getaddrinfo_one_by_one_worker(void *arg)
{
    struct addrinfo *temp_addrinfo = NULL;
    struct addrinfo *cur = NULL;
    int ret = EAI_FAIL;
    int i = 0;
    int option_length = 0;

    TCPAddrinfoRequest *req = (TCPAddrinfoRequest *)arg;

    int family_option[2] = {AF_INET, AF_INET6};

    option_length = sizeof(family_option) / sizeof(family_option[0]);

    for (; i < option_length; ++i) {
        struct addrinfo *hint = &req->hints;
        hint->ai_family = family_option[i];
        ret = getaddrinfo(req->hostname, req->servname, hint, &temp_addrinfo);
        if (ret) {
            req->last_error = ret;
            continue;
        }
        pthread_mutex_lock(&req->mutex);
        if (!req->res) {
            req->res = temp_addrinfo;
        } else {
            cur = req->res;
            while (cur->ai_next)
                cur = cur->ai_next;
            cur->ai_next = temp_addrinfo;
        }
        pthread_mutex_unlock(&req->mutex);
    }
    pthread_mutex_lock(&req->mutex);
    req->finished = 1;
    pthread_cond_signal(&req->cond);
    pthread_mutex_unlock(&req->mutex);
    av_buffer_unref(&req->buffer);
    return NULL;
}

int ijk_tcp_getaddrinfo_nonblock(const char *hostname, const char *servname,
                                 const struct addrinfo *hints, struct addrinfo **res,
                                 int64_t timeout,
                                 const AVIOInterruptCB *int_cb, int one_by_one)
{
    int     ret;
    int64_t start;
    int64_t now;
    AVBufferRef        *req_ref = NULL;
    TCPAddrinfoRequest *req     = NULL;
    pthread_t work_thread;

    if (hostname && !hostname[0])
        hostname = NULL;
#if ASYN_DNS_ON
#else
    if (timeout <= 0)
        return getaddrinfo(hostname, servname, hints, res);
#endif

    ret = tcp_getaddrinfo_request_create(&req, hostname, servname, hints, int_cb);
    if (ret)
        goto fail;

    req_ref = av_buffer_ref(req->buffer);
    if (req_ref == NULL) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    /* FIXME: using a thread pool would be better. */
    if (one_by_one)
        ret = pthread_create(&work_thread, NULL, tcp_getaddrinfo_one_by_one_worker, req);
    else
        ret = pthread_create(&work_thread, NULL, tcp_getaddrinfo_worker, req);

    if (ret) {
        ret = AVERROR(ret);
        goto fail;
    }

    pthread_detach(work_thread);

    start = av_gettime();
    now   = start;

    pthread_mutex_lock(&req->mutex);
    while (1) {
        int64_t wait_time = now + 100000;
        struct timespec tv = { .tv_sec  =  wait_time / 1000000,
                               .tv_nsec = (wait_time % 1000000) * 1000 };
#if ASYN_DNS_ON
        if (req->finished || (ff_check_interrupt(int_cb))) {
#else
        if (req->finished || (start + timeout < now)) {
#endif
            if (req->res) {
                
                av_log(NULL, AV_LOG_DEBUG, "dns complete ip list:\n");
                int ip_counts = 0;
                struct addrinfo* paddr = req->res;
                while (paddr) {
                    char peer_ip[64]={0};
                    if (paddr->ai_family == AF_INET6) {
                        struct sockaddr_in6 peer_addr;
                        int socklen = sizeof(struct sockaddr_in6);
                        inet_ntop(AF_INET6, &((struct sockaddr_in6*)paddr->ai_addr)->sin6_addr, peer_ip, INET6_ADDRSTRLEN);
                    }else{
                        struct sockaddr_in peer_addr;
                        int socklen = sizeof(struct sockaddr);
                        inet_ntop(AF_INET, &((struct sockaddr_in*)paddr->ai_addr)->sin_addr, peer_ip, INET_ADDRSTRLEN);
                    }
                    paddr = paddr->ai_next;
                    av_log(NULL, AV_LOG_DEBUG, "ip: %s, %d\n", peer_ip, ip_counts++);
                }
                
                ret = 0;
                *res = req->res;
                req->res = NULL;
            } else {
                ret = req->last_error ? req->last_error : AVERROR_EXIT;
            }
            break;
        }
//#if defined(__ANDROID__) && defined(HAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC)
//        ret = pthread_cond_timedwait_monotonic_np(&req->cond, &req->mutex, &tv);
//#else
        ret = pthread_cond_timedwait(&req->cond, &req->mutex, &tv);
//#endif
        if (ret != 0 && ret != ETIMEDOUT) {
            av_log(NULL, AV_LOG_ERROR, "pthread_cond_timedwait failed: %d\n", ret);
            ret = AVERROR_EXIT;
            break;
        }

        if (ff_check_interrupt(&req->interrupt_callback)) {
            ret = AVERROR_EXIT;
            break;
        }

        now = av_gettime();
    }
    pthread_mutex_unlock(&req->mutex);
fail:
    av_buffer_unref(&req_ref);
    return ret;
}

#else
int ijk_tcp_getaddrinfo_nonblock(const char *hostname, const char *servname,
                                 const struct addrinfo *hints, struct addrinfo **res,
                                 int64_t timeout,
                                 const AVIOInterruptCB *int_cb)
{
    return getaddrinfo(hostname, servname, hints, res);
}
#endif

static int my_getaddrinfo(URLContext *h, const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res, int order)
{
	//TCPContext *s = h->priv_data;
    struct addrinfo *ai;
    struct sockaddr_in *sin;
	char *ip = NULL;
    //av_log(NULL, AV_LOG_ERROR, "zy dns num= %d\n",global_star_DNS_list.num);
	DnsInfo *match_DNS = NULL;
    TCPContext *s = h->priv_data;
    
    if (s->app_ctx) {
        for(int i=0; i<s->app_ctx->pre_dns->star_DNS_list.num;i++){
            DnsInfo *temp=&(s->app_ctx->pre_dns->star_DNS_list.list[i]);
            //av_log(NULL, AV_LOG_ERROR, "zy dns num= %d, %d, order=%d\n",temp->num, global_star_DNS_list.list[i].num, order);
            if (0 == strcmp(node,(s->app_ctx->pre_dns->star_DNS_list.list[i]).star_DNS_ip[0])){
                match_DNS = &(s->app_ctx->pre_dns->star_DNS_list.list[i]);
                break;
            }
        }
    }
    
	if(match_DNS){
		if(order < match_DNS->num)
			ip= match_DNS->star_DNS_ip[order];
	}
	if (ip==NULL)
		return EAI_FAIL;

	*res = NULL;
    sin  = av_mallocz(sizeof(struct sockaddr_in));
    if (!sin)
        return EAI_FAIL;

	//sin begin
    sin->sin_family = AF_INET;
    //av_log(NULL, AV_LOG_INFO, "zy ip= %s\n",ip);

    if (node) {
		inet_aton(ip, (struct in_addr *) &(sin->sin_addr));
    } else {
        return EAI_FAIL;
    }

    /* Note: getaddrinfo allows service to be a string, which
     * should be looked up using getservbyname. */
    if (service)
        sin->sin_port = htons(atoi(service));

    ai = av_mallocz(sizeof(struct addrinfo));
    if (!ai) {
        av_free(sin);
        return EAI_FAIL;
    }
	//sin over

    *res            = ai;
    ai->ai_family   = AF_INET;
    ai->ai_socktype = hints ? hints->ai_socktype : 0;
    switch (ai->ai_socktype) {
    case SOCK_STREAM:
        ai->ai_protocol = IPPROTO_TCP;
        break;
    case SOCK_DGRAM:
        ai->ai_protocol = IPPROTO_UDP;
        break;
    default:
        ai->ai_protocol = 0;
        break;
    }

    ai->ai_addr    = (struct sockaddr *)sin;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_canonname = NULL;

    ai->ai_next = NULL;
    struct addrinfo *next=NULL;
	my_getaddrinfo(h, node, service, hints, &(next), order+1);
    ai->ai_next = next;
	
    return 0;
}

/* return non zero if error */
static int tcp_open_use_pre_dns(URLContext *h, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai, *cur_ai, *first_ai;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    int try_connect_cnt = 0;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
	int usePreDns = 1; //zy add
    //s->open_timeout = 5000000;
    s->app_ctx = (AVApplicationContext *)(intptr_t)s->app_ctx_intptr;
	s->url_start_status = (URLStartStatus *)(intptr_t)s->url_start_status_intptr;
    int max_reconnect_count = s->reconnect_count;

    //av_log(NULL, AV_LOG_INFO, "TCPPRECON: tcp open uri=%s\n", uri);
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp"))
        return AVERROR(EINVAL);
    if (port <= 0 || port >= 65536) {
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "listen", p)) {
            char *endptr = NULL;
            s->listen = strtol(buf, &endptr, 10);
            /* assume if no digits were found it is a request to enable it */
            if (buf == endptr)
                s->listen = 1;
        }
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0) {
        //s->open_timeout =
        h->rw_timeout   = s->rw_timeout;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;
    //av_log(h, AV_LOG_WARNING, "s->addrinfo_timeout=%d.\n",s->addrinfo_timeout);

    
    init_tcp_connection_logs(s->app_ctx,s->url_start_status);
resetDNS:
    if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
		if (s->url_start_status->status_type == STATUS_TYPE_ALT){
			if(s->url_start_status->path_type==PATH_M3U8){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_begin_audio = %lld",av_gettime()/1000);

			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_begin_audio = %lld",av_gettime()/1000);
			}else if(s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_begin_audio = %lld",av_gettime()/1000);
			}
		}
		else{
			if(s->url_start_status->path_type==PATH_M3U8){
				if (s->app_ctx->pss->redirect){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_DNS_begin = %lld",av_gettime()/1000);
				}else{
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_begin = %lld",av_gettime()/1000);
				}
			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_begin = %lld",av_gettime()/1000);
			}else if(s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_begin = %lld",av_gettime()/1000);
			}else if (s->url_start_status->path_type == PATH_MP4) {
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,"mp4_DNS_begin = %lld", av_gettime() / 1000);
			}	
		}
    }
	
    add_flow_log(s->app_ctx,s->url_start_status,FL_DNS_BEGIN,av_gettime()/1000);
    
	/////////////////////
#ifdef HAVE_PTHREADS
    //av_log(h, AV_LOG_WARNING, "in ijk_tcp_getaddrinfo_nonblock.\n");
	if(usePreDns==1) {
		//av_log(NULL,AV_LOG_INFO,"node = %s, portstr =%s ",hostname, portstr);
		ret = my_getaddrinfo(h, hostname, portstr, &hints, &ai, 1);//zy:doing this in a new thread with time out
		av_log(NULL,AV_LOG_INFO,"zy predns_test: use predns ret=%d \n ",ret);
	}
	if(usePreDns==0||ret) {
		usePreDns=0;
		ret = ijk_tcp_getaddrinfo_nonblock(hostname, portstr, &hints, &ai, s->addrinfo_timeout, &h->interrupt_callback, s->addrinfo_one_by_one);
		av_log(NULL,AV_LOG_INFO,"zy predns_test: use default dns ret=%d\n ",ret);
	}
#else
    if (s->addrinfo_timeout > 0)
        av_log(h, AV_LOG_WARNING, "Ignore addrinfo_timeout without pthreads support.\n");
    if (!hostname[0])
        ret = getaddrinfo(NULL, portstr, &hints, &ai);
    else {
    	if(usePreDns==1) {
    			//av_log(NULL,AV_LOG_INFO,"node = %s, portstr =%s ",hostname, portstr);
    			ret = my_getaddrinfo(h, hostname, portstr, &hints, &ai, 1);//zy:doing this in a new thread with time out
    			av_log(NULL,AV_LOG_INFO,"zy predns_test: use predns ret=%d\n ",ret);
    		}
    	if(usePreDns==0||ret) {
    		usePreDns=0;
    		ret = getaddrinfo(hostname, portstr, &hints, &ai);
			av_log(NULL,AV_LOG_INFO,"zy predns_test: use default dns ret=%d\n ",ret);
    	}
    }
#endif

    if (ret) {
        av_log(h, AV_LOG_ERROR, "Failed to resolve hostname %s: %s\n", hostname, gai_strerror(ret));
		if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
			if (s->url_start_status->status_type == STATUS_TYPE_ALT){
				if(s->url_start_status->path_type==PATH_M3U8){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d",ERROR_M3U8_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_DNS_use_pre_audio = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d",ERROR_TS_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre_audio = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_KEY){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_aduio = %d",ERROR_KEY_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre_audio = %d", usePreDns);
				}
			}
			else{
				if(s->url_start_status->path_type==PATH_M3U8){
					if (s->app_ctx->pss->redirect) {
						startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_REDIRECTED_M3U8_DNS_FAIL);
					}else{
						startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_M3U8_DNS_FAIL);
					}
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_DNS_use_pre = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_TS_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_KEY){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_KEY_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_MP4){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_MP4_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "mp4_DNS_use_pre = %d", usePreDns);
				}
			}
		}
		
        add_flow_log(s->app_ctx,s->url_start_status,FL_DNS_USE_PRE,usePreDns);
        add_flow_log_string(s->app_ctx,s->url_start_status,FL_TCP_CONNECTIONS, get_tcp_connection_logs(s->app_ctx,s->url_start_status));
        return AVERROR(EIO);
    }
	
	if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
		if (s->url_start_status->status_type == STATUS_TYPE_ALT){
			if(s->url_start_status->path_type==PATH_M3U8){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_finish_audio = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_use_pre_audio = %d", usePreDns);

			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_finish_audio = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre_audio = %d", usePreDns);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_finish_audio = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre_audio = %d", usePreDns);
			}
		}
		else{
			if(s->url_start_status->path_type==PATH_M3U8){
				if (s->app_ctx->pss->redirect){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_DNS_finish = %lld",av_gettime()/1000);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_redirected_DNS_use_pre = %d", usePreDns);
				}else{
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_finish = %lld",av_gettime()/1000);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_DNS_use_pre = %d", usePreDns);
				}
			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_finish = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre = %d", usePreDns);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_finish = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre = %d", usePreDns);
			}else if (s->url_start_status->path_type == PATH_MP4) {
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,"mp4_DNS_finish = %lld", av_gettime() / 1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,"mp4_DNS_use_pre = %d", usePreDns);
			}
		 }
	  }
	
    add_flow_log(s->app_ctx,s->url_start_status,FL_DNS_FINISH,av_gettime()/1000);
    add_flow_log(s->app_ctx,s->url_start_status,FL_DNS_USE_PRE,usePreDns);
    cur_ai = ai;
    first_ai = ai;

 restart:
    if (s->ipv6_port_workaround && cur_ai->ai_family == AF_INET6 && port != 0) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)cur_ai->ai_addr;
        in6->sin6_port = htons(port);
    }
    fd = ff_socket(cur_ai->ai_family,
                   cur_ai->ai_socktype,
                   cur_ai->ai_protocol);
    if (fd < 0) {
        ret = ff_neterrno();
        av_log(NULL,AV_LOG_ERROR,"fail to create fd, error=%d\n",ret);
        goto fail;
    }

    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0)
            goto fail1;
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0)
            goto fail1;
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        ret = av_application_on_tcp_will_open(s->app_ctx);
        if (ret) {
            av_log(NULL, AV_LOG_WARNING, "terminated by application in AVAPP_CTRL_WILL_TCP_OPEN");
            goto fail1;
        }
		
		if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
			if (s->url_start_status->status_type == STATUS_TYPE_ALT){
				if(s->url_start_status->path_type==PATH_M3U8){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_begin_audio = %lld",av_gettime()/1000);

				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_begin_audio = %lld",av_gettime()/1000);
				}else if (s->url_start_status->path_type==PATH_KEY){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_begin_audio = %lld", av_gettime()/1000);
				}
			}
			else{
				if(s->url_start_status->path_type==PATH_M3U8){
					if (s->app_ctx->pss->redirect){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_tcp_connect_begin = %lld",av_gettime()/1000);
					}else{
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_begin = %lld",av_gettime()/1000);
					}
				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_begin = %lld",av_gettime()/1000);
				}else if (s->url_start_status->path_type==PATH_KEY){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_begin = %lld", av_gettime()/1000);
				}else if (s->url_start_status->path_type==PATH_MP4){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "mp4_tcp_connect_begin = %lld", av_gettime()/1000);
				}
			}
		}
		
        int ipv6 = 0;
        if (cur_ai->ai_family == AF_INET6 && port != 0){
            ipv6 = 1;
        }
        
        if (ipv6) {
            struct in6_addr addr_zero;
            memset(&addr_zero, 0 , sizeof(struct in6_addr));
            struct in6_addr addr = ((struct sockaddr_in6*)cur_ai->ai_addr)->sin6_addr;
            if (memcmp(&addr, &addr_zero,sizeof(struct in6_addr))==0) {
                av_log(NULL, AV_LOG_WARNING, "dns result ip addr is empty\n");
                goto fail;
            }
        }else{
            struct in_addr addr_zero;
            memset(&addr_zero, 0 , sizeof(struct in_addr));
            struct in_addr addr = ((struct sockaddr_in*)cur_ai->ai_addr)->sin_addr;
            if (memcmp(&addr, &addr_zero,sizeof(struct in_addr))==0) {
                av_log(NULL, AV_LOG_WARNING, "dns result ip addr is empty\n");
                goto fail;
            }
        }
        
        add_flow_log(s->app_ctx,s->url_start_status,FL_TCP_CONNECT_BEGIN,av_gettime()/1000);
        int64_t timebegin = av_gettime();
    	ret = ff_listen_connect(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
    	                                     s->open_timeout / 1000, h, !!cur_ai->ai_next);
        try_connect_cnt++;
        char local_ip[64]={0};
        char peer_ip[64]={0};
        int local_port = 0;
        int peer_port = 0;
        if (ipv6) {
            struct sockaddr_in6 local_addr;
            struct sockaddr_in6 peer_addr;
            int socklen = sizeof(struct sockaddr_in6);
            getsockname(fd, (struct sockaddr_in6*)&local_addr, &socklen);
            getpeername(fd, (struct sockaddr_in6*)&peer_addr, &socklen);
            inet_ntop(AF_INET6, &local_addr.sin6_addr, local_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)cur_ai->ai_addr)->sin6_addr, peer_ip, INET6_ADDRSTRLEN);
            local_port = ntohs(local_addr.sin6_port);
            peer_port = ntohs(peer_addr.sin6_port);
        }else{
            struct sockaddr_in local_addr;
            struct sockaddr_in peer_addr;
            int socklen = sizeof(struct sockaddr);
            getsockname(fd, (struct sockaddr*)&local_addr, &socklen);
            getpeername(fd, (struct sockaddr*)&peer_addr, &socklen);
            inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &((struct sockaddr_in*)cur_ai->ai_addr)->sin_addr, peer_ip, INET_ADDRSTRLEN);
            local_port = ntohs(local_addr.sin_port);
            peer_port = ntohs(peer_addr.sin_port);
        }
        
        if (s->url_start_status && (!s->url_start_status->complete)) {
            if (s->url_start_status->status_type == STATUS_TYPE_ALT){
                startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "inet_type_audio = %d", ipv6);
            }
            else{
                startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "inet_type = %d", ipv6);
            }
        }
        
        av_log(NULL, AV_LOG_INFO, "tcp connect complete, (%s)[%s:%d]<---->[%s:%d], time=%lld, timeout=%d, rw_timeout=%d, predns=%d, ret=%d, fd=%d, try=%d, max_reconnect=%d\n",
               ipv6?"ipv6":"ipv4", local_ip, local_port, peer_ip, peer_port, (av_gettime()-timebegin)/1000, s->open_timeout/1000, s->rw_timeout/1000, usePreDns, ret, fd, try_connect_cnt, max_reconnect_count);
        
        int64_t tcp_connect_time = (av_gettime()-timebegin)/1000;
        ffg_tcp_add_info(s->app_ctx, tcp_connect_time, hostname, peer_ip);
        av_log(NULL,AV_LOG_DEBUG,"tcp connect statistic, hostname=%s, peerip=%s, escaped time=%lld, avg=[%lld, %d]\n", hostname, peer_ip, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), ffg_tcp_get_counts(s->app_ctx));
        
        add_tcp_connection_log(s->app_ctx, s->url_start_status, timebegin/1000, av_gettime()/1000, peer_ip, ret );
        if ((ret) < 0) {
            if (av_application_on_tcp_did_open(s->app_ctx, ret, fd, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), peer_ip )){
                av_log(NULL, AV_LOG_WARNING, "tcp connect fail, av_application_on_tcp_did_open failed");
                goto fail1;
            }
            
            if (ret == AVERROR_EXIT){
                av_log(NULL, AV_LOG_WARNING, "tcp connect fail, reset to use default dns\n" );
                goto fail1;
            }
            else{
                av_log(NULL, AV_LOG_WARNING, "tcp connect fail, restart to use next ip\n");
                goto fail;
            }
            
        } else {
            ret = av_application_on_tcp_did_open(s->app_ctx, 0, fd, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), peer_ip);
            if (ret) {
                av_log(NULL, AV_LOG_WARNING, "terminated by application in AVAPP_CTRL_DID_TCP_OPEN");
                goto fail1;
            }
			
			if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
				if (s->url_start_status->status_type == STATUS_TYPE_ALT){
					if(s->url_start_status->path_type==PATH_M3U8){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_finish_audio = %lld",av_gettime()/1000);

					}else if(s->url_start_status->path_type==PATH_TS){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_finish_audio = %lld",av_gettime()/1000);
					}else if(s->url_start_status->path_type==PATH_KEY){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_finish_audio = %lld",av_gettime()/1000);
					}
				}
				else{
					if(s->url_start_status->path_type==PATH_M3U8){
						if (s->app_ctx->pss->redirect){
							startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_tcp_connect_finish = %lld",av_gettime()/1000);
						}else{
							startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_finish = %lld",av_gettime()/1000);
						}
					}else if(s->url_start_status->path_type==PATH_TS){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_finish = %lld",av_gettime()/1000);
					}else if (s->url_start_status->path_type==PATH_KEY){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_finish = %lld", av_gettime()/1000);
					}else if (s->url_start_status->path_type==PATH_MP4){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "mp4_tcp_connect_finish = %lld", av_gettime()/1000);
					}
				}
			}
            
            add_flow_log(s->app_ctx,s->url_start_status,FL_TCP_CONNECT_FINISH,av_gettime()/1000);
        }
    }

    h->is_streamed = 1;
    s->fd = fd;
    
    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }

    freeaddrinfo(ai);
    add_flow_log_string(s->app_ctx,s->url_start_status,FL_TCP_CONNECTIONS,get_tcp_connection_logs(s->app_ctx,s->url_start_status));
    return 0;

 fail:
    if (fd >= 0){
        closesocket(fd);
        fd = -1;
    }
    if (cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        ret = 0;
        goto restart;
    }
    
    //if preDns fail try getdns by domain, do that again
    if (usePreDns == 1&& !(ff_check_interrupt(&h->interrupt_callback))) {
        usePreDns = 0;
        av_log(NULL, AV_LOG_INFO, "use predns socket failed ");
        goto resetDNS;
    }
fail1:
    if (fd >= 0){
        closesocket(fd);
        fd = -1;
    }
    if (--max_reconnect_count > 0) {
        cur_ai = first_ai;
        av_log(NULL, AV_LOG_WARNING, "fail to connet all ip, try connect again, left=%d\n", max_reconnect_count);
        goto restart;
    }
	
	if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
		if (s->url_start_status->status_type == STATUS_TYPE_ALT){
			if(s->url_start_status->path_type==PATH_M3U8){
				 startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d",ERROR_M3U8_TCP_CONNECT_FAIL);
				 startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret);
				 startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count_audio = %d", try_connect_cnt);

			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", ERROR_TS_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count_audio = %d", try_connect_cnt);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", ERROR_KEY_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count_audio = %d", try_connect_cnt);
			}
		}
		else{
			if(s->url_start_status->path_type==PATH_M3U8){
				if (s->app_ctx->pss->redirect) {
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_REDIRECTED_M3U8_TCP_CONNECT_FAIL);
				}else{
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_M3U8_TCP_CONNECT_FAIL);
				}
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_TS_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}else if(s->url_start_status->path_type==PATH_MP4){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_MP4_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}
		}
	}
	
    add_flow_log_string(s->app_ctx,s->url_start_status,FL_TCP_CONNECTIONS,get_tcp_connection_logs(s->app_ctx,s->url_start_status));
    freeaddrinfo(ai);
    return ret;
}
/* return non zero if error */
static int tcp_open(URLContext *h, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai, *cur_ai, *first_ai;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    int try_connect_cnt = 0;
    const char *p;
    char buf[256];
    int ret;
    char portstr[10];
    s->app_ctx = (AVApplicationContext *)(intptr_t)s->app_ctx_intptr;
	s->url_start_status = (URLStartStatus *)(intptr_t)s->url_start_status_intptr;
    int max_reconnect_count = s->reconnect_count;
    
    char hostname[1024],proto[1024],path[1024];
    AVAppTcpIOControl control = {0};
    DnsCacheEntry *dns_entry = NULL;

    if (s->open_timeout < 0) {
        s->open_timeout = 15000000;
    }

    s->app_ctx = (AVApplicationContext *)av_dict_strtoptr(s->app_ctx_intptr);

    if (s->fastopen) {
        s->tcp_connected = 0;
        strcpy(s->uri, uri);
        return 0;
    }

    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
                 &port, path, sizeof(path), uri);
    
    if (strcmp(proto, "tcp"))
	{
        return AVERROR(EINVAL);
    }
    if (port <= 0 || port >= 65536) 
	{
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    
    //reset tcp read timeout to fix bug of long time loading
    int64_t read_timeout = 0;
    if ( 0==ff_get_player_option_int(s->app_ctx,"timeout", &read_timeout) && read_timeout > 0)
	{
        s->rw_timeout = read_timeout;
    }
    
    if (s->rw_timeout >= 0) 
	{
        //s->open_timeout =
        h->rw_timeout = s->rw_timeout;
    }
    
    if(s->app_ctx && s->app_ctx->pre_dns->pre_dns_on)
    	return tcp_open_use_pre_dns(h, uri, flags);

    //////////////////////////
    p = strchr(uri, '?');
    if (p) 
	{
        if (av_find_info_tag(buf, sizeof(buf), "listen", p)) 
		{
            char *endptr = NULL;
            s->listen = strtol(buf, &endptr, 10);
            /* assume if no digits were found it is a request to enable it */
            if (buf == endptr)
                s->listen = 1;
        }
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) 
		{
            s->rw_timeout = strtol(buf, NULL, 10);
            if (s->rw_timeout >= 0) {
                s->open_timeout = s->rw_timeout;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) 
		{
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0 ) 
	{
        h->rw_timeout = s->rw_timeout;
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;

    if (s->dns_cache_timeout > 0) 
	{
        if (s->dns_cache_clear) 
		{
            av_log(NULL, AV_LOG_INFO, "will delete dns cache entry, uri = %s\n", uri);
            remove_dns_cache_entry(uri);
        } else 
		{
            dns_entry = get_dns_cache_reference(uri);
        }
	}
    init_tcp_connection_logs(s->app_ctx,s->url_start_status);
	
	if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) 
	{
		if (s->url_start_status->status_type == STATUS_TYPE_ALT)
		{
			if(s->url_start_status->path_type==PATH_M3U8)
			{
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_begin_audio = %lld",av_gettime()/1000);

			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_begin_audio = %lld",av_gettime()/1000);
			}else if(s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_begin_audio = %lld",av_gettime()/1000);
			}
		}
		else{
			if(s->url_start_status->path_type==PATH_M3U8){
				if (s->app_ctx->pss->redirect){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_DNS_begin = %lld",av_gettime()/1000);
				}else{
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_begin = %lld",av_gettime()/1000);
				}
			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_begin = %lld",av_gettime()/1000);
			}else if(s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_begin = %lld",av_gettime()/1000);
			}else if (s->url_start_status->path_type == PATH_MP4) {
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,"mp4_DNS_begin = %lld", av_gettime() / 1000);
			}	
		}
    }
	
    add_flow_log(s->app_ctx,s->url_start_status,FL_DNS_BEGIN,av_gettime()/1000);
    
    
    int64_t dns_begin = av_gettime()/1000;
	/////////////////////
#ifdef HAVE_PTHREADS
    ret = ijk_tcp_getaddrinfo_nonblock(hostname, portstr, &hints, &ai, s->addrinfo_timeout, &h->interrupt_callback, s->addrinfo_one_by_one);
#else
    if (s->addrinfo_timeout > 0)
        av_log(h, AV_LOG_WARNING, "Ignore addrinfo_timeout without pthreads support.\n");
    if (!hostname[0])
        ret = getaddrinfo(NULL, portstr, &hints, &ai);
    else
        ret = getaddrinfo(hostname, portstr, &hints, &ai);
#endif
    
    int64_t dns_time = (av_gettime()/1000-dns_begin);
    if (ret==0) {
        ffg_dns_add_info(s->app_ctx, dns_time, hostname);
        av_application_on_dns_statistic(s->app_ctx, 0, hostname, dns_time, ffg_dns_get_avgtime(s->app_ctx));
    }
        
    int usePreDns = 0;
    if (ret) {
		
		if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
			if (s->url_start_status->status_type == STATUS_TYPE_ALT){
				if(s->url_start_status->path_type==PATH_M3U8){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d",ERROR_M3U8_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_DNS_use_pre_audio = %d", usePreDns);

				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d",ERROR_TS_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre_audio = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_KEY){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d",ERROR_KEY_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre_audio = %d", usePreDns);
				}
			}
			else{
				if(s->url_start_status->path_type==PATH_M3U8){
					if (s->app_ctx->pss->redirect) {
						startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_REDIRECTED_M3U8_DNS_FAIL);
					}else{
						startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_M3U8_DNS_FAIL);
					}
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_DNS_use_pre = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_TS_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_KEY){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_KEY_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre = %d", usePreDns);
				}else if(s->url_start_status->path_type==PATH_MP4){
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_MP4_DNS_FAIL);
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d",ret);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "mp4_DNS_use_pre = %d", usePreDns);
				}
			}
		}
		
        add_flow_log_string(s->app_ctx,s->url_start_status,FL_TCP_CONNECTIONS, get_tcp_connection_logs(s->app_ctx,s->url_start_status));
        return AVERROR(EIO);
    }
	
	if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
		if (s->url_start_status->status_type == STATUS_TYPE_ALT){
			if(s->url_start_status->path_type==PATH_M3U8){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_finish_audio = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_use_pre_audio = %d", usePreDns);

			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_finish_audio = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre_audio = %d", usePreDns);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_finish_audio = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre_audio = %d", usePreDns);
			}
		}
		else{
			if(s->url_start_status->path_type==PATH_M3U8){
				if (s->app_ctx->pss->redirect){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_DNS_finish = %lld",av_gettime()/1000);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_redirected_DNS_use_pre = %d", usePreDns);
				}else{
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_DNS_finish = %lld",av_gettime()/1000);
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "m3u8_DNS_use_pre = %d", usePreDns);
				}
			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_DNS_finish = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "ts_DNS_use_pre = %d", usePreDns);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_DNS_finish = %lld",av_gettime()/1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,  "key_DNS_use_pre = %d", usePreDns);
			}else if (s->url_start_status->path_type == PATH_MP4) {
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,"mp4_DNS_finish = %lld", av_gettime() / 1000);
				startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP,"mp4_DNS_use_pre = %d", usePreDns);
			}
		}
	}

    add_flow_log(s->app_ctx,s->url_start_status,FL_DNS_FINISH,av_gettime()/1000);
    cur_ai = ai;
    first_ai = ai;
    
 restart:
    if (s->ipv6_port_workaround && cur_ai->ai_family == AF_INET6 && port != 0) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)cur_ai->ai_addr;
        in6->sin6_port = htons(port);
    }
    fd = ff_socket(cur_ai->ai_family,
                   cur_ai->ai_socktype,
                   cur_ai->ai_protocol);
    if (fd < 0) {
        ret = ff_neterrno();
        goto fail;
    }

    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }
    if (s->tcp_nodelay > 0) {
        setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &s->tcp_nodelay, sizeof (s->tcp_nodelay));
    }

    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0)
            goto fail1;
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0)
            goto fail1;
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        ret = av_application_on_tcp_will_open(s->app_ctx);
        if (ret) {
            av_log(NULL, AV_LOG_WARNING, "terminated by application in AVAPP_CTRL_WILL_TCP_OPEN");
            goto fail1;
        }
		
		if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
			if (s->url_start_status->status_type == STATUS_TYPE_ALT){
				if(s->url_start_status->path_type==PATH_M3U8){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_begin_audio = %lld",av_gettime()/1000);

				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_begin_audio = %lld",av_gettime()/1000);
				}else if (s->url_start_status->path_type==PATH_KEY){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_begin_audio = %lld", av_gettime()/1000);
				}
			}
			else{
				if(s->url_start_status->path_type==PATH_M3U8){
					if (s->app_ctx->pss->redirect){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_tcp_connect_begin = %lld",av_gettime()/1000);
					}else{
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_begin = %lld",av_gettime()/1000);
					}
				}else if(s->url_start_status->path_type==PATH_TS){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_begin = %lld",av_gettime()/1000);
				}else if (s->url_start_status->path_type==PATH_KEY){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_begin = %lld", av_gettime()/1000);
				}else if (s->url_start_status->path_type==PATH_MP4){
					startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "mp4_tcp_connect_begin = %lld", av_gettime()/1000);
				}
			}
		}
        
        int ipv6 = 0;
        if (cur_ai->ai_family == AF_INET6 && port != 0){
            ipv6 = 1;
        }
        
        if (ipv6) {
            struct in6_addr addr_zero;
            memset(&addr_zero, 0 , sizeof(struct in6_addr));
            struct in6_addr addr = ((struct sockaddr_in6*)cur_ai->ai_addr)->sin6_addr;
            if (memcmp(&addr, &addr_zero,sizeof(struct in6_addr))==0) {
                av_log(NULL, AV_LOG_WARNING, "dns result ip addr is empty\n");
                goto fail;
            }
        }else{
            struct in_addr addr_zero;
            memset(&addr_zero, 0 , sizeof(struct in_addr));
            struct in_addr addr = ((struct sockaddr_in*)cur_ai->ai_addr)->sin_addr;
            if (memcmp(&addr, &addr_zero,sizeof(struct in_addr))==0) {
                av_log(NULL, AV_LOG_WARNING, "dns result ip addr is empty\n");
                goto fail;
            }
        }
        
        add_flow_log(s->app_ctx,s->url_start_status,FL_TCP_CONNECT_BEGIN,av_gettime()/1000);
        int64_t timebegin = av_gettime();
    	ret = ff_listen_connect(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
    	                                     s->open_timeout / 1000, h, !!cur_ai->ai_next);
        try_connect_cnt++;
        char local_ip[64]={0};
        char peer_ip[64]={0};
        int local_port = 0;
        int peer_port = 0;
        if (ipv6) {
            struct sockaddr_in6 local_addr;
            struct sockaddr_in6 peer_addr;
            int socklen = sizeof(struct sockaddr_in6);
            getsockname(fd, (struct sockaddr_in6*)&local_addr, &socklen);
            getpeername(fd, (struct sockaddr_in6*)&peer_addr, &socklen);
            inet_ntop(AF_INET6, &local_addr.sin6_addr, local_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)cur_ai->ai_addr)->sin6_addr, peer_ip, INET6_ADDRSTRLEN);
            local_port = ntohs(local_addr.sin6_port);
            peer_port = ntohs(peer_addr.sin6_port);
        }else{
            struct sockaddr_in local_addr;
            struct sockaddr_in peer_addr;
            int socklen = sizeof(struct sockaddr);
            getsockname(fd, (struct sockaddr*)&local_addr, &socklen);
            getpeername(fd, (struct sockaddr*)&peer_addr, &socklen);
            inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &((struct sockaddr_in*)cur_ai->ai_addr)->sin_addr, peer_ip, INET_ADDRSTRLEN);
            local_port = ntohs(local_addr.sin_port);
            peer_port = ntohs(peer_addr.sin_port);
        }
        
        if (s->url_start_status && (!s->url_start_status->complete)) {
            if (s->url_start_status->status_type == STATUS_TYPE_ALT){
                startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "inet_type_audio = %d", ipv6);
            }
            else{
                startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "inet_type = %d", ipv6);
            }
        }
        av_log(NULL, AV_LOG_INFO, "tcp connect complete, (%s)[%s:%d]<---->[%s:%d], time=%lld, timeout=%d, ret=%d, fd=%d, try=%d, max_reconnect=%d\n",
               ipv6?"ipv6":"ipv4", local_ip, local_port, peer_ip, peer_port, (av_gettime()-timebegin)/1000, s->open_timeout/1000, ret, fd, try_connect_cnt, max_reconnect_count);

        int64_t tcp_connect_time = (av_gettime()-timebegin)/1000;
        ffg_tcp_add_info(s->app_ctx, tcp_connect_time, hostname, peer_ip);
        av_log(NULL,AV_LOG_DEBUG,"tcp connect statistic, hostname=%s, peerip=%s, escaped time=%lld, avg=[%lld, %d]\n", hostname, peer_ip, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), ffg_tcp_get_counts(s->app_ctx));
        
        add_tcp_connection_log(s->app_ctx, s->url_start_status, timebegin/1000, av_gettime()/1000, peer_ip, ret );
        if ((ret) < 0) {
            if (av_application_on_tcp_did_open(s->app_ctx, ret, fd, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), peer_ip))
                goto fail1;
            if (ret == AVERROR_EXIT)
                goto fail1;
            else
                goto fail;
        } else {
            if (ret == 0) {
                s->fastopen_success = 0;
            } else {
                s->fastopen_success = 1;
            }
            ret = av_application_on_tcp_did_open(s->app_ctx, 0, fd, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), peer_ip);
            if (ret) {
                av_log(NULL, AV_LOG_WARNING, "terminated by application in AVAPP_CTRL_DID_TCP_OPEN");
                goto fail1;
            } 
	
			
			if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
				if (s->url_start_status->status_type == STATUS_TYPE_ALT){
					if(s->url_start_status->path_type==PATH_M3U8){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_finish_audio = %lld",av_gettime()/1000);

					}else if(s->url_start_status->path_type==PATH_TS){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_finish_audio = %lld",av_gettime()/1000);
					}else if(s->url_start_status->path_type==PATH_KEY){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_finish_audio = %lld",av_gettime()/1000);
					}
				}
				else{
					if(s->url_start_status->path_type==PATH_M3U8){
						if (s->app_ctx->pss->redirect){
							startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_redirected_tcp_connect_finish = %lld",av_gettime()/1000);
						}else{
							startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "m3u8_tcp_connect_finish = %lld",av_gettime()/1000);
						}
					}else if(s->url_start_status->path_type==PATH_TS){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "ts_tcp_connect_finish = %lld",av_gettime()/1000);
					}else if (s->url_start_status->path_type==PATH_KEY){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "key_tcp_connect_finish = %lld", av_gettime()/1000);
					}else if (s->url_start_status->path_type==PATH_MP4){
						startimes_start_log(s->app_ctx, STAR_TIME_LOG_TCP, "mp4_tcp_connect_finish = %lld", av_gettime()/1000);
					}
				}
			}
            
            add_flow_log(s->app_ctx,s->url_start_status,FL_TCP_CONNECT_FINISH,av_gettime()/1000);
        }
    }

    h->is_streamed = 1;
    s->fd = fd;


  
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }

    freeaddrinfo(ai);
    av_log(NULL, AV_LOG_DEBUG, "chenwq: tcp open complete mode=%s, fd=%d\n", h->flags&AVIO_FLAG_NONBLOCK?"nonblock":"blocked",fd );
    add_flow_log_string(s->app_ctx,s->url_start_status,FL_TCP_CONNECTIONS, get_tcp_connection_logs(s->app_ctx,s->url_start_status));
    return 0;

 fail:
    if (fd >= 0){
        closesocket(fd);
        fd = -1;
    }
    if (cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        ret = 0;
        goto restart;
    }
 fail1:
    if (fd >= 0)
        closesocket(fd);
    if (--max_reconnect_count>0)
    {
        cur_ai = first_ai;
        av_log(NULL, AV_LOG_WARNING, "fail to connet all ip, try connect again, left=%d\n", max_reconnect_count);
        goto restart;
    }
	
	if (s->app_ctx && s->url_start_status && (!s->url_start_status->complete)) {
		if (s->url_start_status->status_type == STATUS_TYPE_ALT){
			if(s->url_start_status->path_type==PATH_M3U8){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d",ERROR_M3U8_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count_audio = %d", try_connect_cnt);

			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", ERROR_TS_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count_audio = %d", try_connect_cnt);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_audio = %d", ERROR_KEY_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex_audio = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count_audio = %d", try_connect_cnt);
			}
		}
		else{
			if(s->url_start_status->path_type==PATH_M3U8){
				if (s->app_ctx->pss->redirect) {
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_REDIRECTED_M3U8_TCP_CONNECT_FAIL);
				}else{
					startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d",ERROR_M3U8_TCP_CONNECT_FAIL);
				}
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}else if(s->url_start_status->path_type==PATH_TS){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_TS_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}else if (s->url_start_status->path_type==PATH_KEY){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_KEY_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}else if(s->url_start_status->path_type==PATH_MP4){
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code = %d", ERROR_MP4_TCP_CONNECT_FAIL);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_code_ex = %d", ret);
				startimes_error_log(s->app_ctx, STAR_TIME_LOG_MAIN, "error_tcp_count = %d", try_connect_cnt);
			}
		}
	}
	
    add_flow_log_string(s->app_ctx,s->url_start_status,FL_TCP_CONNECTIONS, get_tcp_connection_logs(s->app_ctx,s->url_start_status));
    freeaddrinfo(ai);
    return ret;
}

/* return non zero if error */
static int tcp_fast_open(URLContext *h, const char *http_request, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai, *cur_ai;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
    AVAppTcpIOControl control = {0};
    DnsCacheEntry *dns_entry = NULL;
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp"))
        return AVERROR(EINVAL);
    if (port <= 0 || port >= 65536) {
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');

    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "listen", p)) {
            char *endptr = NULL;
            s->listen = strtol(buf, &endptr, 10);
            /* assume if no digits were found it is a request to enable it */
            if (buf == endptr)
                s->listen = 1;
        }
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtol(buf, NULL, 10);
            if (s->rw_timeout >= 0) {
                s->open_timeout = s->rw_timeout;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0 ) {
        h->rw_timeout = s->rw_timeout;
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;

    if (s->dns_cache_timeout > 0) {
        if (s->dns_cache_clear) {
            av_log(NULL, AV_LOG_INFO, "will delete dns cache entry, uri = %s\n", uri);
            remove_dns_cache_entry(uri);
        } else {
            dns_entry = get_dns_cache_reference(uri);
        }
    }

    if (!dns_entry) {
#ifdef HAVE_PTHREADS
        ret = ijk_tcp_getaddrinfo_nonblock(hostname, portstr, &hints, &ai, s->addrinfo_timeout, &h->interrupt_callback, s->addrinfo_one_by_one);
#else
        if (s->addrinfo_timeout > 0)
            av_log(h, AV_LOG_WARNING, "Ignore addrinfo_timeout without pthreads support.\n");
        if (!hostname[0])
            ret = getaddrinfo(NULL, portstr, &hints, &ai);
        else
            ret = getaddrinfo(hostname, portstr, &hints, &ai);
#endif

        if (ret) {
            av_log(h, AV_LOG_ERROR,
                "Failed to resolve hostname %s: %s\n",
                hostname, gai_strerror(ret));
            return AVERROR(EIO);
        }

        cur_ai = ai;
    } else {
        av_log(NULL, AV_LOG_INFO, "hit dns cache uri = %s\n", uri);
        cur_ai = dns_entry->res;
    }

 restart:
#if HAVE_STRUCT_SOCKADDR_IN6
    // workaround for IOS9 getaddrinfo in IPv6 only network use hardcode IPv4 address can not resolve port number.
    if (cur_ai->ai_family == AF_INET6){
        struct sockaddr_in6 * sockaddr_v6 = (struct sockaddr_in6 *)cur_ai->ai_addr;
        if (!sockaddr_v6->sin6_port){
            sockaddr_v6->sin6_port = htons(port);
        }
    }
#endif
    fd = ff_socket(cur_ai->ai_family,
                   cur_ai->ai_socktype,
                   cur_ai->ai_protocol);
    if (fd < 0) {
        ret = ff_neterrno();
        goto fail;
    }
    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }
	int64_t timebegin = av_gettime();
    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0)
            goto fail1;
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0)
            goto fail1;
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        ret = av_application_on_tcp_will_open(s->app_ctx);
		char peer_ip[64]={0};
		int64_t tcp_connect_time = (av_gettime()-timebegin)/1000;
        if (ret) {
            av_log(NULL, AV_LOG_WARNING, "terminated by application in AVAPP_CTRL_WILL_TCP_OPEN");
            goto fail1;
        }

        if ((ret = ff_sendto(fd, http_request, strlen(http_request), FAST_OPEN_FLAG,
                 cur_ai->ai_addr, cur_ai->ai_addrlen, s->open_timeout / 1000, h, !!cur_ai->ai_next)) < 0) {
            s->fastopen_success = 0;
            if (av_application_on_tcp_did_open(s->app_ctx, 0, fd, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), peer_ip ))
                goto fail1;
            if (ret == AVERROR_EXIT)
                goto fail1;
            else
                goto fail;
        } else {
            if (ret == 0) {
                s->fastopen_success = 0;
            } else {
                s->fastopen_success = 1;
            }
			
			ret = av_application_on_tcp_did_open(s->app_ctx, 0, fd, tcp_connect_time, ffg_tcp_get_avgtime(s->app_ctx), peer_ip );
            if (ret) {
                av_log(NULL, AV_LOG_WARNING, "terminated by application in AVAPP_CTRL_DID_TCP_OPEN");
                goto fail1;
            } else if (!dns_entry && !strstr(uri, control.ip) && s->dns_cache_timeout > 0) {
                add_dns_cache_entry(uri, cur_ai, s->dns_cache_timeout);
                av_log(NULL, AV_LOG_INFO, "add dns cache uri = %s, ip = %s\n", uri , control.ip);
            }
            av_log(NULL, AV_LOG_INFO, "tcp did open uri = %s, ip = %s\n", uri , control.ip);
        }
    }

    h->is_streamed = 1;
    s->fd = fd;

    if (dns_entry) {
        release_dns_cache_reference(uri, &dns_entry);
    } else {
        freeaddrinfo(ai);
    }
    return 0;

 fail:
    if (cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        if (fd >= 0)
            closesocket(fd);
        ret = 0;
        goto restart;
    }
 fail1:
    if (fd >= 0)
        closesocket(fd);

    if (dns_entry) {
        av_log(NULL, AV_LOG_ERROR, "hit dns cache but connect fail uri = %s, ip = %s\n", uri , control.ip);
        release_dns_cache_reference(uri, &dns_entry);
        remove_dns_cache_entry(uri);
    } else {
        freeaddrinfo(ai);
    }

    return ret;
}

static int tcp_accept(URLContext *s, URLContext **c)
{
    TCPContext *sc = s->priv_data;
    TCPContext *cc;
    int ret;
    av_assert0(sc->listen);
    if ((ret = ffurl_alloc(c, s->filename, s->flags, &s->interrupt_callback)) < 0)
        return ret;
    cc = (*c)->priv_data;
    ret = ff_accept(sc->fd, sc->listen_timeout, s);
    if (ret < 0)
        return ff_neterrno();
    cc->fd = ret;
    return 0;
}

static int tcp_read(URLContext *h, uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;
    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 0, h->rw_timeout, &h->interrupt_callback);
        if (ret){
            if(ret==AVERROR(ETIMEDOUT)){
                add_tcp_rwtimeout_log_end(s->app_ctx,s->url_start_status,"timeout",av_gettime()/1000 );
                av_log(NULL, AV_LOG_WARNING, "tcp read wait timeout, rw_timeout=%lld\n", h->rw_timeout );
            }
            else{
                av_log(NULL, AV_LOG_WARNING, "tcp read wait fail, rw_timeout=%lld\n", h->rw_timeout );
            }
            add_flow_log(s->app_ctx,s->url_start_status,FL_TCP_READ_ERROR, ret);
            return ret;
        }
    }
    ret = recv(s->fd, buf, size, 0);
    if (ret == 0)
        return AVERROR_EOF;
    if (ret > 0){
         av_log(NULL, AV_LOG_TRACE, "chenwq: tcp recv data, recv=%d, size=%d, fd=%d\n", ret, size, s->fd);
         av_application_did_io_tcp_read(s->app_ctx, (void*)h, ret);
    }else if(ret < 0){
         add_flow_log(s->app_ctx,s->url_start_status,FL_TCP_READ_ERROR, ff_neterrno());
		 av_log(NULL, AV_LOG_ERROR, "tcp read failed, ret=%d\n", ret);
	}
    
    return ret < 0 ? ff_neterrno() : ret;
}

static int tcp_write(URLContext *h, const uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 1, h->rw_timeout, &h->interrupt_callback);
        if (ret) {
            if (ret == AVERROR(ETIMEDOUT)) {
                ret = AVERROR_TCP_WRITE_TIMEOUT;
            }
            return ret;
        }
    }

    if (s->fastopen && !s->tcp_connected && av_stristart(buf, "GET", NULL)) {
        ret = tcp_fast_open(h, buf, s->uri, 0);
        if (!ret) {
            s->tcp_connected = 1;
            if (!s->fastopen_success) {
                ret = send(s->fd, buf, size, MSG_NOSIGNAL);
                if (ret > 0) {
                    s->fastopen_success = 1;
                }
                return ret < 0 ? ff_neterrno() : ret;
            }
            return ret;
        } else {
            av_log(NULL, AV_LOG_WARNING, "tcp_fast_open is error ret = %d\n", ret);
            return ret;
        }
    }

    ret = send(s->fd, buf, size, MSG_NOSIGNAL);

    return ret < 0 ? ff_neterrno() : ret;
}

static int tcp_shutdown(URLContext *h, int flags)
{
    TCPContext *s = h->priv_data;
    int how;

    if (flags & AVIO_FLAG_WRITE && flags & AVIO_FLAG_READ) {
        how = SHUT_RDWR;
    } else if (flags & AVIO_FLAG_WRITE) {
        how = SHUT_WR;
    } else {
        how = SHUT_RD;
    }

    return shutdown(s->fd, how);
}

static int tcp_close(URLContext *h)
{
    TCPContext *s = h->priv_data;
    closesocket(s->fd);
    return 0;
}

static int tcp_get_file_handle(URLContext *h)
{
    TCPContext *s = h->priv_data;
    return s->fd;
}

static int tcp_get_window_size(URLContext *h)
{
    TCPContext *s = h->priv_data;
    int avail;
    socklen_t avail_len = sizeof(avail);

#if HAVE_WINSOCK2_H
    /* SO_RCVBUF with winsock only reports the actual TCP window size when
    auto-tuning has been disabled via setting SO_RCVBUF */
    if (s->recv_buffer_size < 0) {
        return AVERROR(ENOSYS);
    }
#endif

    if (getsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &avail, &avail_len)) {
        return ff_neterrno();
    }
    return avail;
}

const URLProtocol ff_tcp_protocol = {
    .name                = "tcp",
    .url_open            = tcp_open,
    .url_accept          = tcp_accept,
    .url_read            = tcp_read,
    .url_write           = tcp_write,
    .url_close           = tcp_close,
    .url_get_file_handle = tcp_get_file_handle,
    .url_get_short_seek  = tcp_get_window_size,
    .url_shutdown        = tcp_shutdown,
    .priv_data_size      = sizeof(TCPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &tcp_class,
};
