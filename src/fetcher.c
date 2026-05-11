/*
 * Fetcher: receives (ip,port) from SYN scan, does HTTP GET,
 * finds <script> tags, fetches JS, runs greyhat scanner.
 */
#include "fetcher.h"
#include "verifier.h"
#include "util-malloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

static uint64_t s_pages = 0, s_scripts = 0, s_gzip = 0, s_html = 0;
static uint64_t s_script_tags = 0, s_js_fetched = 0, s_cdn = 0, s_dnsfail = 0;

uint64_t total_keys_found = 0;
uint64_t total_potential_keys = 0;
uint64_t total_sites_checked = 0;
uint64_t total_html_sites = 0;
uint64_t last_html_time = 0;

static const char *cdn[] = {
    "cloudflare.com","googleapis.com","googletagmanager.com","google-analytics.com",
    "jsdelivr.net","unpkg.com","cdn.jsdelivr.net","cdnjs.cloudflare.com",
    "ajax.googleapis.com","code.jquery.com","stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com","bootcdn.net","cdn.bootcss.com",
    "polyfill.io","facebook.net","connect.facebook.net",
    "twimg.com","platform.twitter.com","assets.adobedtm.com",
    "hotjar.com","static.hotjar.com",NULL
};
static int is_cdn_url(const char *u) {
    for (int i=0; cdn[i]; i++) if (strstr(u,cdn[i])) return 1;
    return 0;
}

/* Safe case-insensitive strstr for non-null-terminated buffers */
static const char *safe_casestrn(const unsigned char *haystack, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle);
    if (hlen < nlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j;
        for (j = 0; j < nlen; j++) {
            if (tolower(haystack[i+j] & 0xFF) != tolower((unsigned char)needle[j])) break;
        }
        if (j == nlen) return (const char*)(haystack + i);
    }
    return NULL;
}

#define QSIZE 8192
#define FETCHER_THROTTLE_THRESHOLD 4096
#define FETCHER_THROTTLE_THRESHOLD 10000 /* slow SYN scan if fetcher queue exceeds this */
struct Job { char ip[64]; unsigned port; };
static struct Job q[QSIZE];
static int qh=0, qt=0, qc=0, running=0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cnd = PTHREAD_COND_INITIALIZER;
static pthread_t *thr = NULL;
static int nthreads = 0;
static int configured_tpc = 0; /* 0 = auto (16) */

static unsigned char *grab(const char *u, size_t *len) {
    char c[2048];
    snprintf(c,sizeof(c),"/usr/bin/curl -s -L -m 4 --connect-timeout 2 -A 'ZorpInvader/1.0' \"%s\" 2>/dev/null", u);
    FILE *f = popen(c,"r");
    if (!f) return NULL;
    size_t cap=131072, tot=0;
    unsigned char *b = malloc(cap);
    if (!b) { pclose(f); return NULL; }
    int n;
    while ((n=fread(b+tot,1,cap-tot-1,f))>0) {
        tot+=n;
        if (tot>cap-8192) {
            cap*=2;
            unsigned char *nb = realloc(b,cap);
            if (!nb) { free(b); pclose(f); return NULL; }
            b=nb;
        }
    }
    pclose(f);
    if (!tot) { free(b); return NULL; }
    b[tot]=0;
    *len=tot;
    return b;
}

static char *resolve_url(const char *ip, unsigned port, const char *src) {
    size_t l=strlen(src);
    char *u=malloc(512+l);
    if (src[0]=='/') snprintf(u,512+l,"http://%s:%u%s",ip,port,src);
    else if (strstr(src,"://")) strncpy(u,src,512+l-1);
    else snprintf(u,512+l,"http://%s:%u/%s",ip,port,src);
    return u;
}

static void process_html(const char *ip, unsigned port, const unsigned char *html, size_t len) {
    if (!html || len<16) return;

    /* Reject binary content: check for null bytes in first 4KB */
    for (size_t i=0; i<len && i<4096; i++) {
        if (html[i]==0) return;
    }

    s_pages++;
    __sync_add_and_fetch(&total_sites_checked,1);
    __sync_add_and_fetch(&total_html_sites,1);
    last_html_time=(uint64_t)time(0);

    /* Check for HTML markers */
    int has_html = 0;
    if (safe_casestrn(html, len, "<script")) has_html = 1;
    else if (safe_casestrn(html, len, "<html")) has_html = 1;
    else if (safe_casestrn(html, len, "<body")) has_html = 1;
    else if (safe_casestrn(html, len, "<head")) has_html = 1;
    if (has_html) s_html++;

    /* Build ipaddress */
    ipaddress ia; memset(&ia,0,sizeof(ia));
    const char *x=ip;
    unsigned a=(unsigned)strtoul(x,(char**)&x,10); x++;
    unsigned b=(unsigned)strtoul(x,(char**)&x,10); x++;
    unsigned c_=(unsigned)strtoul(x,(char**)&x,10); x++;
    unsigned d=(unsigned)strtoul(x,NULL,10);
    ia.ipv4=(a<<24)|(b<<16)|(c_<<8)|d;

    /* Scan full HTML for inline keys */
    greyhat_scan(ia, html, (unsigned)len);

    /* Find <script src="..."> tags using safe_casestrn */
    const char *p=(const char*)html;
    int cnt=0;
    while (cnt<10) {
        const char *tag = safe_casestrn((const unsigned char*)p, len-(p-(const char*)html), "<script");
        if (!tag) break;
        s_script_tags++;
        p = tag + 7;

        /* Find closing > */
        const char *end = memchr(p, '>', len-(p-(const char*)html));
        if (!end) break;

        /* Look for src= within this tag */
        const char *src = safe_casestrn((const unsigned char*)p, end-p, "src");
        if (src && src < end) {
            src += 3;
            while (src < end && (*src==' ' || *src=='\t')) src++;
            if (src < end && *src == '=') src++;
            while (src < end && (*src==' ' || *src=='\t')) src++;
            if (src < end && (*src=='"' || *src=='\'')) {
                char q = *src++;
                const char *ce = memchr(src, q, end-src);
                if (ce) {
                    int sl = (int)(ce-src);
                    char sb[512];
                    int cl = sl<511 ? sl : 511;
                    memcpy(sb, src, cl);
                    sb[cl] = 0;

                    char *url = resolve_url(ip, port, sb);
                    if (!is_cdn_url(url)) {
                        size_t jl = 0;
                        unsigned char *js = grab(url, &jl);
                        if (js) {
                            s_js_fetched++;
                            s_scripts++;
                            greyhat_scan(ia, js, (unsigned)jl);
                            free(js);
                        } else s_dnsfail++;
                    } else s_cdn++;
                    free(url);
                    cnt++;
                }
            }
        }
        p = end;
    }
}

static void *worker(void *arg) {
    (void)arg;
    while (running || qc>0) {
        pthread_mutex_lock(&mtx);
        while (qc==0 && running) pthread_cond_wait(&cnd,&mtx);
        if (!running && qc==0) { pthread_mutex_unlock(&mtx); break; }
        struct Job j=q[qh]; qh=(qh+1)%QSIZE; qc--;
        pthread_mutex_unlock(&mtx);
        char u[256]; snprintf(u,sizeof(u),"http://%s:%u/",j.ip,j.port);
        size_t l=0;
        unsigned char *h=grab(u,&l);
        if (h && l>0) { process_html(j.ip,j.port,h,l); free(h); }
        else if (h) free(h);
    }
    return NULL;
}

void fetcher_submit(const char *ip, unsigned port) {
    struct Job j;
    strncpy(j.ip,ip,63); j.ip[63]=0;
    j.port=port;
    pthread_mutex_lock(&mtx);
    if (qc>=QSIZE) { qh=(qh+1)%QSIZE; qc--; }
    q[qt]=j; qt=(qt+1)%QSIZE; qc++;
    if (qc>256) pthread_cond_broadcast(&cnd); else pthread_cond_signal(&cnd);
    pthread_mutex_unlock(&mtx);
}

void fetcher_set_tpc(int tpc) { configured_tpc = tpc; }

void fetcher_init(void) {
    int nc=sysconf(_SC_NPROCESSORS_ONLN);
    if (nc<1) nc=4;
    int tpc = configured_tpc ? configured_tpc : 16;
    nthreads=nc*tpc; if (nthreads>32) nthreads=32; /* cap to avoid curl fork bomb */
    thr=malloc(sizeof(pthread_t)*nthreads);
    running=1;
    for (int i=0;i<nthreads;i++) pthread_create(&thr[i],NULL,worker,NULL);
    fprintf(stderr,"[fetcher] %d workers on %d cores\n",nthreads,nc);
}

void fetcher_shutdown(void) {
    running=0;
    pthread_cond_broadcast(&cnd);
    for (int i=0;i<nthreads;i++) pthread_join(thr[i],NULL);
    free(thr);
}

uint64_t fetcher_pages_fetched(void) { return s_pages; }
uint64_t fetcher_scripts_fetched(void) { return s_scripts; }
uint64_t fetcher_gzip_bodies(void) { return s_gzip; }
uint64_t fetcher_html_bodies(void) { return s_html; }
uint64_t fetcher_script_tags_found(void) { return s_script_tags; }
uint64_t fetcher_no_sep(void) { return 0; }
uint64_t fetcher_queue_depth(void) { int c; pthread_mutex_lock(&mtx); c=qc; pthread_mutex_unlock(&mtx); return c; }
uint64_t fetcher_script_total(void) { return 0; }
uint64_t fetcher_script_no_src(void) { return 0; }
uint64_t fetcher_script_not_quoted(void) { return 0; }
uint64_t fetcher_script_no_end_quote(void) { return 0; }
uint64_t fetcher_script_no_js(void) { return 0; }
uint64_t fetcher_script_ok(void) { return s_js_fetched; }
uint64_t fetcher_script_cdn(void) { return s_cdn; }
uint64_t fetcher_script_dnsfail(void) { return s_dnsfail; }
uint64_t fetcher_script_noslash(void) { return 0; }
uint64_t fetcher_script_fetched(void) { return s_js_fetched; }
