/*
 * HTTP page fetcher - fetches HTML/JS via curl for API key scanning.
 * Called from banner processing for HTTP responses containing HTML.
 */
#include "fetcher.h"
#include "verifier.h"
#include "massip-parse.h"
void greyhat_scan(ipaddress ip, const unsigned char *px, unsigned length);
#include "util-malloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

/* --- Stats --- */
static uint64_t stats_pages_fetched = 0;
static uint64_t stats_scripts_fetched = 0;
static uint64_t stats_gzip_bodies = 0;
static uint64_t stats_html_bodies = 0;
static uint64_t stats_script_tags = 0;
static uint64_t stats_no_sep = 0;
static uint64_t stats_no_src = 0;
static uint64_t stats_no_quoted = 0;
static uint64_t stats_no_end_quote = 0;
static uint64_t stats_no_js = 0;
static uint64_t stats_ok = 0;
static uint64_t stats_cdn = 0;
static uint64_t stats_dnsfail = 0;
static uint64_t stats_noslash = 0;
static uint64_t stats_fetched = 0;

/* --- Global stats for TUI --- */

/* --- DNS Cache --- */
#define DNS_CACHE_SIZE 2048
struct DNSCacheEntry { char host[128]; int valid; time_t expiry; };
static struct DNSCacheEntry dns_cache[DNS_CACHE_SIZE];

/* --- CDN Blocklist --- */
static const char *cdn_domains[] = {
    "cloudflare.com", "cloudflareinsights.com", "googleapis.com",
    "googletagmanager.com", "google-analytics.com", "jsdelivr.net",
    "unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "bootcdn.net", "cdn.bootcss.com",
    "polyfill.io", "cdn.polyfill.io", "facebook.net", "connect.facebook.net",
    "twimg.com", "platform.twitter.com", "assets.adobedtm.com",
    "hotjar.com", "static.hotjar.com", NULL
};
static int is_cdn_domain(const char *url) {
    for (int i = 0; cdn_domains[i]; i++)
        if (strstr(url, cdn_domains[i])) return 1;
    return 0;
}

/* --- Fetch queue --- */
#define FETCH_QUEUE_SIZE 2048
struct FetchJob {
    char ip[64];
    unsigned port;
    unsigned char *data;
    size_t length;
};
static struct FetchJob fetch_queue[FETCH_QUEUE_SIZE];
static int fetch_head = 0, fetch_tail = 0, fetch_count = 0;
static pthread_mutex_t fetch_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fetch_cond = PTHREAD_COND_INITIALIZER;
static int fetch_running = 0;

/* --- TUI log buffer --- */



/* --- Simple gzip decompression --- */
static unsigned char *gunzip_body(const unsigned char *data, size_t len, size_t *out_len) {
    if (len < 10) return NULL;
    if (data[0] != 0x1f || data[1] != 0x8b) return NULL;
    /* Use system gunzip via pipe */
    char tmpfile[] = "/tmp/zorpgzXXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return NULL;
    write(fd, data, len);
    close(fd);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "gzip -d -c %s 2>/dev/null", tmpfile);
    FILE *fp = popen(cmd, "r");
    unlink(tmpfile);
    if (!fp) return NULL;
    size_t alloc = len * 8;
    if (alloc < 65536) alloc = 65536;
    unsigned char *buf = malloc(alloc);
    size_t total = 0;
    int n;
    while ((n = fread(buf + total, 1, alloc - total - 1, fp)) > 0) {
        total += n;
        if (total > alloc - 4096) {
            alloc *= 2;
            buf = realloc(buf, alloc);
        }
    }
    pclose(fp);
    buf[total] = '\0';
    *out_len = total;
    return buf;
}

/* --- Script tag parser --- */

/* --- Fetch a JS file via curl --- */
static unsigned char *fetch_url(const char *url, size_t *out_len) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "/usr/bin/curl -s -L -m 8 --connect-timeout 4 -A 'Mozilla/5.0' '%s' 2>/dev/null", url);
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    size_t alloc = 65536;
    unsigned char *buf = malloc(alloc);
    size_t total = 0;
    int n;
    while ((n = fread(buf + total, 1, alloc - total - 1, fp)) > 0) {
        total += n;
        if (total > alloc - 4096) { alloc *= 2; buf = realloc(buf, alloc); }
    }
    pclose(fp);
    buf[total] = '\0';
    *out_len = total;
    return buf;
}

/* --- Worker thread --- */
static void *fetcher_worker(void *arg) {
    (void)arg;
    struct FetchJob job;
    while (1) {
        pthread_mutex_lock(&fetch_mutex);
        while (fetch_count == 0 && fetch_running)
            pthread_cond_wait(&fetch_cond, &fetch_mutex);
        if (!fetch_running && fetch_count == 0) {
            pthread_mutex_unlock(&fetch_mutex);
            break;
        }
        job = fetch_queue[fetch_head];
        fetch_head = (fetch_head + 1) % FETCH_QUEUE_SIZE;
        fetch_count--;
        pthread_mutex_unlock(&fetch_mutex);

        /* Check if it looks like HTML */
        const unsigned char *px = job.data;
        size_t len = job.length;
        stats_pages_fetched++;

        /* Try gzip decompression */
        size_t decompressed_len = 0;
        unsigned char *decompressed = NULL;
        if (len > 10 && px[0] == 0x1f && px[1] == 0x8b) {
            decompressed = gunzip_body(px, len, &decompressed_len);
            if (decompressed) { stats_gzip_bodies++; px = decompressed; len = decompressed_len; }
        }

        if (len > 10) {
            const char *data = (const char *)px;
            if (strcasestr(data, "<html") || strcasestr(data, "<body") || strcasestr(data, "<script"))
                stats_html_bodies++;
        }

        /* Find script tags and fetch JS */
        char base_url[256];
        snprintf(base_url, sizeof(base_url), "http://%s:%u/", job.ip, job.port);

        /* Parse and fetch up to 10 script sources */
        int scripts_found = 0;
        const char *p = (const char *)px;
        while (scripts_found < 10 && (p = strcasestr(p, "<script"))) {
            stats_script_tags++;
            p += 7;
            const char *src_attr = strcasestr(p, "src=");
            const char *close_tag = strchr(p, '>');
            if (src_attr && close_tag && src_attr < close_tag) {
                src_attr += 4;
                while (*src_attr == ' ' || *src_attr == '\t') src_attr++;
                if (*src_attr == '"' || *src_attr == '\'') {
                    char quote = *src_attr++;
                    const char *end = strchr(src_attr, quote);
                    if (end && end < close_tag) {
                        int slen = (int)(end - src_attr);
                        if (slen > 3 && (strstr(src_attr, ".js") || strstr(src_attr, ".js?"))) {
                            char *url = malloc(slen + 256);
                            strncpy(url, src_attr, slen);
                            url[slen] = '\0';
                            /* Resolve relative */
                            if (url[0] == '/') {
                                char *full = malloc(64 + slen + 1);
                                snprintf(full, 64 + slen + 1, "http://%s:%u%s", job.ip, job.port, url);
                                free(url); url = full;
                            } else if (!strstr(url, "://")) {
                                char *full = malloc(64 + slen + 1);
                                snprintf(full, 64 + slen + 1, "http://%s:%u/%s", job.ip, job.port, url);
                                free(url); url = full;
                            }
                            /* Check CDN */
                            if (is_cdn_domain(url)) { stats_cdn++; free(url); p = close_tag; continue; }
                            /* Fetch JS */
                            size_t js_len = 0;
                            unsigned char *js = fetch_url(url, &js_len);
                            if (js) {
                                stats_fetched++;
                                stats_scripts_fetched++;
                                /* Scan for keys */
                                extern void *greyhat_thread(void *);
                                ipaddress ip; memset(&ip, 0, sizeof(ip));
                                ip.ipv4 = massip_parse_ipv4(job.ip);
                                greyhat_scan(ip, js, (unsigned)js_len);
                                free(js);
                            } else { stats_dnsfail++; }
                            free(url);
                            scripts_found++;
                        }
                    }
                }
            }
            p = close_tag ? close_tag : p;
        }

        free(decompressed);
        free(job.data);
    }
    return NULL;
}

static pthread_t *fetcher_threads = NULL;
static int fetcher_num_threads = 0;

void fetcher_init(void) {
    memset(dns_cache, 0, sizeof(dns_cache));
    int n = sysconf(_SC_NPROCESSORS_ONLN);
    fetcher_num_threads = (n > 0) ? (n * 2 > 16 ? 16 : n * 2) : 8;
    if (fetcher_num_threads < 4) fetcher_num_threads = 4;
    fetcher_threads = malloc(sizeof(pthread_t) * fetcher_num_threads);
    fetch_running = 1;
    for (int i = 0; i < fetcher_num_threads; i++)
        pthread_create(&fetcher_threads[i], NULL, fetcher_worker, NULL);
}

void fetcher_submit_page(const char *ip, unsigned port, const unsigned char *html, size_t length) {
    struct FetchJob job;
    strncpy(job.ip, ip, sizeof(job.ip) - 1); job.ip[sizeof(job.ip) - 1] = '\0';
    job.port = port;
    job.data = malloc(length);
    memcpy(job.data, html, length);
    job.length = length;
    pthread_mutex_lock(&fetch_mutex);
    if (fetch_count >= FETCH_QUEUE_SIZE) {
        fetch_head = (fetch_head + 1) % FETCH_QUEUE_SIZE;
        fetch_count--;
        free(fetch_queue[fetch_head].data);
    }
    fetch_queue[fetch_tail] = job;
    fetch_tail = (fetch_tail + 1) % FETCH_QUEUE_SIZE;
    fetch_count++;
    pthread_cond_signal(&fetch_cond);
    pthread_mutex_unlock(&fetch_mutex);
}

/* Stats getters */
uint64_t fetcher_pages_fetched(void) { return stats_pages_fetched; }
uint64_t fetcher_scripts_fetched(void) { return stats_scripts_fetched; }
uint64_t fetcher_gzip_bodies(void) { return stats_gzip_bodies; }
uint64_t fetcher_html_bodies(void) { return stats_html_bodies; }
uint64_t fetcher_script_tags_found(void) { return stats_script_tags; }
uint64_t fetcher_no_sep(void) { return stats_no_sep; }
uint64_t fetcher_no_src(void) { return stats_no_src; }
uint64_t fetcher_not_quoted(void) { return stats_no_quoted; }
uint64_t fetcher_script_no_end_quote(void) { return stats_no_end_quote; }
uint64_t fetcher_script_no_js(void) { return stats_no_js; }
uint64_t fetcher_script_ok(void) { return stats_ok; }
uint64_t fetcher_script_total(void) { return stats_fetched; }
uint64_t fetcher_script_cdn(void) { return stats_cdn; }
uint64_t fetcher_script_dnsfail(void) { return stats_dnsfail; }
uint64_t fetcher_script_noslash(void) { return stats_noslash; }
uint64_t fetcher_script_fetched(void) { return stats_fetched; }
uint64_t fetcher_queue_depth(void) {
    pthread_mutex_lock(&fetch_mutex);
    int d = fetch_count;
    pthread_mutex_unlock(&fetch_mutex);
    return d;
}
