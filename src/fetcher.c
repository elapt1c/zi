/*
 * Fetcher worker pool - receives (ip, port) from SYN scan result queue,
 * does full HTTP GET, decompresses, finds <script> sources, fetches JS,
 * runs greyhat pattern scanner, submits to verifier.
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

/* --- Stats --- */
static uint64_t stats_pages_fetched = 0;
static uint64_t stats_scripts_fetched = 0;
static uint64_t stats_gzip_bodies = 0;
static uint64_t stats_html_bodies = 0;
static uint64_t stats_script_tags = 0;
static uint64_t stats_script_fetched = 0;
static uint64_t stats_cdn = 0;
static uint64_t stats_dnsfail = 0;

/* --- Globals for TUI --- */
uint64_t total_keys_found = 0;
uint64_t total_potential_keys = 0;
uint64_t total_sites_checked = 0;
uint64_t total_html_sites = 0;
uint64_t last_html_time = 0;

/* --- TUI log buffer --- */
char discovery_log[10][64];
int discovery_log_ptr = 0;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --- CDN blocklist --- */
static const char *cdn_domains[] = {
    "cloudflare.com", "cloudflareinsights.com", "googleapis.com",
    "googletagmanager.com", "google-analytics.com", "jsdelivr.net",
    "unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "bootcdn.net", "cdn.bootcss.com",
    "polyfill.io", "facebook.net", "connect.facebook.net",
    "twimg.com", "platform.twitter.com", "assets.adobedtm.com",
    "hotjar.com", "static.hotjar.com", NULL
};

static int is_cdn(const char *url) {
    for (int i = 0; cdn_domains[i]; i++)
        if (strstr(url, cdn_domains[i])) return 1;
    return 0;
}

/* --- Fetch queue (ip:port pairs from SYN scan) --- */
#define QUEUE_SIZE 32768
struct Job { char ip[64]; unsigned port; };
static struct Job queue[QUEUE_SIZE];
static int head = 0, tail = 0, count = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int running = 0;

static pthread_t *threads = NULL;
static int num_threads = 0;

/* --- curl_path --- */
static const char *curl_path = "/usr/bin/curl";

/* --- Fetch a URL into a buffer --- */
static unsigned char *curl_fetch(const char *url, size_t *out_len) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "%s -s -L -m 6 --connect-timeout 3 -A 'ZorpInvader/1.0' --compressed \"%s\" 2>/dev/null",
        curl_path, url);
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    size_t cap = 131072;
    unsigned char *buf = malloc(cap);
    size_t total = 0;
    int n;
    while ((n = fread(buf + total, 1, cap - total - 1, fp)) > 0) {
        total += n;
        if (total > cap - 8192) { cap *= 2; buf = realloc(buf, cap); }
    }
    pclose(fp);
    if (total == 0) { free(buf); return NULL; }
    buf[total] = '\0';
    *out_len = total;
    return buf;
}

/* --- Resolve a relative script URL --- */
static char *resolve_url(const char *base_ip, unsigned base_port, const char *script_src) {
    size_t len = strlen(script_src);
    char *url = malloc(512 + len);
    if (script_src[0] == '/') {
        snprintf(url, 512 + len, "http://%s:%u%s", base_ip, base_port, script_src);
    } else if (strstr(script_src, "://")) {
        strncpy(url, script_src, 512 + len - 1);
    } else {
        snprintf(url, 512 + len, "http://%s:%u/%s", base_ip, base_port, script_src);
    }
    return url;
}

/* --- Find all <script src=""> in HTML, fetch JS, scan for keys --- */
static void process_html(const char *ip, unsigned port, const unsigned char *html, size_t hlen) {
    stats_pages_fetched++;
    __sync_add_and_fetch(&total_sites_checked, 1);
    __sync_add_and_fetch(&total_html_sites, 1);
    last_html_time = (uint64_t)time(0);

    if (hlen > 32)
        stats_html_bodies++;

    const char *p = (const char *)html;
    int found = 0;
    while (found < 10 && (p = strcasestr(p, "<script"))) {
        stats_script_tags++;
        p += 7;
        const char *src = strcasestr(p, "src=");
        const char *end = strchr(p, '>');
        if (!src || !end || src >= end) { p = end; continue; }
        src += 4;
        while (*src == ' ' || *src == '\t') src++;
        if (*src != '"' && *src != '\'') { p = end; continue; }
        char q = *src++;
        const char *close = strchr(src, q);
        if (!close || close >= end) { p = end; continue; }
        int slen = (int)(close - src);
        if (slen < 5 || !strstr(src, ".js")) { p = close; continue; }

        char src_buf[512];
        strncpy(src_buf, src, slen);
        src_buf[slen] = '\0';

        char *url = resolve_url(ip, port, src_buf);
        if (is_cdn(url)) { stats_cdn++; free(url); p = close; continue; }

        size_t js_len = 0;
        unsigned char *js = curl_fetch(url, &js_len);
        free(url);
        if (!js) { stats_dnsfail++; p = close; continue; }

        stats_script_fetched++;
        stats_scripts_fetched++;

        /* Scan JS for API keys */
        ipaddress ipaddr;
        memset(&ipaddr, 0, sizeof(ipaddr));
        /* Parse IP string to ipv4 */
        unsigned a=0, b=0, c=0, d=0;
        const char *ipx = ip;
        a = (unsigned)strtoul(ipx, (char**)&ipx, 10); ipx++;
        b = (unsigned)strtoul(ipx, (char**)&ipx, 10); ipx++;
        c = (unsigned)strtoul(ipx, (char**)&ipx, 10); ipx++;
        d = (unsigned)strtoul(ipx, NULL, 10);
        ipaddr.ipv4 = (a<<24)|(b<<16)|(c<<8)|d;
        greyhat_scan(ipaddr, js, (unsigned)js_len);

        free(js);
        found++;
        p = close;
    }
}

/* --- Worker thread: pops (ip,port), does GET, processes --- */
static void *worker(void *arg) {
    (void)arg;
    struct Job j;
    while (running || count > 0) {
        pthread_mutex_lock(&mutex);
        while (count == 0 && running)
            pthread_cond_wait(&cond, &mutex);
        if (!running && count == 0) { pthread_mutex_unlock(&mutex); break; }
        j = queue[head];
        head = (head + 1) % QUEUE_SIZE;
        count--;
        pthread_mutex_unlock(&mutex);

        char url[256];
        snprintf(url, sizeof(url), "http://%s:%u/", j.ip, j.port);
        size_t len = 0;
        unsigned char *html = curl_fetch(url, &len);
        if (!html) continue;

        process_html(j.ip, j.port, html, len);
        free(html);
    }
    return NULL;
}

/* --- Public API --- */

void fetcher_submit(const char *ip, unsigned port) {
    /* Dedup: only submit HTTP-like ports */
    struct Job j;
    strncpy(j.ip, ip, sizeof(j.ip) - 1); j.ip[sizeof(j.ip) - 1] = '\0';
    j.port = port;

    pthread_mutex_lock(&mutex);
    if (count >= QUEUE_SIZE) {
        /* Drop oldest */
        free(queue[head].ip); /* fixed string, no-op */
        head = (head + 1) % QUEUE_SIZE;
        count--;
    }
    queue[tail] = j;
    tail = (tail + 1) % QUEUE_SIZE;
    count++;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
}

void fetcher_init(void) {
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 4;
    num_threads = ncpu * 4; /* 4 threads per core */
    if (num_threads > 64) num_threads = 64;
    threads = malloc(sizeof(pthread_t) * num_threads);
    running = 1;
    for (int i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, worker, NULL);
    fprintf(stderr, "[fetcher] %d workers on %d cores\n", num_threads, ncpu);
}

void fetcher_shutdown(void) {
    running = 0;
    pthread_cond_broadcast(&cond);
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);
    free(threads);
}

/* Stats getters */
uint64_t fetcher_pages_fetched(void) { return stats_pages_fetched; }
uint64_t fetcher_scripts_fetched(void) { return stats_scripts_fetched; }
uint64_t fetcher_gzip_bodies(void) { return stats_gzip_bodies; }
uint64_t fetcher_html_bodies(void) { return stats_html_bodies; }
uint64_t fetcher_script_tags_found(void) { return stats_script_tags; }
uint64_t fetcher_no_sep(void) { return 0; }
uint64_t fetcher_queue_depth(void) { pthread_mutex_lock(&mutex); int c = count; pthread_mutex_unlock(&mutex); return c; }
uint64_t fetcher_script_total(void) { return 0; }
uint64_t fetcher_script_no_src(void) { return 0; }
uint64_t fetcher_not_quoted(void) { return 0; }
uint64_t fetcher_script_no_end_quote(void) { return 0; }
uint64_t fetcher_script_no_js(void) { return 0; }
uint64_t fetcher_script_ok(void) { return stats_script_fetched; }
uint64_t fetcher_script_cdn(void) { return stats_cdn; }
uint64_t fetcher_script_dnsfail(void) { return stats_dnsfail; }
uint64_t fetcher_script_noslash(void) { return 0; }
uint64_t fetcher_script_fetched(void) { return stats_script_fetched; }
uint64_t fetcher_script_not_quoted(void) { return 0; }
uint64_t fetcher_src(void) { return 0; }
