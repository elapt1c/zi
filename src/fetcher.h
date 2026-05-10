#ifndef FETCHER_H
#define FETCHER_H

#include <stdint.h>
#include "zorpinvader.h"

uint64_t fetcher_pages_fetched(void);
uint64_t fetcher_scripts_fetched(void);
uint64_t fetcher_gzip_bodies(void);
uint64_t fetcher_html_bodies(void);
uint64_t fetcher_script_tags_found(void);
uint64_t fetcher_no_sep(void);
uint64_t fetcher_queue_depth(void);
uint64_t fetcher_script_total(void);
uint64_t fetcher_script_no_src(void);
uint64_t fetcher_script_not_quoted(void);
uint64_t fetcher_script_no_end_quote(void);
uint64_t fetcher_script_no_js(void);
uint64_t fetcher_script_ok(void);
uint64_t fetcher_script_cdn(void);
uint64_t fetcher_script_dnsfail(void);
uint64_t fetcher_script_noslash(void);
uint64_t fetcher_script_fetched(void);

extern uint64_t total_keys_found;
extern uint64_t total_potential_keys;
extern uint64_t total_sites_checked;
extern uint64_t total_html_sites;
extern uint64_t last_html_time;

extern char discovery_log[10][64];
extern int discovery_log_ptr;

void fetcher_init(void);
void fetcher_submit_page(const char *ip, unsigned port, const unsigned char *html, size_t length);
void greyhat_init(void);
void *greyhat_thread(void *arg);
void log_banner(const char *ip, unsigned port, unsigned proto, const char *banner);

#endif
