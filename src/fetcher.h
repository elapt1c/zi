#ifndef FETCHER_H
#define FETCHER_H

#include <stdint.h>
#include "zorpinvader.h"

/* Stats getters */
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

/* Globals */
extern uint64_t total_keys_found;
extern uint64_t total_potential_keys;
extern uint64_t total_sites_checked;
extern uint64_t total_html_sites;
extern uint64_t last_html_time;

/* API */
void fetcher_init(void);
void fetcher_shutdown(void);
void fetcher_submit(const char *ip, unsigned port);

/* Greyhat */
void greyhat_init(void);
void *greyhat_thread(void *arg);
void greyhat_scan(ipaddress ip, const unsigned char *px, unsigned length);

#endif
