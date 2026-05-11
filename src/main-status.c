#include <unistd.h>
#include "main-status.h"
#include "pixie-timer.h"
#include "unusedparm.h"
#include "main-globals.h"
#include "util-safefunc.h"
#include "util-bool.h"
#include "fetcher.h"
#include "verifier.h"
#include <stdio.h>
#include <string.h>

void status_print(
    struct Status *status,
    uint64_t count,
    uint64_t max_count,
    double pps,
    uint64_t total_tcbs,
    uint64_t total_synacks,
    uint64_t total_syns,
    uint64_t exiting,
    bool json_status)
{
    (void)total_tcbs; (void)total_syns; (void)exiting;
    double elapsed_time;
    double rate;
    double now;
    double percent_done;
    double time_remaining;
    double kpps = pps / 1000;

    global_now = time(0);
    now = (double)pixie_gettime();
    elapsed_time = (now - status->last.clock)/1000000.0;
    if (elapsed_time <= 0) return;

    rate = (count - status->last.count)*1.0/elapsed_time;
    status->last_rates[status->last_count++ & 0x7] = rate;
    rate = 0;
    for (int i=0; i<8; i++) rate += status->last_rates[i];
    rate /= 8;

    percent_done = (double)(count*100.0/max_count);
    time_remaining  = (1.0 - percent_done/100.0) * (max_count / rate);

    fprintf(stderr, "\x1b[1;1H\x1b[2K\x1b[44;37m ZorpInvader | Status: %s | Keys: %lu/%lu/%lu \x1b[0m\n",
        is_tx_done ? "Waiting" : "Scanning",
        (unsigned long)verifier_stats_valid(),
        (unsigned long)total_keys_found,
        (unsigned long)total_html_sites);

    fprintf(stderr, "\x1b[2;1H\x1b[2K \x1b[32mRate:\x1b[0m %6.2f kpps | \x1b[36mProgress:\x1b[0m %5.2f%% | \x1b[33mETA:\x1b[0m %02u:%02u:%02u | \x1b[31mFound:\x1b[0m %lu\n",
        kpps, percent_done,
        (unsigned)(time_remaining/3600), (unsigned)(time_remaining/60)%60, (unsigned)(time_remaining)%60,
        total_synacks);

    fprintf(stderr, "\x1b[3;1H\x1b[2K\x1b[37m--------------------------------------------------------------------------------\x1b[0m\n");
    fprintf(stderr, "\x1b[4;1H\x1b[2K\x1b[35m[  KEY SCAN LOG  ]\x1b[0m\n");

    char key_log_buf[12][128];
    int key_log_ptr;
    verifier_get_key_scan_log(key_log_buf, &key_log_ptr);

    /* Show the last 10 entries (most recent at bottom) */
    int start = (key_log_ptr + 12 - 10) % 12;
    for (int i=0; i<10; i++) {
        int k_idx = (start + i) % 12;
        const char *entry = key_log_buf[k_idx];
        const char *color = "\x1b[37m";
        if (strstr(entry, "[CONFIRMED]")) color = "\x1b[32m";
        else if (strstr(entry, "[REJECTED]")) color = "\x1b[31m";
        else if (strstr(entry, "[DETECTED]")) color = "\x1b[33m";
        fprintf(stderr, "\x1b[%d;1H\x1b[2K%s%s\x1b[0m\n", 5+i, color, entry);
    }

    fprintf(stderr, "\x1b[15;1H\x1b[2K\x1b[37m--------------------------------------------------------------------------------\x1b[0m\n");
    fprintf(stderr, "\x1b[16;1H\x1b[2K\x1b[36mFetcher:\x1b[0m pages=%lu scripts=%lu | \x1b[35mgzip=%lu html=%lu <script>=%lu | \x1b[33mqueue=%lu\n",
        fetcher_pages_fetched(), fetcher_scripts_fetched(),
        fetcher_gzip_bodies(), fetcher_html_bodies(), fetcher_script_tags_found(), fetcher_queue_depth());
    fprintf(stderr, "\x1b[17;1H\x1b[2K\x1b[37mValid: %lu | Invalid: %lu | Pending: %ld\n",
        verifier_stats_valid(), verifier_stats_invalid(), verifier_stats_pending());

    fflush(stderr);

    /* Write raw status to file for external watchdog */
    {
        FILE *sf = fopen("/tmp/zorp_status", "w");
        if (sf) {
            fprintf(sf, "ETA: %02u:%02u:%02u Found: %lu\n",
                (unsigned)(time_remaining/3600), (unsigned)(time_remaining/60)%60, (unsigned)(time_remaining)%60,
                total_synacks);
            fclose(sf);
        }
    }

    status->last.clock = now;
    status->last.count = count;
}

void status_finish(struct Status *status) {
    (void)status;
    fprintf(stderr, "\nScan Complete.\n");
}

void status_start(struct Status *status) {
    memset(status, 0, sizeof(*status));
    status->last.clock = clock();
    status->last.time = time(0);
    status->last.count = 0;
    status->timer = 0x1;
    fprintf(stderr, "\x1b[2J");
}
