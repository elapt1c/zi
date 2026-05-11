#include <stdint.h>
#ifndef VERIFIER_H
#define VERIFIER_H

int verify_api_key(const char *provider, const char *key);
void verifier_init(int worker_count);
void verifier_shutdown(void);
void verifier_submit(const char *ip, const char *key, const char *provider, const char *category);
uint64_t verifier_stats_valid(void);
uint64_t verifier_stats_invalid(void);
uint64_t verifier_stats_pending(void);
int verifier_get_key_scan_log(char buf[12][128], int *ptr);
void verifier_init_key_log(void);

#endif
