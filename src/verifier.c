#include "verifier.h"
#include "zorpinvader-app.h"
#include "util-malloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>

#define VERIFY_QUEUE_SIZE 4096

struct VerifyJob {
    char ip[64];
    char key[512];
    char provider[128];
    char category[64];
};

static struct VerifyJob verify_queue[VERIFY_QUEUE_SIZE];
static int verify_head = 0, verify_tail = 0, verify_count = 0;
static pthread_mutex_t verify_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t verify_cond = PTHREAD_COND_INITIALIZER;

static int stats_valid = 0, stats_invalid = 0, stats_pending = 0;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

static FILE *csv_fp = NULL;
static pthread_mutex_t csv_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t *verify_threads = NULL;
static int num_threads = 0;
static int running = 0;

static const char *curl_path = "/usr/bin/curl";

/* Key scan log ring buffer for TUI */
char key_scan_log[12][128];
int key_scan_log_ptr = 0;
static pthread_mutex_t key_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void log_key_result(int confirmed, const char *ip, const char *key, const char *provider) {
    char entry[128];
    const char *label;
    int klen = (int)strlen(key);
    char short_key[40];
    if (klen > 36) {
        snprintf(short_key, sizeof(short_key), "%.15s...%.15s", key, key + klen - 15);
    } else {
        strncpy(short_key, key, sizeof(short_key) - 1);
        short_key[sizeof(short_key) - 1] = '\0';
    }
    if (confirmed == 1) label = "CONFIRMED";
    else if (confirmed == 0) label = "REJECTED";
    else label = "DETECTED";
    char short_prov[32];
    strncpy(short_prov, provider, sizeof(short_prov) - 1);
    short_prov[sizeof(short_prov) - 1] = '\0';
    snprintf(entry, sizeof(entry), "[%s] %-36.36s | %s", label, short_key, short_prov);
    pthread_mutex_lock(&key_log_mutex);
    strncpy(key_scan_log[key_scan_log_ptr], entry, 127);
    key_scan_log_ptr = (key_scan_log_ptr + 1) % 12;
    pthread_mutex_unlock(&key_log_mutex);
}

void verifier_init_key_log(void) {
    memset(key_scan_log, 0, sizeof(key_scan_log));
    key_scan_log_ptr = 0;
}

int verifier_get_key_scan_log(char buf[12][128], int *ptr) {
    pthread_mutex_lock(&key_log_mutex);
    memcpy(buf, key_scan_log, sizeof(key_scan_log));
    *ptr = key_scan_log_ptr;
    pthread_mutex_unlock(&key_log_mutex);
    return 12;
}

static void queue_push(const struct VerifyJob *job) {
    pthread_mutex_lock(&verify_mutex);
    if (verify_count >= VERIFY_QUEUE_SIZE) {
        verify_head = (verify_head + 1) % VERIFY_QUEUE_SIZE;
        verify_count--;
    }
    verify_queue[verify_tail] = *job;
    verify_tail = (verify_tail + 1) % VERIFY_QUEUE_SIZE;
    verify_count++;
    pthread_cond_signal(&verify_cond);
    pthread_mutex_unlock(&verify_mutex);
}

static int queue_pop(struct VerifyJob *job) {
    pthread_mutex_lock(&verify_mutex);
    while (verify_count == 0 && running)
        pthread_cond_wait(&verify_cond, &verify_mutex);
    if (!running && verify_count == 0) {
        pthread_mutex_unlock(&verify_mutex);
        return 0;
    }
    *job = verify_queue[verify_head];
    verify_head = (verify_head + 1) % VERIFY_QUEUE_SIZE;
    verify_count--;
    pthread_mutex_unlock(&verify_mutex);
    return 1;
}

static int http_status_basic(const char *url, const char *user, const char *pass) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "%s -s -o /dev/null -w '%%{http_code}' -m 10 --connect-timeout 5 -u '%s:%s' \"%s\"",
             curl_path, user, pass, url);
    char buf[16] = {0};
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    fgets(buf, sizeof(buf), fp);
    int status = 0;
    char discard[256];
    while (fgets(discard, sizeof(discard), fp));
    pclose(fp);
    sscanf(buf, "%d", &status);
    return status;
}

static int http_status(const char *url, const char *method, const char **headers) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "%s -s -o /dev/null -w '%%{http_code}' -m 10 --connect-timeout 5", curl_path);
    if (method && strcmp(method, "GET") != 0) {
        strncat(cmd, " -X ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, method, sizeof(cmd) - strlen(cmd) - 1);
    }
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            char hdr_cmd[4096];
            snprintf(hdr_cmd, sizeof(hdr_cmd), " -H '%s'", headers[i]);
            strncat(cmd, hdr_cmd, sizeof(cmd) - strlen(cmd) - 1);
        }
    }
    char url_cmd[4096];
    snprintf(url_cmd, sizeof(url_cmd), " \"%s\"", url);
    strncat(cmd, url_cmd, sizeof(cmd) - strlen(cmd) - 1);
    char buf[16] = {0};
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    fgets(buf, sizeof(buf), fp);
    int status = 0;
    char discard[256];
    while (fgets(discard, sizeof(discard), fp));
    pclose(fp);
    sscanf(buf, "%d", &status);
    return status;
}

static char *http_body(const char *url, const char **headers, int max_body) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "%s -s -m 10 --connect-timeout 5", curl_path);
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            char hdr_cmd[4096];
            snprintf(hdr_cmd, sizeof(hdr_cmd), " -H '%s'", headers[i]);
            strncat(cmd, hdr_cmd, sizeof(cmd) - strlen(cmd) - 1);
        }
    }
    char url_cmd[4096];
    snprintf(url_cmd, sizeof(url_cmd), " \"%s\"", url);
    strncat(cmd, url_cmd, sizeof(cmd) - strlen(cmd) - 1);
    char *body = malloc(max_body + 1);
    body[0] = '\0';
    FILE *fp = popen(cmd, "r");
    if (!fp) { free(body); return NULL; }
    int total = 0;
    char buf[256];
    while ((int)fread(buf, 1, sizeof(buf), fp) > 0) {
        int n = (int)strlen(buf);
        if (total + n < max_body) { memcpy(body + total, buf, n); total += n; }
        else { memcpy(body + total, buf, max_body - total); total = max_body; break; }
    }
    body[total] = '\0';
    pclose(fp);
    return body;
}

/* --- Provider verifiers --- */
static int verify_openai(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.openai.com/v1/models", "GET", h) == 200;
}
static int verify_google(const char *key) {
    char url[512]; snprintf(url, sizeof(url), "https://www.googleapis.com/youtube/v3/videos?part=snippet&id=dQw4w4WgXcQ&key=%s", key);
    return http_status(url, "GET", NULL) == 200;
}
static int verify_github(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: token %s", key);
    const char *h[] = {auth, "Accept: application/vnd.github.v3+json", NULL};
    return http_status("https://api.github.com", "GET", h) == 200;
}
static int verify_stripe(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.stripe.com/v1/charges?limit=1", "GET", h) == 200;
}
static int verify_slack(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    char *body = http_body("https://slack.com/api/auth.test", h, 256);
    int valid = (body && strstr(body, "\"ok\":true")) ? 1 : 0;
    free(body);
    return valid;
}
static int verify_datadog(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "DD-API-KEY: %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.datadoghq.com/api/v1/user", "GET", h) == 200;
}
static int verify_circleci(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Circle-Token: %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://circleci.com/api/v2/me", "GET", h) == 200;
}
static int verify_huggingface(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://huggingface.co/api/whoami-v2", "GET", h) == 200;
}
static int verify_discord(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://discord.com/api/users/@me", "GET", h) == 200;
}
static int verify_twitter(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    int s = http_status("https://api.twitter.com/2/tweets/search/recent?query=hello&max_results=1", "GET", h);
    return (s == 200 || s == 403 || s == 429) ? 1 : 0;
}
static int verify_groq(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.groq.com/openai/v1/models", "GET", h) == 200;
}
static int verify_anthropic(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "x-api-key: %s", key);
    const char *h[] = {auth, "anthropic-version: 2023-06-01", NULL};
    int s = http_status("https://api.anthropic.com/v1/models", "GET", h);
    return (s == 200 || s == 400) ? 1 : 0;
}
static int verify_digitalocean(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.digitalocean.com/v2/account", "GET", h) == 200;
}
static int verify_gitlab(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "PRIVATE-TOKEN: %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://gitlab.com/api/v4/user", "GET", h) == 200;
}
static int verify_sendgrid(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.sendgrid.com/v3/user", "GET", h) == 200;
}
static int verify_fastly(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Fastly-Key: %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.fastly.com/currentuser", "GET", h) == 200;
}
static int verify_cohere(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.cohere.ai/v1/models", "GET", h) == 200;
}
static int verify_deepseek(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.deepseek.com/user", "GET", h) == 200;
}
static int verify_fireworks(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.fireworks.ai/inference/v1/models", "GET", h) == 200;
}
static int verify_mistral(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.mistral.ai/v1/models", "GET", h) == 200;
}
static int verify_nvidia(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://integrate.api.nvidia.com/v1/models", "GET", h) == 200;
}
static int verify_together(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.together.xyz/v1/models", "GET", h) == 200;
}
static int verify_azure(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://management.azure.com/subscriptions?api-version=2022-12-01", "GET", h) == 200;
}
static int verify_alibaba(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://dashscope.aliyuncs.com/compatible-mode/v1/models", "GET", h) == 200;
}
static int verify_cloudflare(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.cloudflare.com/client/v4/user/tokens/verify", "GET", h) == 200;
}
static int verify_heroku(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, "Accept: application/vnd.heroku+json; version=3", NULL};
    return http_status("https://api.heroku.com/account", "GET", h) == 200;
}
static int verify_replicate(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.replicate.com/v1/user", "GET", h) == 200;
}
static int verify_elevenlabs(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.elevenlabs.io/v1/user", "GET", h) == 200;
}
static int verify_square(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://connect.squareup.com/v2/locations", "GET", h) == 200;
}
static int verify_linear(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.linear.app/graphql", "GET", h) == 200;
}
static int verify_sentry(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://sentry.io/api/0/", "GET", h) == 200;
}
static int verify_npm(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://registry.npmjs.org/-/npm/v1/user", "GET", h) == 200;
}
static int verify_rubygems(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://rubygems.org/api/v1/profiles/me.json", "GET", h) == 200;
}
static int verify_flutterwave(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.flutterwave.com/v3/balances", "GET", h) == 200;
}
static int verify_assemblyai(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.assemblyai.com/v1/user", "GET", h) == 200;
}
static int verify_vercel(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.vercel.com/v2/user", "GET", h) == 200;
}
static int verify_openrouter(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, "HTTP-Referer: http://zorpinvader.local", "X-Title: ZorpInvader", NULL};
    return http_status("https://openrouter.ai/api/v1/auth/key", "GET", h) == 200;
}
static int verify_voyage(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", key);
    const char *h[] = {auth, NULL};
    return http_status("https://api.voyageai.com/v1/models", "GET", h) == 200;
}
static int verify_paypal(const char *key) {
    char url[512]; snprintf(url, sizeof(url), "https://api-m.paypal.com/v1/oauth2/token?grant_type=client_credentials&client_id=%s", key);
    int s = http_status(url, "POST", NULL);
    return (s == 200 || s == 401) ? 1 : 0;
}
static int verify_meta(const char *key) {
    char url[512]; snprintf(url, sizeof(url), "https://graph.facebook.com/me?access_token=%s", key);
    return http_status(url, "GET", NULL) == 200;
}
static int verify_twilio(const char *key) {
    return http_status_basic("https://api.twilio.com/2010-04-01/Accounts.json", key, "") == 200;
}
static int verify_pypi(const char *key) {
    return http_status_basic("https://pypi.org/_/api/accounts/me/", key, "token") == 200;
}
static int verify_mailgun(const char *key) {
    return http_status_basic("https://api.mailgun.net/v3/domains", "api", key) == 200;
}
static int verify_tiktok(const char *key) {
    char auth[512]; snprintf(auth, sizeof(auth), "Bearer %s", key);
    const char *h[] = {auth, NULL};
    int s = http_status("https://open.tiktokapis.com/v2/oauth/token/", "POST", h);
    return (s == 200 || s == 400) ? 1 : 0;
}
static int verify_aws(const char *key) { (void)key; return -1; }
static int verify_databricks(const char *key) { (void)key; return -1; }
static int verify_skip(const char *key) { (void)key; return -1; }

typedef int (*verify_fn_t)(const char *);
struct ProviderVerifier { const char *provider; verify_fn_t fn; };

static const struct ProviderVerifier verifiers[] = {
    {"openai", verify_openai}, {"google", verify_google}, {"github", verify_github},
    {"stripe", verify_stripe}, {"slack", verify_slack}, {"datadog", verify_datadog},
    {"circleci", verify_circleci}, {"huggingface", verify_huggingface},
    {"discord", verify_discord}, {"twitter", verify_twitter}, {"groq", verify_groq},
    {"anthropic", verify_anthropic}, {"twilio", verify_twilio},
    {"digitalocean", verify_digitalocean}, {"gitlab", verify_gitlab},
    {"sendgrid", verify_sendgrid}, {"fastly", verify_fastly}, {"cohere", verify_cohere},
    {"deepseek", verify_deepseek}, {"fireworks", verify_fireworks},
    {"mistral", verify_mistral}, {"nvidia", verify_nvidia}, {"together", verify_together},
    {"azure", verify_azure}, {"jwt", verify_azure}, {"alibaba", verify_alibaba},
    {"cloudflare", verify_cloudflare}, {"heroku", verify_heroku},
    {"pypi", verify_pypi}, {"mailgun", verify_mailgun}, {"replicate", verify_replicate},
    {"elevenlabs", verify_elevenlabs}, {"square", verify_square}, {"linear", verify_linear},
    {"sentry", verify_sentry}, {"npm", verify_npm}, {"rubygems", verify_rubygems},
    {"flutterwave", verify_flutterwave}, {"assemblyai", verify_assemblyai},
    {"vercel", verify_vercel}, {"openrouter", verify_openrouter}, {"voyage", verify_voyage},
    {"paypal", verify_paypal}, {"meta", verify_meta}, {"hf", verify_huggingface},
    {"databricks", verify_databricks}, {"tiktok", verify_tiktok}, {"aws", verify_aws},
    {"Contextual (label match)", verify_skip}, {"Unknown", verify_skip},
    {NULL, NULL}
};

static verify_fn_t find_verifier(const char *provider) {
    for (int i = 0; verifiers[i].provider != NULL; i++)
        if (strcmp(provider, verifiers[i].provider) == 0) return verifiers[i].fn;
    return NULL;
}

static void write_valid_key(const char *ip, const char *key, const char *provider, const char *category, int confirmed) {
    char ts[32]; time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    pthread_mutex_lock(&csv_mutex);
    fprintf(csv_fp, "%d,%s,%s,%s,%s,%s\n", confirmed, ip, key, provider, category, ts);
    fflush(csv_fp);
    pthread_mutex_unlock(&csv_mutex);
}

static void *verifier_worker(void *arg) {
    (void)arg;
    struct VerifyJob job;
    while (running || verify_count > 0) {
        if (!queue_pop(&job)) break;
        pthread_mutex_lock(&stats_mutex); stats_pending--; pthread_mutex_unlock(&stats_mutex);
        verify_fn_t fn = find_verifier(job.category);
        if (!fn) fn = find_verifier(job.provider);
        int result = fn ? fn(job.key) : 1;
        if (result == 1) {
            write_valid_key(job.ip, job.key, job.provider, job.category, 1);
            pthread_mutex_lock(&stats_mutex); stats_valid++; pthread_mutex_unlock(&stats_mutex);
            log_key_result(1, job.ip, job.key, job.provider);
        } else if (result == 0) {
            pthread_mutex_lock(&stats_mutex); stats_invalid++; pthread_mutex_unlock(&stats_mutex);
            log_key_result(0, job.ip, job.key, job.provider);
        } else {
            write_valid_key(job.ip, job.key, job.provider, job.category, 2);
            pthread_mutex_lock(&stats_mutex); stats_valid++; pthread_mutex_unlock(&stats_mutex);
            log_key_result(2, job.ip, job.key, job.provider);
        }
    }
    return NULL;
}

int verify_api_key(const char *provider, const char *key) {
    verify_fn_t fn = find_verifier(provider);
    return fn ? fn(key) : -1;
}

void verifier_init(int worker_count) {
    if (worker_count <= 0) {
        int n = sysconf(_SC_NPROCESSORS_ONLN);
        worker_count = (n > 0) ? (n / 2 > 4 ? 4 : n / 2) : 4;
        if (worker_count < 1) worker_count = 1;
        if (worker_count > 8) worker_count = 8;
    }
    csv_fp = fopen("found_keys.csv", "a");
    if (csv_fp) {
        fseek(csv_fp, 0, SEEK_END);
        if (ftell(csv_fp) == 0) fprintf(csv_fp, "confirmed,ip_address,api_key,provider,category,timestamp\n");
        fflush(csv_fp);
    }
    running = 1;
    num_threads = worker_count;
    verify_threads = malloc(sizeof(pthread_t) * worker_count);
    for (int i = 0; i < worker_count; i++)
        pthread_create(&verify_threads[i], NULL, verifier_worker, NULL);
    fprintf(stderr, "[verifier] %d worker threads started\n", worker_count);
}

void verifier_shutdown(void) {
    running = 0;
    pthread_cond_broadcast(&verify_cond);
    for (int i = 0; i < num_threads; i++) pthread_join(verify_threads[i], NULL);
    free(verify_threads); verify_threads = NULL;
    if (csv_fp) { fflush(csv_fp); fclose(csv_fp); csv_fp = NULL; }
    fprintf(stderr, "[verifier] shutdown: %d valid, %d invalid\n", stats_valid, stats_invalid);
}

void verifier_submit(const char *ip, const char *key, const char *provider, const char *category) {
    struct VerifyJob job;
    strncpy(job.ip, ip, sizeof(job.ip) - 1); job.ip[sizeof(job.ip) - 1] = '\0';
    strncpy(job.key, key, sizeof(job.key) - 1); job.key[sizeof(job.key) - 1] = '\0';
    strncpy(job.provider, provider, sizeof(job.provider) - 1); job.provider[sizeof(job.provider) - 1] = '\0';
    strncpy(job.category, category, sizeof(job.category) - 1); job.category[sizeof(job.category) - 1] = '\0';
    queue_push(&job);
    pthread_mutex_lock(&stats_mutex); stats_pending++; pthread_mutex_unlock(&stats_mutex);
}

int verifier_stats_valid(void) { pthread_mutex_lock(&stats_mutex); int v = stats_valid; pthread_mutex_unlock(&stats_mutex); return v; }
int verifier_stats_invalid(void) { pthread_mutex_lock(&stats_mutex); int v = stats_invalid; pthread_mutex_unlock(&stats_mutex); return v; }
int verifier_stats_pending(void) { pthread_mutex_lock(&stats_mutex); int v = stats_pending; pthread_mutex_unlock(&stats_mutex); return v; }
