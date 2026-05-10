#include "greyhat.h"
#include "fetcher.h"
#include "smack.h"
#include "util-malloc.h"
#include "verifier.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>

struct SMACK *greyhat_smack;
pthread_mutex_t greyhat_mutex = PTHREAD_MUTEX_INITIALIZER;
extern pthread_cond_t greyhat_cond;

/* --- Deduplication cache --- */
#define CACHE_SIZE 16384
struct SeenEntry { char ip[64]; char key[128]; int valid; unsigned int hash; };
struct SeenEntry seen_cache[CACHE_SIZE];
static unsigned int hash_entry(const char *ip, const char *key) {
    unsigned int h = 5381;
    const char *s = ip; while (*s) h = ((h << 5) + h) + *s++;
    s = key; while (*s) h = ((h << 5) + h) + *s++;
    return h;
}
static int is_duplicate(const char *ip, const char *key) {
    unsigned int h = hash_entry(ip, key);
    unsigned int idx = h % CACHE_SIZE;
    return (seen_cache[idx].valid && seen_cache[idx].hash == h &&
            strcmp(seen_cache[idx].ip, ip) == 0 && strncmp(seen_cache[idx].key, key, 127) == 0);
}
static void add_to_cache(const char *ip, const char *key) {
    unsigned int h = hash_entry(ip, key);
    unsigned int idx = h % CACHE_SIZE;
    seen_cache[idx].valid = 1; seen_cache[idx].hash = h;
    strncpy(seen_cache[idx].ip, ip, 63); seen_cache[idx].ip[63] = '\0';
    strncpy(seen_cache[idx].key, key, 127); seen_cache[idx].key[127] = '\0';
}

/* --- TUI log buffers --- */
char discovery_log[10][64];
int discovery_log_ptr = 0;

static void log_discovery(const char *msg) {
    pthread_mutex_lock(&greyhat_mutex);
    strncpy(discovery_log[discovery_log_ptr], msg, 63);
    discovery_log[discovery_log_ptr][63] = '\0';
    discovery_log_ptr = (discovery_log_ptr + 1) % 10;
    pthread_mutex_unlock(&greyhat_mutex);
}

void log_banner(const char *ip, unsigned port, unsigned proto, const char *banner) {
    char msg[64];
    snprintf(msg, sizeof(msg), "%s:%u [http]", ip, port);
    log_discovery(msg);
}

/* --- Key patterns --- */
enum { ID_KEY = 1, ID_LABEL = 2 };
struct KeyPattern {
    const char *prefix; int min_len, max_len;
    const char *provider, *category;
};
static const struct KeyPattern key_patterns[] = {
    {"AKIA", 20, 20, "AWS Access Key ID", "aws"},
    {"ASIA", 20, 20, "AWS Temporary Access Key", "aws"},
    {"ABIA", 20, 20, "AWS IAM Access Key", "aws"},
    {"ACCA", 20, 20, "AWS Access Key (legacy)", "aws"},
    {"sk-proj-", 32, 60, "OpenAI Project Key", "openai"},
    {"sk-", 20, 60, "OpenAI API Key", "openai"},
    {"LTAI", 16, 40, "Alibaba Cloud Access Key", "alibaba"},
    {"AIza", 30, 50, "Google API Key", "google"},
    {"ghp_", 36, 42, "GitHub Personal Access Token", "github"},
    {"gho_", 36, 42, "GitHub OAuth Token", "github"},
    {"ghu_", 36, 42, "GitHub User-to-Server Token", "github"},
    {"ghs_", 36, 42, "GitHub Server-to-Server Token", "github"},
    {"github_pat_", 50, 100, "GitHub Fine-Grained PAT", "github"},
    {"sk_live_", 30, 50, "Stripe Secret Key (Live)", "stripe"},
    {"pk_live_", 30, 50, "Stripe Publishable Key (Live)", "stripe"},
    {"sk_test_", 30, 50, "Stripe Secret Key (Test)", "stripe"},
    {"rk_live_", 30, 50, "Stripe Restricted Key (Live)", "stripe"},
    {"rk_test_", 30, 50, "Stripe Restricted Key (Test)", "stripe"},
    {"xoxb-", 12, 60, "Slack Bot Token", "slack"},
    {"xoxp-", 12, 60, "Slack User Token", "slack"},
    {"xoxa-", 12, 60, "Slack App Token", "slack"},
    {"xoxr-", 12, 60, "Slack Refresh Token", "slack"},
    {"xoxs-", 12, 60, "Slack Shared Token", "slack"},
    {"eyJ", 100, 1000, "Azure/Microsoft JWT", "azure"},
    {"dop_v1_", 60, 80, "DigitalOcean API Token", "digitalocean"},
    {"doa_", 60, 80, "DigitalOcean OAuth Token", "digitalocean"},
    {"glpat-", 20, 30, "GitLab Personal Access Token", "gitlab"},
    {"glft-", 20, 30, "GitLab Feed Token", "gitlab"},
    {"GR1348941", 20, 30, "GitLab Runner Registration Token", "gitlab"},
    {"pypi-", 40, 60, "PyPI API Token", "pypi"},
    {"key-", 30, 40, "Mailgun API Key", "mailgun"},
    {"SG.", 50, 80, "SendGrid API Key", "sendgrid"},
    {"vF8", 35, 45, "Cloudflare Global API Key", "cloudflare"},
    {"HRKU", 30, 40, "Heroku API Key", "heroku"},
    {"FASTLY_", 30, 50, "Fastly API Token", "fastly"},
    {"hf_", 20, 40, "Hugging Face Token", "huggingface"},
    {"sk-ant-", 40, 60, "Anthropic API Key", "anthropic"},
    {"sk-ant-api", 40, 60, "Anthropic API Key (full)", "anthropic"},
    {"cohere-", 30, 50, "Cohere API Key", "cohere"},
    {"gsk_", 40, 60, "Groq API Key", "groq"},
    {"dapi", 30, 50, "Databricks API Token", "databricks"},
    {"lin_api_", 40, 60, "Linear API Key", "linear"},
    {"sntrys_", 50, 80, "Sentry Auth Token", "sentry"},
    {"vercel_", 20, 40, "Vercel API Token", "vercel"},
    {"npm_", 30, 50, "NPM Access Token", "npm"},
    {"rubygems_", 40, 60, "RubyGems API Key", "rubygems"},
    {"FLWSECK_", 30, 50, "Flutterwave Secret Key", "flutterwave"},
    {"sq0atp-", 20, 30, "Square Access Token", "square"},
    {"sq0csp-", 40, 60, "Square Application Secret", "square"},
    {"A21A", 30, 50, "PayPal Client ID", "paypal"},
    {"EAAC", 50, 150, "Facebook Access Token", "meta"},
    {"EAAG", 50, 150, "Facebook Graph API Token", "meta"},
    {"AAAAAAAA", 50, 100, "Twitter Bearer Token", "twitter"},
    {"sk-or-", 40, 60, "OpenRouter API Key", "openrouter"},
    {"pplx-", 30, 50, "Perplexity API Key", "perplexity"},
    {"mistral-", 30, 50, "Mistral AI API Key", "mistral"},
    {"r8_", 30, 50, "Replicate API Token", "replicate"},
    {"elevenlabs-", 30, 50, "ElevenLabs API Key", "elevenlabs"},
    {NULL, 0, 0, NULL, NULL}
};

/* --- Task queue --- */
struct VerificationTask {
    char ip[64], key[512], metadata[1024];
    struct VerificationTask *next;
};
static struct VerificationTask *queue_head = NULL;
static struct VerificationTask *queue_tail = NULL;

static void enqueue_task(struct VerificationTask *task) {
    pthread_mutex_lock(&greyhat_mutex);
    if (queue_tail) { queue_tail->next = task; queue_tail = task; }
    else { queue_head = queue_tail = task; }
    pthread_mutex_unlock(&greyhat_mutex);
}

static int is_valid_key_char(char c) {
    return isalnum(c) || c == '-' || c == '_' || c == '.' || c == '+' || c == '/' || c == '=';
}

static void extract_and_enqueue(const char *ip_str, const unsigned char *px, unsigned length, unsigned offset, size_t id, int is_test) {
    char key[512] = {0};
    int key_len = 0, start_offset = offset - 1;
    if (id == ID_LABEL) {
        while (start_offset < (int)length && (isalnum(px[start_offset]) || px[start_offset] == '-' || px[start_offset] == '_')) start_offset++;
        while (start_offset < (int)length && (isspace(px[start_offset]) || px[start_offset] == ':' || px[start_offset] == '=' || px[start_offset] == '"' || px[start_offset] == '\'')) start_offset++;
    } else {
        while (start_offset > 0 && is_valid_key_char(px[start_offset-1])) start_offset--;
    }
    for (int i = 0; i < 511 && (start_offset + i) < (int)length; i++) {
        char c = px[start_offset + i];
        if (is_valid_key_char(c)) { key[i] = c; key_len = i + 1; } else break;
    }
    key[key_len] = '\0';
    if (!is_test && is_duplicate(ip_str, key)) return;
    if (strstr(key, "AKIAIOSFODNN7EXAMPLE") != NULL) return;
    if (strncmp(key, "iVBOR", 5) == 0 || strncmp(key, "R0lGOD", 6) == 0 || strncmp(key, "/9j/", 4) == 0) return;
    if (strncmp(key, "MII", 3) == 0 && key_len > 100) return;
    if (strncmp(key, "data:", 5) == 0) return;
    if (strncmp(key, "http://", 7) == 0 || strncmp(key, "https://", 8) == 0) return;
    if (strncmp(key, "-----BEGIN", 10) == 0) return;
    if (key_len < 8) return;
    /* Reject placeholder keys */
    int same_char = 1;
    for (int i = 1; i < key_len; i++) { if (key[i] != key[0]) { same_char = 0; break; } }
    if (same_char) return;
    if (key_len > 20) {
        int max_count = 0;
        for (int ci = 0; ci < key_len; ci++) {
            int count = 0;
            for (int cj = ci; cj < key_len; cj++) if (key[cj] == key[ci]) count++;
            if (count > max_count) max_count = count;
        }
        if (max_count * 100 / key_len > 80) return;
    }
    int pass = 0;
    const char *detected_provider = "Unknown", *detected_category = "unknown";
    if (id == ID_LABEL) {
        if (key_len >= 16) { pass = 1; detected_provider = "Contextual (label match)"; detected_category = "unknown"; }
    } else {
        for (int i = 0; key_patterns[i].prefix != NULL; i++) {
            if (strncmp(key, key_patterns[i].prefix, strlen(key_patterns[i].prefix)) == 0) {
                int mn = key_patterns[i].min_len, mx = key_patterns[i].max_len;
                if (key_len >= mn && (mx == 0 || key_len <= mx)) {
                    pass = 1; detected_provider = key_patterns[i].provider; detected_category = key_patterns[i].category;
                    break;
                }
            }
        }
    }
    if (!pass && strncmp(key, "ey", 2) == 0 && key_len >= 60) {
        int dot_positions[5] = {0}, dot_count = 0, valid_b64url = 1;
        for (int i = 0; i < key_len; i++) {
            char c = key[i];
            if (c == '.') { if (dot_count < 5) dot_positions[dot_count] = i; dot_count++; }
            else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '='))
                { valid_b64url = 0; break; }
        }
        if (valid_b64url && dot_count >= 2) {
            int part1_len = dot_positions[0];
            int part2_len = dot_positions[1] - dot_positions[0] - 1;
            int part3_len = key_len - dot_positions[1] - 1;
            if (part1_len >= 10 && part2_len >= 10 && part3_len >= 10) {
                int is_source_map = 0;
                const char *sm_markers[] = {"mappings", "sources", "webpack", "sourceMappingURL", "names", "file\"", NULL};
                for (int i = 0; sm_markers[i]; i++) { if (strstr(key, sm_markers[i])) { is_source_map = 1; break; } }
                if (!is_source_map) { pass = 1; detected_provider = "JWT Token"; detected_category = "jwt"; }
            }
        }
    }
    if (pass) {
        if (!is_test) add_to_cache(ip_str, key);
        struct VerificationTask *task = CALLOC(1, sizeof(*task));
        strncpy(task->ip, ip_str, sizeof(task->ip)-1); task->ip[sizeof(task->ip)-1] = '\0';
        strncpy(task->key, key, sizeof(task->key)-1); task->key[sizeof(task->key)-1] = '\0';
        snprintf(task->metadata, sizeof(task->metadata), "%s|%s", detected_provider, detected_category);
        enqueue_task(task);
        total_potential_keys++;
        char log_msg[64];
        snprintf(log_msg, 64, "FOUND: %-20.20s [%s]", key, detected_provider);
        log_discovery(log_msg);
    }
}

void greyhat_scan(ipaddress ip, const unsigned char *px, unsigned length) {
    unsigned state = 0, offset = 0;
    char ip_str[64];
    ipaddress_formatted_t fmt = ipaddress_fmt(ip);
    strncpy(ip_str, fmt.string, sizeof(ip_str)); ip_str[sizeof(ip_str)-1] = '\0';
    total_sites_checked++;
    if (length > 10) {
        const char *data = (const char *)px;
        if (strcasestr(data, "<script") || strcasestr(data, "<style") || strcasestr(data, "<html")) {
            total_html_sites++;
            last_html_time = (uint64_t)time(0);
        }
    }
    while (offset < length) {
        size_t id = smack_search_next(greyhat_smack, &state, px, &offset, length);
        if (id != SMACK_NOT_FOUND) extract_and_enqueue(ip_str, px, length, offset, id, 0);
    }
}

void greyhat_init(void) {
    memset(seen_cache, 0, sizeof(seen_cache));
    memset(discovery_log, 0, sizeof(discovery_log));
    greyhat_smack = smack_create("greyhat", 0);
    for (int i = 0; key_patterns[i].prefix != NULL; i++)
        smack_add_pattern(greyhat_smack, key_patterns[i].prefix, strlen(key_patterns[i].prefix), ID_KEY, 0);
    const char *labels[] = {"api_key","api-key","apikey","token","secret","password",
                            "access_key","access-key","secret_key","secret-key",
                            "api_token","api-token","auth_token","auth-token","bearer","authorization"};
    for (int i = 0; i < 16; i++) smack_add_pattern(greyhat_smack, labels[i], strlen(labels[i]), ID_LABEL, 1);
    smack_compile(greyhat_smack);
}

void *greyhat_thread(void *arg) {
    (void)arg;
    while (1) {
        struct VerificationTask *task = NULL;
        pthread_mutex_lock(&greyhat_mutex);
        while (queue_head == NULL) pthread_cond_wait(&greyhat_cond, &greyhat_mutex);
        task = queue_head; queue_head = task->next; if (queue_head == NULL) queue_tail = NULL;
        pthread_mutex_unlock(&greyhat_mutex);
        char provider[128] = "Unknown", category[64] = "unknown";
        if (task->metadata[0]) {
            char *sep = strchr(task->metadata, '|');
            if (sep) {
                int pl = (int)(sep - task->metadata); if (pl >= 128) pl = 127;
                strncpy(provider, task->metadata, pl); provider[pl] = '\0';
                strncpy(category, sep+1, 63); category[63] = '\0';
            } else { strncpy(provider, task->metadata, 127); provider[127] = '\0'; }
        }
        verifier_submit(task->ip, task->key, provider, category);
        total_keys_found++;
        free(task);
    }
    return NULL;
}
