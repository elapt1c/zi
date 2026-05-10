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
#include <unistd.h>

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

static void log_discovery(const char *msg) {
    pthread_mutex_lock(&greyhat_mutex);
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
    /* AWS - 4 char prefix, distinctive */
    {"AKIA", 16, 25, "AWS Access Key ID", "aws"},
    {"ASIA", 16, 25, "AWS Temporary Access Key", "aws"},
    /* OpenAI - distinctive prefix */    /* Google - distinctive */
    {"AIzaSy", 16, 60, "Google API Key", "google"},
    {"ya29.", 20, 500, "Google OAuth2 Token", "google"},
    /* GitHub - distinctive */
    {"ghp_", 16, 100, "GitHub Personal Access Token", "github"},
    {"gho_", 16, 100, "GitHub OAuth Token", "github"},
    {"ghu_", 16, 100, "GitHub User-to-Server Token", "github"},
    {"ghs_", 16, 100, "GitHub Server-to-Server Token", "github"},
    {"github_pat_", 16, 200, "GitHub Fine-Grained PAT", "github"},
    /* Stripe - distinctive */    {"pk_live_", 16, 100, "Stripe Publishable Key (Live)", "stripe"},    {"rk_live_", 16, 100, "Stripe Restricted Key (Live)", "stripe"},
    {"rk_test_", 16, 100, "Stripe Restricted Key (Test)", "stripe"},
    {"whsec_", 16, 80, "Stripe Webhook Secret", "stripe"},
    /* Slack - distinctive */    /* Datadog - use full prefix */    /* CircleCI */
    {"cci_", 16, 80, "CircleCI API Token", "circleci"},
    /* HuggingFace */    /* Discord */    /* Twitter/X */
    {"AAAAAAAA", 20, 200, "Twitter Bearer Token", "twitter"},
    /* Groq */
    {"gsk_", 16, 80, "Groq API Key", "groq"},
    /* Anthropic */    /* Twilio */    /* DigitalOcean */
    {"dop_v1_", 30, 150, "DigitalOcean API Token", "digitalocean"},
    {"doa_", 16, 150, "DigitalOcean OAuth Token", "digitalocean"},
    /* GitLab */
    {"glpat-", 16, 80, "GitLab Personal Access Token", "gitlab"},
    {"glft-", 16, 80, "GitLab Feed Token", "gitlab"},
    {"GR1348941", 16, 80, "GitLab Runner Token", "gitlab"},
    /* SendGrid */
    {"SG.", 16, 120, "SendGrid API Key", "sendgrid"},
    /* Fastly */
    {"FASTLY_", 16, 80, "Fastly API Token", "fastly"},
    /* Cohere */
    {"cohere-", 16, 80, "Cohere API Key", "cohere"},
    /* DeepSeek */    /* Fireworks */    {"fireworks-", 16, 80, "Fireworks AI Token", "fireworks"},
    /* Mistral */
    {"mistral-", 16, 80, "Mistral AI API Key", "mistral"},
    /* Nvidia */
    {"nvapi-", 16, 80, "Nvidia NIM API Key", "nvidia"},
    /* Together */
    {"together-", 16, 80, "Together AI API Key", "together"},
    /* Azure/JWT */    {"0.AAA", 16, 200, "Azure AD Token", "azure"},
    /* Alibaba */
    {"LTAI", 12, 60, "Alibaba Cloud Access Key", "alibaba"},
    /* Cloudflare */
    {"cloudflare_", 16, 80, "Cloudflare API Token", "cloudflare"},
    /* Heroku */
    {"HRKU", 16, 80, "Heroku API Key", "heroku"},
    /* PyPI */
    {"pypi-", 16, 100, "PyPI API Token", "pypi"},
    /* Mailgun */    /* Replicate */    /* ElevenLabs */
    {"elevenlabs-", 16, 80, "ElevenLabs API Key", "elevenlabs"},
    /* Square */
    {"sq0atp-", 10, 50, "Square Access Token", "square"},
    {"sq0csp-", 16, 100, "Square Application Secret", "square"},
    /* Linear */
    {"lin_api_", 16, 80, "Linear API Key", "linear"},
    /* Sentry */
    {"sntrys_", 16, 100, "Sentry Auth Token", "sentry"},
    /* NPM */
    {"npm_", 16, 100, "NPM Access Token", "npm"},
    /* RubyGems */
    {"rubygems_", 16, 80, "RubyGems API Key", "rubygems"},
    /* Flutterwave */
    {"FLWSECK_", 16, 80, "Flutterwave Secret Key", "flutterwave"},
    /* AssemblyAI */
    {"assemblyai_", 16, 80, "AssemblyAI API Key", "assemblyai"},
    /* Vercel */
    {"vercel_", 10, 80, "Vercel API Token", "vercel"},
    /* OpenRouter */    /* Voyage */
    {"voyage-", 16, 80, "Voyage AI API Key", "voyage"},
    /* PayPal */
    {"A21A", 16, 80, "PayPal Client ID", "paypal"},
    /* Meta/Facebook */
    {"EAAC", 20, 500, "Facebook Access Token", "meta"},
    {"EAAG", 20, 500, "Facebook Graph API Token", "meta"},
    {"EAAE", 20, 500, "Facebook Enterprise Token", "meta"},
    /* Databricks */    /* TikTok */
    {"act_", 16, 60, "TikTok Advertiser Token", "tiktok"},    /* Re-added patterns that actually match real keys */
    {"pk_live_", 16, 100, "Stripe Publishable Key (Live)", "stripe"},
    {"sk_live_", 16, 100, "Stripe Secret Key (Live)", "stripe"},
    {"sk_test_", 16, 100, "Stripe Secret Key (Test)", "stripe"},
    {"rk_live_", 16, 100, "Stripe Restricted Key (Live)", "stripe"},
    {"rk_test_", 16, 100, "Stripe Restricted Key (Test)", "stripe"},
    {"whsec_", 16, 80, "Stripe Webhook Secret", "stripe"},
    {"cus_", 16, 80, "Stripe Customer ID", "stripe"},
    {"sk-proj-", 16, 100, "OpenAI Project Key", "openai"},
    {"sk-ant-", 16, 100, "Anthropic API Key", "anthropic"},
    {"sk-or-", 16, 100, "DeepSeek/OpenRouter Key", "deepseek"},
    {"sk-or-v1-", 16, 100, "OpenRouter API Key", "openrouter"},
    {"ghp_", 16, 100, "GitHub Personal Access Token", "github"},
    {"gho_", 16, 100, "GitHub OAuth Token", "github"},
    {"xoxb-", 8, 100, "Slack Bot Token", "slack"},
    {"xoxp-", 8, 100, "Slack User Token", "slack"},
    {"dop_v1_", 30, 150, "DigitalOcean API Token", "digitalocean"},
    {"glpat-", 16, 80, "GitLab Personal Access Token", "gitlab"},
    {"GR1348941", 16, 80, "GitLab Runner Token", "gitlab"},
    {"gsk_", 16, 80, "Groq API Key", "groq"},
    {"cohere-", 16, 80, "Cohere API Key", "cohere"},
    {"mistral-", 16, 80, "Mistral AI API Key", "mistral"},
    {"fireworks-", 16, 80, "Fireworks AI Token", "fireworks"},
    {"nvapi-", 16, 80, "Nvidia NIM API Key", "nvidia"},
    {"together-", 16, 80, "Together AI API Key", "together"},
    {"assemblyai_", 16, 80, "AssemblyAI API Key", "assemblyai"},
    {"elevenlabs-", 16, 80, "ElevenLabs API Key", "elevenlabs"},
    {"rubygems_", 16, 80, "RubyGems API Key", "rubygems"},
    {"FLWSECK_", 16, 80, "Flutterwave Secret Key", "flutterwave"},
    {"sntrys_", 16, 100, "Sentry Auth Token", "sentry"},
    {"lin_api_", 16, 80, "Linear API Key", "linear"},
    {"pypi-", 16, 100, "PyPI API Token", "pypi"},
    {"HRKU", 16, 80, "Heroku API Key", "heroku"},
    {"FASTLY_", 16, 80, "Fastly API Token", "fastly"},
    {"cloudflare_", 16, 80, "Cloudflare API Token", "cloudflare"},
    {"vercel_", 10, 80, "Vercel API Token", "vercel"},
    {"sq0csp-", 16, 100, "Square Application Secret", "square"},
    {"sq0atp-", 10, 50, "Square Access Token", "square"},
    {"voyage-", 16, 80, "Voyage AI API Key", "voyage"},
    {"EAAC", 20, 500, "Facebook Access Token", "meta"},
    {"EAAG", 20, 500, "Facebook Graph API Token", "meta"},
    {"A21A", 16, 80, "PayPal Client ID", "paypal"},
    {"AAAAAAAA", 20, 200, "Twitter Bearer Token", "twitter"},
    {"ya29.", 20, 500, "Google OAuth2 Token", "google"},
    {"AIzaSy", 16, 60, "Google API Key", "google"},
    {"LTAI", 12, 60, "Alibaba Cloud Access Key", "alibaba"},
    {"dapi", 16, 100, "Databricks API Token", "databricks"},
    {"act_", 16, 60, "TikTok Advertiser Token", "tiktok"},
    {"cci_", 16, 80, "CircleCI API Token", "circleci"},
    {"SG.", 16, 120, "SendGrid API Key", "sendgrid"},
    {"ey", 50, 3000, "JWT Token", "jwt"},
    {NULL, 0, 0, NULL, NULL}
};

/* --- Task queue --- */
struct VerificationTask {
    char ip[64], key[512], metadata[1024];
    struct VerificationTask *next;
};

static void enqueue_task(struct VerificationTask *task) {
    /* Directly submit to verifier - no queue needed */
    char provider[128] = "Unknown", category[64] = "unknown";
    if (task->metadata[0]) {
        char *sep = strchr(task->metadata, '|');
        if (sep) {
            int pl = (int)(sep - task->metadata); if (pl >= 128) pl = 127;
            strncpy(provider, task->metadata, pl); provider[pl] = 0;
            strncpy(category, sep+1, 63); category[63] = 0;
        } else { strncpy(provider, task->metadata, 127); provider[127] = 0; }
    }
    verifier_submit(task->ip, task->key, provider, category);
    total_keys_found++;
    free(task);
}

static int is_valid_key_char(char c) {
    return isalnum(c) || c == '-' || c == '_' || c == '.' || c == '+' || c == '/' || c == '=';
}

static void extract_and_enqueue(const char *ip_str, const unsigned char *px, unsigned length, unsigned offset, size_t id, int is_test) {
    char key[512] = {0};
    int key_len = 0, start_offset = offset - 1;
    /* Debug: show what smack found */
    
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
    if (!is_test && is_duplicate(ip_str, key)) {  return; }
    if (strstr(key, "AKIAIOSFODNN7EXAMPLE") != NULL) {  return; }
    if (strncmp(key, "iVBOR", 5) == 0 || strncmp(key, "R0lGOD", 6) == 0 || strncmp(key, "/9j/", 4) == 0) {  return; }
    if (strncmp(key, "MII", 3) == 0 && key_len > 100) {  return; }
    if (strncmp(key, "data:", 5) == 0) {  return; }
    if (strncmp(key, "http://", 7) == 0 || strncmp(key, "https://", 8) == 0) {  return; }
    if (strncmp(key, "-----BEGIN", 10) == 0) {  return; }
    if (key_len < 10) {  return; }
    /* Reject placeholder keys */
    int same_char = 1;
    for (int i = 1; i < key_len; i++) { if (key[i] != key[0]) { same_char = 0; break; } }
    if (same_char) {  return; }
    if (key_len > 20) {
        int max_count = 0;
        for (int ci = 0; ci < key_len; ci++) {
            int count = 0;
            for (int cj = ci; cj < key_len; cj++) if (key[cj] == key[ci]) count++;
            if (count > max_count) max_count = count;
        }
        if (max_count * 100 / key_len > 80) {  return; }
    }
    int pass = 0;
    const char *detected_provider = "Unknown", *detected_category = "unknown";
    if (id == ID_LABEL) {
        if (key_len >= 8) { pass = 1; detected_provider = "Contextual (label match)"; detected_category = "unknown"; }
    } else {
        for (int i = 0; key_patterns[i].prefix != NULL; i++) {
            if (strncmp(key, key_patterns[i].prefix, strlen(key_patterns[i].prefix)) == 0) {
                int mn = key_patterns[i].min_len;
                if (key_len >= mn) {
                    pass = 1; detected_provider = key_patterns[i].provider; detected_category = key_patterns[i].category;
                    
                    break;
                } else {
                    
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
        if (id != SMACK_NOT_FOUND) {
            
            extract_and_enqueue(ip_str, px, length, offset, id, 0);
        }
    }
}

void greyhat_init(void) {
    memset(seen_cache, 0, sizeof(seen_cache));
    greyhat_smack = smack_create("greyhat", 0);
    for (int i = 0; key_patterns[i].prefix != NULL; i++)
        smack_add_pattern(greyhat_smack, key_patterns[i].prefix, strlen(key_patterns[i].prefix), ID_KEY, 0);
    /* No label-based detection - all keys must match prefix patterns with verifiers */
    smack_compile(greyhat_smack);
}

void *greyhat_thread(void *arg) { (void)arg; return NULL; }
