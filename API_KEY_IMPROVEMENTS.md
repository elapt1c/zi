# API Key Detection Improvements

## What was changed

### 1. Heuristic Context-Based Verification (replaced AI verification)

**Before:** Keys were verified by calling Alibaba's Qwen-turbo AI API via `curl`. This was:
- **Slow** — network call per key (seconds each)
- **Unreliable** — AI was rejecting valid keys (including the test keys)
- **Costly** — required valid AI API keys and credits
- **Privacy risk** — sends found keys to a third-party AI service

**After:** Fast, local heuristic analysis of the context where the key was found:

#### Scoring System

**Positive signals (key in legitimate code context):**
| Signal | Score | Example |
|--------|-------|---------|
| Key inside quotes | +3 | `var key = "sk-..."` |
| 3+ code keywords nearby | +3 | `const API_KEY = "..."` |
| 2 code keywords nearby | +2 | `api_key = "..."` |
| HTML/script context | +2 | `<script>...key...</script>` |
| JSON-like structure | +2 | `{"api_key": "sk-..."}` |
| HTTP header context | +1 | `Authorization: Bearer ...` |
| Code delimiters nearby | +1 | `;`, `}`, `,` |
| Assignment operators | +1 | `= "`, `: "` |
| Distinctive pattern bonus | +2 | AWS AKIA, GitHub ghp_, Stripe sk_live_, Slack xoxb- |

**Negative signals (key in binary/random data):**
| Signal | Effect |
|--------|--------|
| Base64 image data nearby | Immediate REJECT |
| PEM/certificate data | Immediate REJECT |
| Data URI scheme | Immediate REJECT |
| < 60% printable chars | Immediate REJECT |
| 60-80% printable chars | -1 |

#### Verdicts
| Score | Status | Meaning |
|-------|--------|---------|
| ≥ 4 | `verified` | Strong code context — likely real exposed key |
| 1-3 | `suspicious` | Weak context — report for review |
| ≤ 0 | `rejected` | No code context or binary data — likely false positive |

**Benefits:**
- Instant verification (no network call)
- 100% deterministic (same input → same output)
- No external dependencies or API keys needed
- Self-contained (works offline)
- Doesn't send sensitive keys to third parties

### 2. Expanded Key Pattern Registry (6 → 70+ patterns)

**Before:** Only 6 key prefixes detected (LTAI, sk-, AKIA, AIza, ghp_, ey)

**After:** 70+ patterns covering major cloud providers, AI platforms, and SaaS services:

#### Cloud Providers
- **AWS**: Access Key IDs (AKIA, ASIA, ABIA, ACCA), 20-char format
- **Google Cloud**: API keys (AIza), Firebase, YouTube Data API
- **Alibaba Cloud**: Access keys (LTAI)
- **Azure/Microsoft**: Access tokens (0.AAA), JWTs (eyJ)
- **Cloudflare**: Global API keys (vF8), API tokens
- **DigitalOcean**: API tokens (dop_v1_), OAuth tokens (doa_)

#### AI/ML Platforms
- **OpenAI**: Project keys (sk-proj-), standard keys (sk-)
- **Anthropic**: API keys (sk-ant-, sk-ant-api)
- **Cohere**: API keys (cohere-)
- **Groq**: API keys (gsk_)
- **Hugging Face**: Tokens (hf_)
- **Stability AI**: API keys (sk-)
- **ElevenLabs**: API keys
- **Mistral AI**: API keys (mistral-)
- **Perplexity**: API keys (pplx-)
- **OpenRouter**: API keys (sk-or-)
- **Replicate**: API tokens (r8_)

#### Developer Platforms
- **GitHub**: Personal access tokens (ghp_), OAuth (gho_), user-to-server (ghu_), 
  server-to-server (ghs_), fine-grained PATs (github_pat_)
- **GitLab**: Personal access tokens (glpat-), feed tokens (glft-), 
  runner registration tokens (GR1348941)
- **NPM**: Access tokens (npm_)
- **PyPI**: API tokens (pypi-)
- **RubyGems**: API keys (rubygems_)
- **Vercel**: API tokens (vercel_)
- **Heroku**: API keys (HRKU)
- **Sentry**: Auth tokens (sntrys_)
- **Linear**: API keys (lin_api_)
- **Databricks**: API tokens (dapi)

#### Payment/Financial
- **Stripe**: Secret keys (sk_live_, sk_test_), publishable keys (pk_live_, pk_test_),
  restricted keys (rk_live_, rk_test_)
- **PayPal**: Client IDs (A21A)
- **Square**: Access tokens (sq0atp-), application secrets (sq0csp-)
- **Flutterwave**: Secret keys (FLWSECK_)

#### Communication/Messaging
- **Slack**: Bot tokens (xoxb-), user tokens (xoxp-), app tokens (xoxa-),
  refresh tokens (xoxr-), shared tokens (xoxs-)
- **Discord**: Bot tokens (MTE), client tokens (ND)
- **Twilio**: API key SIDs (SK)
- **SendGrid**: API keys (SG.)
- **Mailgun**: API keys (key-)
- **TikTok**: API keys (tt)

#### Monitoring/Infrastructure
- **DataDog**: API keys (dd)
- **Fastly**: API tokens (FASTLY_)
- **CircleCI**: Personal API tokens (cc)

#### Social Media
- **Meta/Facebook**: Access tokens (EAAC), Graph API tokens (EAAG)
- **Twitter/X**: Bearer tokens (AAAAAAAA)

### 2. Pattern-Aware Validation

Each pattern now has:
- **Prefix**: The identifying start of the key
- **Minimum length**: Shortest valid key for that pattern
- **Maximum length**: Longest expected key (0 = no strict limit)
- **Provider name**: Human-readable description
- **Category**: Machine-readable classification (aws, openai, google, etc.)

This eliminates false positives by enforcing length constraints specific to each provider.

### 3. Improved Noise Filtering

Added filters for:
- Data URIs (data:)
- URLs (http://, https://)
- PEM headers (-----BEGIN)
- Very short strings (< 8 chars)
- Base64-encoded images (iVBOR, R0lGOD, /9j/)
- SSL certificates (MII, >100 chars)

### 4. Hash-Based Deduplication Cache

**Before:** Linear search through 16K entries (O(n) per lookup)

**After:** Hash-based lookup (O(1) per lookup) using DJB2 hash of (ip, key) pair.
Much faster for high-volume scanning with minimal collision risk.

### 5. Enhanced CSV Output

**Before:** `ip,key,category` (3 columns, no header)

**After:** `ip_address,api_key,provider,category,verification_status,timestamp` (6 columns with header)
- **provider**: Human-readable provider name (e.g., "AWS Access Key ID", "OpenAI API Key")
- **category**: Machine-readable category (aws, openai, google, github, etc.)
- **verification_status**: "verified" or "unverified" based on AI validation
- **timestamp**: ISO 8601 UTC timestamp of discovery

CSV now includes a header row for easier parsing and automated reporting.

### 6. Better Log Messages

Discovery logs now show provider name:
```
Before: FOUND: sk-5cf9419b76c54ef...
After:  FOUND: sk-5cf9419b76c54ef... [OpenAI API Key]
```

AI verification logs also show provider:
```
Before: VERIFIED: Unknown
After:  VERIFIED: openai (OpenAI API Key)
```

## Files Modified

- `src/greyhat.c`: All changes (pattern registry, validation, deduplication, CSV output)

## Testing

- Build: `make clean && make -j` ✅
- Selftest: `bin/zorpinvader --selftest` ✅

## Usage

### Basic API Key Scanning

The expanded key detection is active automatically when using `--banners` mode:

```bash
# Scan for HTTP services and check for API keys
./bin/zorpinvader <target> -p80,443,8080,8443 --banners

# Results logged to found_keys.csv
cat found_keys.csv
```

### Randomized Scan Order

By default, scans always start from index 0 (encrypted by seed, so order appears random but
is deterministic for a given seed). Use `--randomize-start` to begin at a random position
each time, making scan order truly unpredictable:

```bash
# Start at random position in the scan range
./bin/zorpinvader 0.0.0.0/0 -p80 --banners --randomize-start

# Combine with custom seed for maximum unpredictability
./bin/zorpinvader 0.0.0.0/0 -p80 --banners --randomize-start --seed 12345
```

This is useful when you want to avoid always scanning the same IPs first,
especially if you're running multiple partial scans of the same range.

## Notes

- **Heuristic verification**: The new context-based verifier runs locally with no network calls. It analyzes the surrounding ~100 bytes of text where the key was found to determine if it's in a legitimate code/config context or in binary/encrypted/image data.
- **Three-tier verdicts**: Keys are classified as `verified` (strong context), `suspicious` (weak context), or `rejected` (binary data/false positive). This gives you nuance rather than binary yes/no.
- The pattern registry is easily extensible: just add a new entry to `key_patterns[]`
- Patterns are matched in order, so more specific patterns (e.g., sk-proj-) should come before generic ones (sk-)
- The "Together AI" pattern uses a single underscore prefix which may generate false positives; consider removing if noise is an issue
- JWT detection (ey prefix) requires at least 2 dots in the key to reduce false positives
