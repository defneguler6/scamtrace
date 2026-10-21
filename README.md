# ScamTrace (prototype v0.3)

ScamTrace tells a payment firm, at the moment a payment is made or received,
whether the payee is collecting money for a **live scam campaign on social
media (TikTok, Instagram, Facebook) or the scam websites they advertise**. It
also gives the firm an evidence pack it can use for mule-account reviews and
APP reimbursement claims.

It is built for smaller **receiving-side** firms (e-money institutions,
payment institutions, fintechs, crypto on-ramps). These firms now carry half
of each APP reimbursement but sit outside the large bank intelligence
networks.

> Status: working prototype, October 2026. Everything in `demo/` is
> synthetic (fictional brands, accounts and posts). It has not yet been run
> against live scam content.

## How it works

```
 TikTok / Instagram ──┐
  official ad library │                ┌──────────────────────────────┐
  submitted post +    ├─▶ AI (Claude) ─┤ scam? type? impersonation?   │
  screenshots         │   reads text   │ red flags (quoted)           │
                      │   + images     │ payment details (even in     │
 scam ad landing URL ─┘                │ images) · WhatsApp/Telegram  │
                                       │ · off-platform links         │
                                       └──────────────┬───────────────┘
                     re-validate every identifier     │
                     (checksums, formats) ◀───────────┤
                                                      ▼
            crawler follows links ─▶ payment page ─▶ AI reads page + screenshot
                                                      │
                     store (keyed hashes, scrubbed text) ─▶ campaign clustering
                                                      │   shared payee / wallet /
                                                      │   WhatsApp / account /
                                                      ▼   site / page kit
                      payment firm ─▶ POST /v1/payee/check
                                      GET  /v1/campaigns/{id}/evidence-pack
```

### Where social media content comes from

ScamTrace **does not scrape TikTok or Instagram**. It uses:

| Source | What it gives | Module |
|---|---|---|
| **Meta Ad Library API** (Instagram, Facebook) | Ad text, advertiser page, snapshot, display domain | `sources/meta_ad_library.py` |
| **TikTok Commercial Content API** | Ads shown in the EEA, Switzerland and UK: advertiser, dates, images | `sources/tiktok_ccl.py` |
| **Submissions** (`POST /v1/sightings/social`) | A post link, caption and screenshots, e.g. from a payment firm's own scam claims, where victims usually include screenshots of the post | `api.py` |

The crawler only visits the **off-platform** sites posts point to (ad
destination, link in bio). It never visits the platforms or chat apps.

Known coverage limits (part of the open questions below): Meta's API returns
commercial ads only if they reached the EU, so UK-only scam ads may be
missing. TikTok's library often lacks destination URLs, which is one reason
the AI reads ad images. Organic (non-ad) posts are only covered through
submissions.

### The AI layer (`scamtrace/ai.py`)

A vision language model analyses two kinds of input and returns structured
output through a forced tool call. The model is **pluggable**
(`SCAMTRACE_PROVIDER` in `.env`):

| Provider | What it is | Needs |
|---|---|---|
| `claude` (default) | Anthropic Claude | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI GPT models | `OPENAI_API_KEY`, `SCAMTRACE_MODEL` |
| `gemini` | Google Gemini (OpenAI-compatible endpoint) | `GEMINI_API_KEY`, `SCAMTRACE_MODEL` |
| `ollama` | Open-weights vision models running on your own machine | Ollama running, `SCAMTRACE_MODEL` |
| `openai_compatible` | Any other OpenAI-compatible server, e.g. vLLM or a hosted open model | `SCAMTRACE_BASE_URL`, `SCAMTRACE_MODEL` |
| `heuristic` | Keyword scorer, no model | nothing |

It analyses:

* **Posts and ads**: verdict and likelihood, scam type (investment,
  purchase, job, romance, impersonation, giveaway, loan, rental), who it
  impersonates, red flags with quotes, calls to action (link, WhatsApp,
  Telegram, DM), and payment details visible in the caption **or the
  screenshot**.
* **Payment pages** reached by the crawler: text plus screenshot, so bank
  details shown only as an image are still captured.

Safeguards:

* **Untrusted content.** Posts and pages are wrapped as data, and the model
  is told to ignore instructions inside them (prompt injection).
* **No identifier is trusted from the model.** Every account number, IBAN
  or wallet it reports is re-checked by deterministic validators (mod-97,
  base58/bech32 checksums, UK formats). Anything that fails is shown as
  "unverified" and never stored as a payee.
* **Offline fallback.** Without an API key a transparent keyword heuristic
  runs instead. It is text-only and is the baseline the AI must beat.

### Choosing a model, and the path to our own models

`python -m scamtrace.evaluate` scores any set of providers on a labelled
set of posts and writes `results.md`, `results.csv` and per-post details:

```bash
python eval/make_sample.py      # 14 synthetic posts: shows the format only
python -m scamtrace.evaluate eval/sample.jsonl \
    --providers claude,openai:MODEL,gemini:MODEL,ollama:MODEL,heuristic
```

It reports scam-detection precision, recall and F1; scam-type accuracy;
how many expected payment details the full pipeline found and how many it
found wrongly; errors; seconds per post; tokens; and cost if you supply a
price file (`--prices`). Prices are not built in because they change.

**Use a real labelled set for decisions.** Fourteen synthetic posts show
the format but cannot rank models. Aim for at least 200 real posts (about
half scams, half genuine posts that look similar: sales, jobs, savings
products, private sellers), labelled and double-checked. Keep real data in
`eval/real/`, which git ignores, because screenshots can contain personal
data.

Plan: frontier models label data and handle rare cases now. Analyst-
confirmed labels build a proprietary dataset. Smaller in-house models
(scam-post classifier, screenshot payment-detail extractor, mule-risk
scorer) are trained on it and run on our own infrastructure, which also
keeps payment-firm data away from outside providers. This script is how
each in-house model is judged against the frontier models before it
replaces them.

### Linking into campaigns (`cluster.py`)

Sightings are linked when they share a payment detail, a WhatsApp number or
Telegram handle, a social account, a website, or a page template (one scam
kit re-skinned on many domains). One mule account seen in a TikTok
screenshot therefore links to every site, wallet and post of the same group.

### Privacy by design

Identifiers are stored only as keyed hashes (HMAC-SHA256) plus a masked form
(`**-**-34 ****6819`). All stored free text (page text, captions, AI
output) is scrubbed of anything that looks like an account number, IBAN or
wallet. A test checks that the database holds no full identifier.

## Run it

```bash
bash setup_mac.sh                  # one-time: venv, dependencies, browser
source .venv/bin/activate
cp .env.example .env               # then paste your ANTHROPIC_API_KEY into .env

python demo/run_demo.py            # end-to-end demo, writes demo/output/
python -m pytest                   # 35 tests, no network or API key needed
bash run_api.sh                    # API on the demo data: http://127.0.0.1:8000/docs
```

Pull real ads once you have library access (tokens in `.env`):

```bash
python -m scamtrace.sources.pull meta   "ai trading"     --countries GB,IE
python -m scamtrace.sources.pull tiktok "clearance sale" --country GB
```

Submit a post (base64 screenshots):

```bash
curl -X POST localhost:8000/v1/sightings/social -H 'X-API-Key: demo-key' \
  -H 'content-type: application/json' \
  -d '{"submission_id":"SUB-9","post_url":"https://www.tiktok.com/@x/video/1",
       "screenshots_b64":["'"$(base64 -i post.png)"'"]}'
```

## The demo

`demo/make_sites.py` builds five synthetic websites, four post screenshots,
and records shaped like the Meta and TikTok API responses.

| Item | What it shows |
|---|---|
| Instagram ad (Meta record) for "QuantumYield" | Ad → link caption → investment site → bank account + USDT wallet; joins the investment campaign |
| TikTok ad (TikTok record), image only | Advertiser + destination → hot-tub shop → mule account; joins the purchase campaign |
| TikTok post, **details only in the screenshot** | With AI on: Claude reads the sort code and account from the image and the post joins the purchase campaign. With AI off: nothing found |
| Instagram job-scam post | Telegram handle + USDT wallet → new "job" campaign |
| Instagram bakery post, legitimate shop | Control cases: no payment details flagged |

## What is not built yet, and open questions

* **Data access.** Confirm Meta and TikTok library terms allow this
  commercial use, and how much UK scam content each covers. Agree
  submission feeds with payment-firm pilots.
* **Legal review**: automated visits to scam sites, the decoy-form approach,
  UK GDPR for receiving-account data (lawful basis, DPIA, retention), and
  the risk of flagging an account that was hijacked or reused.
* **Video.** TikTok ads are mostly video. The prototype reads images and
  video cover frames only. Next steps: sampled frames and speech-to-text.
* **Accuracy on real data**: build the real labelled set and run the
  evaluation script across providers and the keyword baseline.
* **In-house models**: train and evaluate the first specialised model
  (scam-post classifier) once enough confirmed labels exist.
* **Stable campaign IDs**: a campaign's ID can change when two campaigns
  merge. Production needs a persistent ID with merge history.
* **Bank-grade engineering**: UK modulus checking, client-side hashed
  queries so raw details never leave the payment firm, webhooks, audit
  logs, security assurance.
