# ScamTrace (prototype)

ScamTrace tells a payment firm, at the moment a payment is made or received,
whether the payee is collecting money for a **live scam advert campaign**,
and gives the firm an evidence pack it can use for mule-account reviews and
APP reimbursement claims.

It is built for smaller **receiving-side** firms (e-money institutions,
payment institutions, fintechs, crypto on-ramps) that now carry half of each
APP reimbursement but sit outside the large bank intelligence networks.

> Status: working prototype, October 2026. Everything in `demo/` is
> synthetic. It has not yet been run against live scam adverts.

## How it works

```
 scam advert ─▶ crawler ─▶ extractor ─▶ store (hashed) ─▶ campaign clustering
 (ad source)    headless    payment       SQLite            shared payee /
                browser     details                         same site /
                follows     + masked                        same page kit
                funnel to   context                               │
                payment                                           ▼
                                      payment firm ─▶ POST /v1/payee/check
                                                     GET  /v1/campaigns/{id}/evidence-pack
```

1. **Crawler** (`scamtrace/crawler.py`). A headless browser opens the
   advert's landing page and clicks through the funnel (Start / Register /
   Buy / Deposit ...) until payment details appear. It handles details that
   only appear after a click (JavaScript reveals). Forms are filled only with
   an obviously fake decoy profile (`example.invalid` email, Ofcom drama
   phone number); it never types card or bank data and never pays. Each step
   is recorded with time, URL, screenshot and page hash.
2. **Extractor** (`scamtrace/extract.py`, `identifiers.py`). Finds UK sort
   code + account number pairs (labelled or pasted together), IBANs
   (mod-97 checked), Bitcoin/Ethereum/TRON wallets (checksum validated) and
   payment links (PayPal.me, Monzo.me, Revolut.me, Stripe links ...). It
   also looks inside button and attribute values, where "copy address"
   widgets hide wallets. Phone numbers, company numbers, VAT numbers, dates
   and order references are not flagged.
3. **Privacy by design.** Identifiers are stored only as keyed hashes
   (HMAC-SHA256) plus a masked form (`**-**-34 ****6819`). Evidence snippets
   are masked. A database leak exposes no account numbers.
4. **Campaign clustering** (`cluster.py`). Sightings are linked when they
   share a payee, a website, or a page template (one scam kit re-skinned on
   many domains). A mule account seen once is thereby linked to every other
   account and wallet the same group uses.
5. **Scam typing** (`classify.py`). A transparent keyword scorer labels
   investment vs purchase scams and lists pressure tactics ("if your bank
   asks, say it is for a friend"). It is the baseline for the planned LLM
   classifier.
6. **API** (`api.py`, FastAPI). Payee check with risk level and a
   recommended action that differs for inbound (mule risk) and outbound
   (customer about to pay) payments. Victim and partner reports can be
   added; they raise risk to "medium" until the payee is seen on a live
   scam page ("high").
7. **Evidence pack** (`evidence.py`). JSON for systems; HTML with
   embedded screenshots for analysts handling a claim.

## Run it

```bash
pip install -e ".[dev]"
python -m playwright install chromium

python demo/run_demo.py          # end-to-end demo, writes demo/output/
python -m pytest                 # 16 tests

uvicorn scamtrace.api:app        # then open http://127.0.0.1:8000/docs
```

Example check:

```bash
curl -X POST localhost:8000/v1/payee/check -H 'X-API-Key: demo-key' \
  -H 'content-type: application/json' \
  -d '{"sort_code":"00-90-12","account_number":"40404017","direction":"inbound"}'
```

Environment: `SCAMTRACE_HASH_KEY` (secret for hashing; set it in any real
deployment), `SCAMTRACE_API_KEYS`, `SCAMTRACE_DB`, `SCAMTRACE_EVIDENCE`.

## The demo

`demo/make_sites.py` builds five synthetic sites: one investment-scam kit
under two brands with different bank accounts but a shared USDT wallet, two
different-looking purchase-scam shops that share one mule account, and a
legitimate shop as a control. Sort codes start `00`, IBANs use bank code
`TEST`, wallets are random keys. Result of the demo run:

| Check | Result |
|---|---|
| Ads crawled to the payment step | 4 of 4 scam ads; 0 details flagged on the legitimate shop |
| Campaigns found | 2 scam campaigns from 4 sites, plus 1 victim-report-only |
| Investment-scam account (site A) | high risk, linked to site B's account and the wallet |
| Purchase-scam mule account | high risk, 2 websites |
| Account only in a victim report | medium risk |
| Unknown account | no match |

## What is not built yet, and open questions

These are honest gaps, listed so they can be tested and answered:

- **Advert source.** The crawler takes an advert's landing URL. Getting
  those URLs at scale is the main open question: platform ad libraries and
  their API access rules differ by country and ad type and must be checked
  for the UK, along with platform terms. Alternatives: partner and victim
  report feeds, search-ad monitoring, URL feeds from takedown and
  threat-intelligence providers.
- **Legal review** of automated crawling of scam sites, the decoy-form
  approach, and processing data about receiving accounts (UK GDPR lawful
  basis, DPIA, retention, and the risk of flagging a wrongly reused or
  hijacked account).
- **Details shown in images** (screenshots of bank details) need OCR, and
  details given only in chat after signup are out of scope by design.
- **LLM layer**: page understanding for messy instructions, scam-type
  classification, and summarising campaigns. The keyword classifier is the
  baseline it must beat.
- **Accuracy on real data**: precision of the extractor and clustering on
  a labelled sample of real scam and legitimate pages.
- **Bank-grade engineering**: UK modulus checking of account numbers,
  client-side hashed queries so raw details never leave the payment firm,
  webhooks for new campaigns, audit logging, and security assurance.
