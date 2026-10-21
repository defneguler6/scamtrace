"""Compare AI models on a labelled set of posts.

    python -m scamtrace.evaluate eval/sample.jsonl \
        --providers claude,openai:MODEL,gemini:MODEL,ollama:MODEL,heuristic

Each provider is "name" or "name:model". Keys and URLs come from .env.

The labelled set is JSONL, one post per line:

    {"id": "p1", "platform": "tiktok", "text": "caption or ad text",
     "images": ["images/p1.png"],              # paths relative to the file
     "label": "scam" | "legitimate",
     "scam_type": "purchase",                   # optional, for scams
     "payment_details": [{"kind": "uk_account", "value": "00-90-12 40404017"}]}

Scores per provider:
  * scam detection: precision, recall, F1 (scam = likelihood >= --threshold)
  * scam type accuracy on labelled scams
  * payment details: share of expected details found, and share of found
    details that were expected (the full pipeline: text extraction plus
    model output, each re-validated)
  * errors, mean and p95 seconds per post, tokens, and cost if prices are
    given (--prices prices.json: {"provider:model": {"input_per_mtok": x,
    "output_per_mtok": y}}). Prices are not built in because they change.

Writes results.md, results.csv and details.jsonl to --out.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from dataclasses import dataclass, field
from pathlib import Path

from . import ai, identifiers as ids
from .extract import extract


@dataclass
class Item:
    id: str
    label: str
    text: str = ""
    platform: str = ""
    images: list[bytes] = field(default_factory=list)
    scam_type: str | None = None
    expected: set[str] = field(default_factory=set)   # identifier tokens


def load(path: str | Path) -> list[Item]:
    path = Path(path)
    items = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        r = json.loads(line)
        if r.get("label") not in ("scam", "legitimate"):
            raise ValueError(f"line {n}: label must be 'scam' or 'legitimate'")
        expected = set()
        for p in r.get("payment_details", []):
            found = ai._validate_one(p["kind"], p["value"])
            if not found:
                raise ValueError(f"line {n}: payment detail {p['kind']} does not validate")
            expected |= {i.token for i in found}
        items.append(Item(
            id=str(r["id"]), label=r["label"], text=r.get("text", ""),
            platform=r.get("platform", ""), scam_type=r.get("scam_type"),
            images=[(path.parent / im).read_bytes() for im in r.get("images", [])],
            expected=expected))
    return items


def _predicted_tokens(analysis: dict, text: str) -> set[str]:
    found = {f.identifier.token for f in extract(text)
             if f.identifier.kind in ids.PAYMENT_KINDS}
    pay, _ = ai.payment_findings(analysis)
    return found | {f.identifier.token for f in pay}


def run(analyser, items: list[Item], threshold: float = 0.5) -> tuple[dict, list[dict]]:
    rows, secs, tin, tout = [], [], 0, 0
    tp = fp = fn = tn = errors = 0
    type_ok = type_n = 0
    exp_total = exp_found = pred_total = pred_correct = 0
    for it in items:
        row = {"id": it.id, "label": it.label}
        try:
            a = analyser.analyse("social_post", it.text, it.images, {"platform": it.platform})
        except Exception as e:  # count, keep going
            errors += 1
            row.update(error=str(e)[:300])
            a = None
        if a is None:
            is_scam = False
            pred = set()
        else:
            u = a.get("usage", {})
            secs.append(u.get("seconds", 0.0))
            tin += u.get("input_tokens", 0)
            tout += u.get("output_tokens", 0)
            is_scam = a.get("scam_likelihood", 0) >= threshold
            pred = _predicted_tokens(a, it.text)
            row.update(verdict=a.get("verdict"), likelihood=a.get("scam_likelihood"),
                       scam_type=a.get("scam_type"))
        truth = it.label == "scam"
        tp += truth and is_scam
        fp += (not truth) and is_scam
        fn += truth and not is_scam
        tn += (not truth) and not is_scam
        if truth and it.scam_type and a is not None:
            type_n += 1
            type_ok += a.get("scam_type") == it.scam_type
        exp_total += len(it.expected)
        exp_found += len(it.expected & pred)
        pred_total += len(pred)
        pred_correct += len(pred & it.expected)
        row.update(predicted_scam=is_scam, expected_payment_details=len(it.expected),
                   found=len(it.expected & pred), extra=len(pred - it.expected))
        rows.append(row)

    def ratio(a, b):
        return round(a / b, 3) if b else None

    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = (round(2 * precision * recall / (precision + recall), 3)
          if precision and recall else None)
    metrics = {
        "n": len(items), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "errors": errors,
        "precision": precision, "recall": recall, "f1": f1,
        "type_accuracy": ratio(type_ok, type_n),
        "payment_recall": ratio(exp_found, exp_total),
        "payment_precision": ratio(pred_correct, pred_total),
        "mean_seconds": round(statistics.mean(secs), 2) if secs else None,
        "p95_seconds": round(sorted(secs)[max(0, math.ceil(0.95 * len(secs)) - 1)], 2) if secs else None,
        "input_tokens": tin, "output_tokens": tout,
    }
    return metrics, rows


def _analyser_for(spec: str):
    name, _, model = spec.partition(":")
    return ai.make_analyser(name, model or None)


COLUMNS = ["provider", "n", "precision", "recall", "f1", "type_accuracy",
           "payment_recall", "payment_precision", "errors", "mean_seconds",
           "p95_seconds", "input_tokens", "output_tokens", "cost_usd"]


def _fmt(v):
    return "–" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dataset")
    p.add_argument("--providers", default="claude,heuristic")
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--prices", help="JSON file of prices per million tokens")
    p.add_argument("--out", default="eval/results")
    a = p.parse_args(argv)

    items = load(a.dataset)
    prices = json.loads(Path(a.prices).read_text()) if a.prices else {}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"{len(items)} posts ({sum(i.label == 'scam' for i in items)} scams) from {a.dataset}")

    results, details = [], []
    for spec in a.providers.split(","):
        spec = spec.strip()
        try:
            analyser = _analyser_for(spec)
        except Exception as e:
            print(f"- {spec}: skipped ({e})")
            continue
        label = spec if analyser.engine == "heuristic" else f"{analyser.engine}:{analyser.model}"
        print(f"- {label}: running …")
        m, rows = run(analyser, items, a.threshold)
        price = prices.get(label)
        m["cost_usd"] = (round(m["input_tokens"] / 1e6 * price["input_per_mtok"] +
                               m["output_tokens"] / 1e6 * price["output_per_mtok"], 4)
                         if price else None)
        m["provider"] = label
        results.append(m)
        details += [{"provider": label, **r} for r in rows]

    md = ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    md += ["| " + " | ".join(_fmt(r.get(c)) for c in COLUMNS) + " |" for r in results]
    note = (f"\nThreshold {a.threshold}. Small samples give wide error bars: "
            f"treat differences of a few posts as noise.\n")
    (out / "results.md").write_text("\n".join(md) + "\n" + note)
    with open(out / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)
    (out / "details.jsonl").write_text("\n".join(json.dumps(d) for d in details) + "\n")
    print("\n" + "\n".join(md) + note)
    print(f"Saved to {out}/")


if __name__ == "__main__":
    main()
