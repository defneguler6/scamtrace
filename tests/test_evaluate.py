"""Provider backends and the evaluation script, without network access."""

import json
from pathlib import Path

import httpx
import pytest

from scamtrace import ai, evaluate, identifiers as ids
from test_ai import PNG, analysis


def test_openai_compatible_backend_request_and_parse():
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        seen["auth"] = req.headers.get("Authorization")
        seen["body"] = json.loads(req.content)
        args = analysis(scam_type="job", impersonates="",
                        payment_instructions=[{"kind": "uk_account", "seen_in": "image",
                                               "raw": "00-21-43 66554433", "payee_name": ""}])
        return httpx.Response(200, json={
            "choices": [{"message": {"tool_calls": [{"function": {
                "name": "report_scam_analysis", "arguments": json.dumps(args)}}]}}],
            "usage": {"prompt_tokens": 1200, "completion_tokens": 300}})

    be = ai.OpenAICompatibleBackend("gemini", "some-model", api_key="k",
                                    http=httpx.Client(transport=httpx.MockTransport(handler)))
    out = ai.Analyser(backend=be).analyse("social_post", "hello", [PNG])
    assert seen["url"].startswith("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
    assert seen["auth"] == "Bearer k"
    body = seen["body"]
    assert body["model"] == "some-model"
    assert body["tool_choice"]["function"]["name"] == "report_scam_analysis"
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][1]["content"][0]["image_url"]["url"].startswith("data:image/png;base64,")
    assert out["engine"] == "gemini:some-model" and out["scam_type"] == "job"
    assert out["impersonates"] is None and out["payment_instructions"][0]["payee_name"] is None
    assert out["usage"]["input_tokens"] == 1200 and out["images_read"] is True


def test_openai_compatible_error_is_raised():
    be = ai.OpenAICompatibleBackend(
        "ollama", "llava", http=httpx.Client(transport=httpx.MockTransport(
            lambda r: httpx.Response(404, json={"error": {"message": "model not found"}}))))
    assert be.base_url == "http://localhost:11434/v1" and be.api_key is None
    with pytest.raises(RuntimeError, match="model not found"):
        ai.Analyser(backend=be).analyse("social_post", "x")


def test_make_analyser_config(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SCAMTRACE_MODEL", "SCAMTRACE_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    assert ai.make_analyser("heuristic").engine == "heuristic"
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        ai.make_analyser("claude")
    with pytest.raises(RuntimeError, match="SCAMTRACE_MODEL"):
        ai.make_analyser("openai")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    a = ai.make_analyser("openai", "m1")
    assert (a.engine, a.model) == ("openai", "m1")
    monkeypatch.setenv("SCAMTRACE_PROVIDER", "nonsense")
    assert ai.from_env().engine == "heuristic"  # falls back, never crashes


class Scripted:
    """Analyser double that answers from a table keyed by post text."""
    engine, model = "fake", "m"

    def __init__(self, answers):
        self.answers = answers

    def analyse(self, kind, text="", images=(), context=None):
        a = self.answers[text]
        if isinstance(a, Exception):
            raise a
        return {**a, "usage": {"seconds": 1.0, "input_tokens": 100, "output_tokens": 10}}


def test_evaluation_metrics(tmp_path):
    acct = "00-21-43 66554433"
    rows = [
        {"id": "a", "text": "A", "label": "scam", "scam_type": "purchase",
         "payment_details": [{"kind": "uk_account", "value": acct}]},
        {"id": "b", "text": "B", "label": "scam", "scam_type": "job"},
        {"id": "c", "text": "C", "label": "legitimate"},
        {"id": "d", "text": "D", "label": "legitimate"},
        {"id": "e", "text": "E", "label": "scam"},
    ]
    f = tmp_path / "set.jsonl"
    f.write_text("# comment\n" + "\n".join(json.dumps(r) for r in rows))
    items = evaluate.load(f)
    assert items[0].expected == {ids.uk_account("00-21-43", "66554433").token}

    answers = {
        "A": analysis(scam_likelihood=0.9, scam_type="purchase",
                      payment_instructions=[{"kind": "uk_account", "raw": acct, "seen_in": "image"}]),
        "B": analysis(scam_likelihood=0.8, scam_type="investment"),   # wrong type
        "C": analysis(scam_likelihood=0.7, scam_type="purchase"),     # false positive
        "D": analysis(scam_likelihood=0.1),
        "E": RuntimeError("timeout"),                                  # error = missed
    }
    m, details = evaluate.run(Scripted(answers), items)
    assert (m["tp"], m["fp"], m["fn"], m["tn"], m["errors"]) == (2, 1, 1, 1, 1)
    assert m["precision"] == round(2 / 3, 3) and m["recall"] == round(2 / 3, 3)
    assert m["type_accuracy"] == 0.5
    assert m["payment_recall"] == 1.0 and m["payment_precision"] == 1.0
    assert m["input_tokens"] == 400 and m["mean_seconds"] == 1.0
    assert details[4]["error"] == "timeout"


def test_invalid_label_or_detail_is_rejected(tmp_path):
    f = tmp_path / "bad.jsonl"
    f.write_text(json.dumps({"id": "x", "label": "maybe"}))
    with pytest.raises(ValueError, match="label"):
        evaluate.load(f)
    f.write_text(json.dumps({"id": "x", "label": "scam",
                             "payment_details": [{"kind": "iban", "value": "GB00NOPE"}]}))
    with pytest.raises(ValueError, match="does not validate"):
        evaluate.load(f)


def test_cli_writes_reports(tmp_path):
    root = Path(__file__).parent.parent
    sample = root / "eval" / "sample.jsonl"
    if not sample.exists():
        pytest.skip("run eval/make_sample.py first")
    evaluate.main([str(sample), "--providers", "heuristic", "--out", str(tmp_path)])
    assert "heuristic" in (tmp_path / "results.md").read_text()
    assert (tmp_path / "results.csv").read_text().startswith("provider,")
