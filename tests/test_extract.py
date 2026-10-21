import os

from scamtrace import identifiers as ids
from scamtrace.classify import classify
from scamtrace.cluster import campaigns, site_key
from scamtrace.extract import extract


def kinds(html):
    return sorted(f.identifier.kind for f in extract(html))


# --------------------------------------------------------- identifiers

def test_iban_checksum():
    good = ids.iban_with_check_digits("GB", "TEST00000112345678")
    assert ids.iban(good)
    bad = good[:-1] + ("0" if good[-1] != "0" else "1")
    assert ids.iban(bad) is None
    assert ids.iban("GB82 WEST 1234 5698 7654 32")  # textbook example


def test_wallets_need_valid_checksums():
    t = ids.b58encode_check(b"\x41" + os.urandom(20))
    assert ids.tron(t)
    assert ids.tron(t[:-1] + ("A" if t[-1] != "A" else "B")) is None
    b = ids.bech32_encode("bc", [0] + [i % 32 for i in range(32)])
    assert ids.btc(b)
    assert ids.btc(b[:-1] + ("q" if b[-1] != "q" else "p")) is None
    assert ids.eth("0x" + "0" * 40) is None  # placeholder address


def test_uk_account_normalisation_and_masking():
    a = ids.uk_account("00-12-34", "1926819")  # 7-digit account padded
    assert a.canonical == "001234:01926819"
    assert a.masked == "**-**-34 ****6819"
    assert ids.uk_account("12-34", "12345678") is None


def test_tokens_are_keyed_hashes():
    a = ids.uk_account("00-12-34", "31926819")
    t1 = a.token
    assert t1 != a.canonical and len(t1) == 64
    os.environ["SCAMTRACE_HASH_KEY"] = "other"
    try:
        assert ids.uk_account("00-12-34", "31926819").token != t1
    finally:
        del os.environ["SCAMTRACE_HASH_KEY"]


# ------------------------------------------------------------ extraction

def test_labelled_and_unlabelled_uk_details():
    assert kinds("<p>Sort code: 00-11-22</p><p>Account number: 87654321</p>") == ["uk_account"]
    assert kinds("send to 00-11-22 87654321 today") == ["uk_account"]
    assert kinds("sort code 00 11 22 acc 87654321") == ["uk_account"]


def test_no_false_positives_on_ordinary_numbers():
    html = ("<p>Company number 09876543. VAT GB 123 4567 89. Call 0117 496 0123."
            " Order 20261020 placed 12-03-2026.</p>")
    assert kinds(html) == []


def test_details_hidden_in_attributes_and_links():
    t = ids.b58encode_check(b"\x41" + os.urandom(20))
    html = f'<button data-copy="{t}">Copy</button><a href="https://paypal.me/deals4u">Pay</a>'
    assert kinds(html) == ["payment_link", "tron"]


def test_snippets_never_contain_full_numbers():
    t = ids.b58encode_check(b"\x41" + os.urandom(20))
    for f in extract(f"Sort code: 00-12-34 Account number: 31926819 USDT {t}"):
        assert "31926819" not in f.snippet and t not in f.snippet


# ---------------------------------------------------------- classify

def test_classifier():
    assert classify("AI trading platform, guaranteed daily returns, deposit now")["scam_type"] == "investment"
    c = classify("70% off clearance, free delivery. Bank transfer only.")
    assert c["scam_type"] == "purchase" and "bank transfer only" in c["pressure_tactics"]


# ----------------------------------------------------------- cluster

def test_site_key():
    assert site_key("https://shop.example.co.uk/x") == "example.co.uk"
    assert site_key("https://a.b.example.com/") == "example.com"


def test_campaigns_link_by_payee_site_and_template():
    kit = "join the ai trading platform everyone is talking about daily returns " * 3
    s = [
        {"id": "a", "tokens": {"T1"}, "urls": ["https://one.com"], "text": kit + "brand one"},
        {"id": "b", "tokens": {"T2"}, "urls": ["https://two.com"], "text": kit + "brand two"},
        {"id": "c", "tokens": {"T2", "T3"}, "urls": [], "text": ""},       # shares payee with b
        {"id": "d", "tokens": {"T4"}, "urls": ["https://shop.one.com"], "text": "garden"},  # same site as a
        {"id": "e", "tokens": {"T9"}, "urls": ["https://other.org"], "text": "unrelated"},
    ]
    groups = sorted(sorted(m) for m in campaigns(s).values())
    assert groups == [["a", "b", "c", "d"], ["e"]]


def test_iban_followed_by_words():
    good = ids.iban_with_check_digits("GB", "TEST00440155667788")
    assert kinds(f"pay the deposit to {good} I will post you the keys") == ["iban"]
    spaced = " ".join(good[i:i + 4] for i in range(0, len(good), 4))
    assert kinds(f"IBAN: {spaced} thank you") == ["iban"]
