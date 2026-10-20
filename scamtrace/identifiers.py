"""Payment identifiers: validation, normalisation, hashing and masking.

Every identifier is reduced to a canonical string, then to a keyed hash
(HMAC-SHA256). Only the hash and a masked form are stored, so the
database never holds a raw account number or wallet address.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass

# ---------------------------------------------------------------- hashing

_DEFAULT_KEY = "dev-only-change-me"


def _key() -> bytes:
    return os.environ.get("SCAMTRACE_HASH_KEY", _DEFAULT_KEY).encode()


def token_for(canonical: str) -> str:
    return hmac.new(_key(), canonical.encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------ data model

KINDS = ("uk_account", "iban", "btc", "eth", "tron", "payment_link")


@dataclass(frozen=True)
class Identifier:
    kind: str
    canonical: str  # never persisted
    masked: str

    @property
    def token(self) -> str:
        return token_for(self.canonical)


# ------------------------------------------------------------- UK bank


def uk_account(sort_code: str, account_number: str) -> Identifier | None:
    sc = re.sub(r"\D", "", sort_code or "")
    an = re.sub(r"\D", "", account_number or "")
    if len(sc) != 6:
        return None
    # UK account numbers are 8 digits; some banks print 7 and pad with a 0.
    if len(an) == 7:
        an = "0" + an
    if len(an) != 8:
        return None
    return Identifier(
        "uk_account",
        f"{sc}:{an}",
        f"**-**-{sc[4:]} ****{an[4:]}",
    )


# ------------------------------------------------------------------ IBAN

_IBAN_LEN = {"GB": 22, "IE": 22, "DE": 22, "FR": 27, "ES": 24, "IT": 27,
             "NL": 18, "LT": 20, "LV": 21, "EE": 20, "PT": 25, "BE": 16,
             "MT": 31, "CY": 28, "PL": 28, "AE": 23, "TR": 26}


def iban_checksum_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    digits = "".join(str(int(c, 36)) for c in s)
    return int(digits) % 97 == 1


def iban(raw: str) -> Identifier | None:
    s = re.sub(r"\s", "", raw or "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{8,30}", s):
        return None
    expected = _IBAN_LEN.get(s[:2])
    if expected and len(s) != expected:
        return None
    if not iban_checksum_ok(s):
        return None
    return Identifier("iban", s, f"{s[:4]}…{s[-4:]}")


def iban_with_check_digits(country: str, bban: str) -> str:
    """Build a valid IBAN (used to make synthetic test data)."""
    s = bban + country + "00"
    digits = "".join(str(int(c, 36)) for c in s)
    check = 98 - int(digits) % 97
    return f"{country}{check:02d}{bban}"


# ------------------------------------------------------------- base58

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode_check(s: str) -> bytes | None:
    n = 0
    for c in s:
        i = _B58.find(c)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    body, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
        return None
    return body


def b58encode_check(body: bytes) -> str:
    raw = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


# ------------------------------------------------------------- bech32

_BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_ok(addr: str) -> bool:
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return False
    hrp, data = addr[:pos], addr[pos + 1:]
    if any(c not in _BECH for c in data):
        return False
    values = [_BECH.index(c) for c in data]
    # bech32 (const 1) for segwit v0, bech32m for v1+
    return _polymod(_hrp_expand(hrp) + values) in (1, 0x2BC830A3)


def bech32_encode(hrp: str, data5: list[int]) -> str:
    """Build a valid bech32 string (used to make synthetic test data)."""
    values = _hrp_expand(hrp) + data5
    pm = _polymod(values + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH[d] for d in data5 + checksum)


# ------------------------------------------------------------- wallets


def btc(addr: str) -> Identifier | None:
    if addr.lower().startswith("bc1"):
        if not bech32_ok(addr):
            return None
        canon = addr.lower()
    else:
        body = b58decode_check(addr)
        if body is None or len(body) != 21 or body[0] not in (0x00, 0x05):
            return None
        canon = addr
    return Identifier("btc", canon, f"{canon[:6]}…{canon[-4:]}")


def eth(addr: str) -> Identifier | None:
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", addr or ""):
        return None
    canon = addr.lower()
    if len(set(canon[2:])) < 4:  # 0x000…0 style placeholders
        return None
    return Identifier("eth", canon, f"{canon[:6]}…{canon[-4:]}")


def tron(addr: str) -> Identifier | None:
    body = b58decode_check(addr or "")
    if body is None or len(body) != 21 or body[0] != 0x41:
        return None
    return Identifier("tron", addr, f"{addr[:5]}…{addr[-4:]}")


# -------------------------------------------------------- payment links

PAYMENT_LINK_HOSTS = (
    "paypal.me", "www.paypal.me", "monzo.me", "revolut.me",
    "buy.stripe.com", "checkout.stripe.com", "pay.sumup.com",
    "wise.com/pay", "link.payoneer.com",
)


def payment_link(url: str) -> Identifier | None:
    u = re.sub(r"^https?://", "", (url or "").strip(), flags=re.I)
    u = u.split("?")[0].split("#")[0].rstrip("/")
    low = u.lower()
    if not any(low.startswith(h + "/") for h in PAYMENT_LINK_HOSTS):
        return None
    if low.count("/") < 1 or len(low.split("/")[-1]) < 2:
        return None
    host = low.split("/")[0]
    return Identifier("payment_link", low, f"{host}/…{low[-4:]}")


# ------------------------------------------------------ query parsing


def from_query(q: dict) -> Identifier | None:
    """Build an identifier from an API check-payee request body."""
    if q.get("sort_code") or q.get("account_number"):
        return uk_account(q.get("sort_code", ""), q.get("account_number", ""))
    if q.get("iban"):
        return iban(q["iban"])
    if q.get("wallet"):
        w = q["wallet"].strip()
        return eth(w) or tron(w) or btc(w)
    if q.get("payment_link"):
        return payment_link(q["payment_link"])
    return None
