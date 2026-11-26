"""IPQualityScore 寄件者帳號信譽查詢（Provider Adapter）。

只負責呼叫 IPQS Email Validation API 並萃取最小必要證據，
不決定要不要查詢、也不寫資料庫——那是 router（intel.py）的職責。
用 urllib（標準庫）呼叫，不新增相依套件。
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

API_URL = "https://www.ipqualityscore.com/api/json/email"
TIMEOUT_SECONDS = 8
# recent_abuse 為真且 fraud_score 達此門檻才視為已確認風險（門檻待以誤判測試校準）
FRAUD_SCORE_THRESHOLD = 85
# 寫入快取時只保留這些欄位作為證據，不存整包回應、不存個資
EVIDENCE_FIELDS = ("recent_abuse", "fraud_score", "suspect", "leaked", "valid", "disposable")


def check_email(email: str, *, api_key: str, opener=urllib.request.urlopen) -> dict:
    """呼叫 IPQS，回傳原始 JSON dict。opener 可注入以便測試，不實際連網。"""
    key = urllib.parse.quote(api_key, safe="")
    addr = urllib.parse.quote(email, safe="")
    with opener(f"{API_URL}/{key}/{addr}", timeout=TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


def is_confirmed_risk(raw: dict) -> bool:
    """近期濫用且 fraud_score 達門檻才算已確認風險（ACCOUNT_ABUSE）。"""
    return bool(raw.get("recent_abuse")) and float(raw.get("fraud_score") or 0) >= FRAUD_SCORE_THRESHOLD


def evidence(raw: dict) -> dict:
    """萃取最小必要證據（不存整包回應、不存個資）。"""
    return {k: raw[k] for k in EVIDENCE_FIELDS if k in raw}
