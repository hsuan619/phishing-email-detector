"""忠實重現比賽版（v1.0-competition）app.py 的評分邏輯，作為評估基準。

刻意保留原版行為，包括：
- 關鍵字用子字串比對（'ach' 會命中 'attached'）
- 黑名單查詢為 `email_pattern = email OR email_pattern LIKE '@domain'`，
  參數沒有萬用字元，因此 'mailserveralert@%' 這類規則永遠不會命中
- 寄件者 email 不做大小寫正規化
"""
from __future__ import annotations

import csv
import re

from dataset import ROOT

SUSPICIOUS_PATTERNS = [
    re.compile(r"(security|alert|notice|update|verify|account|login|service)", re.IGNORECASE),
    re.compile(r"\.(cn|tk|xyz|biz|info|net|top|gq|work)$", re.IGNORECASE),
]


class LegacyDetector:
    def __init__(self):
        with open(ROOT / "rules" / "keywords_v1.csv", newline="", encoding="utf-8") as f:
            self.keywords = [(r["keyword"].lower(), int(r["score"])) for r in csv.DictReader(f)]
        # v1 只有 is_blacklist 欄位，對應到 v2 的 list_type == 'blacklist'
        with open(ROOT / "rules" / "senders.csv", newline="", encoding="utf-8") as f:
            self.blacklist = {r["pattern"] for r in csv.DictReader(f) if r["list_type"] == "blacklist"}

    def score(self, email: str, content: str) -> int:
        email = email.strip()
        content = content.lower()
        domain = email.split("@")[-1] if "@" in email else ""
        name = email.split("@")[0] if "@" in email else ""
        total = 0
        if email in self.blacklist or f"@{domain}" in self.blacklist:
            total += 100
        if total < 100 and any(p.search(name) or p.search(domain) for p in SUSPICIOUS_PATTERNS):
            total += 20
        total += sum(score for kw, score in self.keywords if kw in content)
        return total
