"""釣魚郵件風險評分引擎（不依賴資料庫，方便測試與離線評估）。

評分流程：
1. 寄件者檢查：黑名單 +100、可疑模式 +20、信任網域 0
2. 內容關鍵字：每個命中的關鍵字依權重加分（10 / 15 / 20），同一個字只算一次
3. 風險分級：>= 60 High、30~59 Medium、< 30 Low
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

BLACKLIST_SCORE = 100
SUSPICIOUS_SCORE = 20
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30

# 程式內建的可疑寄件者特徵（不在資料庫中）
SUSPICIOUS_LOCAL_PART = re.compile(
    r"(security|alert|notice|verify|login|suspend|urgent)", re.IGNORECASE
)
# 濫用率高的免費／廉價 TLD（移除了 v1 中的 .net、.info 等常見 TLD 以降低誤判）
SUSPICIOUS_TLDS = {"tk", "xyz", "top", "gq", "ml", "cf", "ga", "work", "click", "zip"}

CJK = re.compile(r"[぀-ヿ㐀-鿿豈-﫿]")
_ADDRESS_IN_BRACKETS = re.compile(r"<([^<>@\s]+@[^<>\s]+)>")


@dataclass(frozen=True)
class Keyword:
    text: str
    score: int
    category: str


@dataclass(frozen=True)
class SenderRule:
    """寄件者規則。pattern 可為完整地址、@domain，或含 % 萬用字元（SQL LIKE 語法）。"""

    pattern: str
    list_type: str  # blacklist | suspicious | trusted
    description: str = ""


@dataclass
class Finding:
    rule: str
    score: int
    detail: str


@dataclass
class AnalysisResult:
    email: str
    total_score: int
    risk_level: str
    sender_findings: list[Finding] = field(default_factory=list)
    keyword_hits: list[Finding] = field(default_factory=list)

    @property
    def is_phishing(self) -> bool:
        return self.risk_level in ("High", "Medium")

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "isPhishing": self.is_phishing,
            "totalScore": self.total_score,
            "riskLevel": self.risk_level,
            "senderFindings": [f.__dict__ for f in self.sender_findings],
            "keywordHits": [f.__dict__ for f in self.keyword_hits],
        }


def normalize_address(raw: str) -> str:
    """從 'Name <user@host>' 等格式取出小寫的 email 地址。"""
    raw = raw.strip()
    m = _ADDRESS_IN_BRACKETS.search(raw)
    return (m.group(1) if m else raw).strip().strip('"').lower()


def risk_level(total_score: int) -> str:
    if total_score >= HIGH_THRESHOLD:
        return "High"
    if total_score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def _rule_matches(pattern: str, address: str, domain: str) -> bool:
    pattern = pattern.lower()
    if "%" in pattern:
        return fnmatch.fnmatchcase(address, pattern.replace("%", "*"))
    if pattern.startswith("@"):
        # @example.com 同時涵蓋子網域，例如 mail.example.com
        return domain == pattern[1:] or domain.endswith("." + pattern[1:])
    return address == pattern


def compile_keyword(text: str) -> re.Pattern:
    """英文關鍵字以單字邊界比對，避免 'ach' 命中 'attached'；中文沒有詞邊界，直接比對子字串。"""
    escaped = re.escape(text.lower())
    if CJK.search(text):
        return re.compile(escaped)
    return re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")


_WORD = re.compile(r"[a-z0-9]+")


class Detector:
    def __init__(self, sender_rules: list[SenderRule], keywords: list[Keyword]):
        self.sender_rules = sender_rules
        # 單一英文單字用集合查詢（快），片語、網址、中文才用 regex；兩者比對結果相同
        self.word_keywords = {kw.text.lower(): kw for kw in keywords if _WORD.fullmatch(kw.text.lower())}
        self.pattern_keywords = [
            (kw, compile_keyword(kw.text)) for kw in keywords if not _WORD.fullmatch(kw.text.lower())
        ]

    def check_sender(self, address: str) -> list[Finding]:
        local, _, domain = address.rpartition("@")
        matched = [r for r in self.sender_rules if _rule_matches(r.pattern, address, domain)]

        for list_type in ("blacklist", "trusted"):
            rule = next((r for r in matched if r.list_type == list_type), None)
            if rule:
                if list_type == "trusted":
                    return []
                return [Finding("blacklist", BLACKLIST_SCORE, f"{rule.pattern}：{rule.description}")]

        reasons = [f"{r.pattern}：{r.description}" for r in matched if r.list_type == "suspicious"]
        if SUSPICIOUS_LOCAL_PART.search(local):
            reasons.append(f"寄件者名稱「{local}」含警示用語")
        tld = domain.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f"使用高濫用率的頂級網域 .{tld}")
        if reasons:
            return [Finding("suspicious", SUSPICIOUS_SCORE, "；".join(reasons))]
        return []

    def local_sender_list_type(self, address: str) -> str | None:
        """寄件者帳號在既有名單中的分類：blacklist / trusted / None。

        不含啟發式 suspicious（TLD、名稱警示詞）。供外部情資 router 判斷是否需查 IPQS：
        已在黑／白名單中就不查。黑名單優先於信任。
        """
        local, _, domain = address.rpartition("@")
        matched = {r.list_type for r in self.sender_rules if _rule_matches(r.pattern, address, domain)}
        if "blacklist" in matched:
            return "blacklist"
        if "trusted" in matched:
            return "trusted"
        return None

    def check_content(self, content: str) -> list[Finding]:
        text = content.lower()
        words = set(_WORD.findall(text))
        matched = [kw for word, kw in self.word_keywords.items() if word in words]
        matched += [kw for kw, pattern in self.pattern_keywords if pattern.search(text)]
        return [Finding(kw.category, kw.score, kw.text) for kw in matched]

    def analyze(self, email: str, content: str) -> AnalysisResult:
        address = normalize_address(email)
        sender = self.check_sender(address)
        hits = self.check_content(content)
        total = sum(f.score for f in sender) + sum(f.score for f in hits)
        return AnalysisResult(address, total, risk_level(total), sender, hits)
