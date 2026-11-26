"""從 CSV（rules/）或 PostgreSQL 載入偵測規則。"""
from __future__ import annotations

import csv
from pathlib import Path

from detector import Keyword, SenderRule

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def load_keywords_csv(path: Path = RULES_DIR / "keywords.csv") -> list[Keyword]:
    with open(path, newline="", encoding="utf-8") as f:
        return [Keyword(r["keyword"], int(r["score"]), r["category"]) for r in csv.DictReader(f)]


def load_senders_csv(path: Path = RULES_DIR / "senders.csv") -> list[SenderRule]:
    with open(path, newline="", encoding="utf-8") as f:
        return [SenderRule(r["pattern"], r["list_type"], r["description"]) for r in csv.DictReader(f)]


def load_from_db(conn) -> tuple[list[SenderRule], list[Keyword]]:
    with conn.cursor() as cur:
        cur.execute("SELECT pattern, list_type, description FROM sender_rules")
        senders = [SenderRule(*row) for row in cur.fetchall()]
        cur.execute("SELECT keyword, score, category FROM phishing_keywords")
        keywords = [Keyword(*row) for row in cur.fetchall()]
    return senders, keywords


def add_sender_db(conn, pattern: str, list_type: str, description: str) -> bool:
    """新增一筆寄件者規則到 DB；同 pattern+list_type 已存在則不加。回傳是否真的新增。"""
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM sender_rules WHERE pattern=%s AND list_type=%s LIMIT 1",
                    (pattern, list_type))
        if cur.fetchone():
            return False
        cur.execute("INSERT INTO sender_rules (pattern, list_type, description) VALUES (%s, %s, %s)",
                    (pattern, list_type, description))
    return True


def append_sender_csv(pattern: str, list_type: str, description: str,
                      path: Path = RULES_DIR / "senders.csv") -> bool:
    """附加一筆寄件者規則到 CSV（免資料庫模式）；同 pattern+list_type 已存在則不加。回傳是否真的新增。"""
    existing = {(r.pattern.lower(), r.list_type) for r in load_senders_csv(path)}
    if (pattern.lower(), list_type) in existing:
        return False
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([pattern, list_type, description])
    return True
