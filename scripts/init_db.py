"""建立資料表並從 rules/*.csv 匯入規則（可重複執行，會覆蓋既有資料）。

用法：python scripts/init_db.py
連線參數讀取 DATABASE_URL 或 libpq 標準環境變數（PGHOST、PGUSER…）。
"""
import csv
import os
from contextlib import closing
from pathlib import Path

import psycopg2

ROOT = Path(__file__).resolve().parent.parent


def read_csv(name: str) -> list[dict]:
    with open(ROOT / "rules" / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main() -> None:
    senders = read_csv("senders.csv")
    keywords = read_csv("keywords.csv")
    with closing(psycopg2.connect(os.environ.get("DATABASE_URL", ""))) as conn, conn, conn.cursor() as cur:
        cur.execute((ROOT / "db" / "schema.sql").read_text(encoding="utf-8"))
        cur.execute("TRUNCATE sender_rules, phishing_keywords RESTART IDENTITY")
        cur.executemany(
            "INSERT INTO sender_rules (pattern, list_type, description) VALUES (%s, %s, %s)",
            [(r["pattern"], r["list_type"], r["description"]) for r in senders],
        )
        cur.executemany(
            "INSERT INTO phishing_keywords (keyword, score, category, source) VALUES (%s, %s, %s, %s)",
            [(r["keyword"], int(r["score"]), r["category"], r["source"]) for r in keywords],
        )
    print(f"已匯入 {len(senders)} 筆寄件者規則、{len(keywords)} 個關鍵字")


if __name__ == "__main__":
    main()
