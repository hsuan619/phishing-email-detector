"""威脅情資快取（Threat Intelligence Cache）的讀取與 upsert。

讀取採 lazy 失效：只回傳未撤銷且未過期的有效紀錄，過期／撤銷視為 miss，
由 router 重新查詢後 upsert 刷新。不需要背景清理程式。
"""
from __future__ import annotations

from psycopg2.extras import Json

_COLUMNS = ("indicatorType", "indicatorValue", "source", "verdict", "threatCategory",
            "evidence", "firstSeen", "lastVerified", "expiresAt")


def lookup(conn, indicator_type: str, indicator_value: str, source: str) -> dict | None:
    """回傳有效（未撤銷、未過期）的快取紀錄，否則 None。"""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT indicator_type, indicator_value, source, verdict, threat_category,
                   evidence, first_seen, last_verified, expires_at
            FROM threat_intel_cache
            WHERE indicator_type = %s AND indicator_value = %s AND source = %s
              AND verdict <> 'REVOKED'
              AND (expires_at IS NULL OR expires_at > now())
            """,
            (indicator_type, indicator_value, source),
        )
        row = cur.fetchone()
    if not row:
        return None
    rec = dict(zip(_COLUMNS, row))
    for ts in ("firstSeen", "lastVerified", "expiresAt"):
        if rec[ts] is not None:
            rec[ts] = rec[ts].isoformat()
    return rec


def upsert(conn, indicator_type: str, indicator_value: str, source: str,
           verdict: str, threat_category: str, evidence: dict, ttl_days: int) -> str:
    """寫入或更新快取並 commit，回傳 'INSERTED' 或 'UPDATED'。"""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO threat_intel_cache
                (indicator_type, indicator_value, source, verdict, threat_category, evidence, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, now() + make_interval(days => %s))
            ON CONFLICT (indicator_type, indicator_value, source) DO UPDATE SET
                verdict         = EXCLUDED.verdict,
                threat_category = EXCLUDED.threat_category,
                evidence        = EXCLUDED.evidence,
                last_verified   = now(),
                expires_at      = EXCLUDED.expires_at
            RETURNING (xmax = 0) AS inserted
            """,
            (indicator_type, indicator_value, source, verdict, threat_category, Json(evidence), ttl_days),
        )
        inserted = cur.fetchone()[0]
    conn.commit()
    return "INSERTED" if inserted else "UPDATED"
