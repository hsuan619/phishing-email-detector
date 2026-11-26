"""寄件者外部情資 router 與風險融合（Tool Router + Risk Fusion）。

流程：帳號在本地名單（黑／白）→ 不查；否則先查快取，快取 miss 再呼叫 IPQS；
只有 IPQS 確認風險才寫入快取。查無紀錄或查詢失敗都不寫正向快取、不表示安全。
"""
from __future__ import annotations

import logging
import os
from contextlib import closing

import psycopg2

import cache
import ipqs
import llm

log = logging.getLogger(__name__)

CACHE_TTL_DAYS = 14
_PLACEHOLDER_KEY = "your_ipqs_api_key_here"


def query_sender_intel(get_conn, detector, address: str) -> tuple[dict, dict]:
    """回傳 (senderIntel, databaseUpdate)。get_conn 為「取得新連線」的 callable。"""
    if not address:
        return {"status": "not_provided"}, {"status": "NOT_UPDATED"}

    local = detector.local_sender_list_type(address)
    if local is not None:
        return ({"status": "skipped", "detail": f"帳號已在本地 {local} 名單，未再查外部情資"},
                {"status": "NOT_UPDATED"})

    # 先查快取（lazy 失效：過期／撤銷視為 miss）。免資料庫模式（get_conn 為 None）跳過。
    cached = None
    if get_conn is not None:
        try:
            with closing(get_conn()) as conn:
                cached = cache.lookup(conn, "EMAIL", address, "IPQS")
        except psycopg2.Error:
            log.exception("快取查詢失敗")
            cached = None
    if cached:
        return ({"status": "cache_hit", "verdict": cached["verdict"], "source": "IPQS",
                 "category": cached["threatCategory"], "evidence": cached["evidence"],
                 "lastVerified": cached["lastVerified"]},
                {"status": "CACHE_HIT"})

    api_key = os.environ.get("IPQS_API_KEY", "")
    if not api_key or api_key == _PLACEHOLDER_KEY:
        return ({"status": "not_configured", "detail": "未設定 IPQS_API_KEY，略過外部查詢"},
                {"status": "NOT_UPDATED"})

    try:
        raw = ipqs.check_email(address, api_key=api_key)
    except Exception:  # 網路／逾時／回應格式
        log.exception("IPQS 查詢失敗")
        return ({"status": "error", "detail": "IPQS 查詢失敗或逾時，外部驗證未完成"},
                {"status": "NOT_UPDATED"})

    ev = ipqs.evidence(raw)
    if not ipqs.is_confirmed_risk(raw):
        return ({"status": "no_known_abuse", "source": "IPQS",
                 "detail": "IPQS 查無近期濫用紀錄，仍無法確認其安全性", "evidence": ev},
                {"status": "NOT_UPDATED"})

    # 確認風險 → 寫入快取（免資料庫模式無法持久化，回報已確認但未寫入）
    if get_conn is None:
        return ({"status": "confirmed", "verdict": "CONFIRMED_RISK", "source": "IPQS",
                 "category": "ACCOUNT_ABUSE", "evidence": ev, "detail": "免資料庫模式，未寫入快取"},
                {"status": "NOT_UPDATED"})
    try:
        with closing(get_conn()) as conn:
            action = cache.upsert(conn, "EMAIL", address, "IPQS",
                                  "CONFIRMED_RISK", "ACCOUNT_ABUSE", ev, CACHE_TTL_DAYS)
    except psycopg2.Error:
        log.exception("快取寫入失敗")
        return ({"status": "confirmed", "verdict": "CONFIRMED_RISK", "source": "IPQS",
                 "category": "ACCOUNT_ABUSE", "evidence": ev, "detail": "已確認風險，但寫入快取失敗"},
                {"status": "UPDATE_FAILED"})

    return ({"status": "confirmed", "verdict": "CONFIRMED_RISK", "source": "IPQS",
             "category": "ACCOUNT_ABUSE", "evidence": ev},
            {"status": action})


def apply_intel_to_risk(result: dict, sender_intel: dict) -> None:
    """風險融合：外部確認惡意 = 硬性覆蓋，整體升為 High（見 PRD §9）。"""
    if sender_intel.get("verdict") == "CONFIRMED_RISK":
        result["riskLevel"] = "High"
        result["isPhishing"] = True
        result.setdefault("overrides", []).append(
            "IPQS 確認寄件帳號近期濫用（ACCOUNT_ABUSE），整體風險升為 High"
        )


def analyze_content(email: str, content: str) -> tuple[dict | None, dict]:
    """本地 LLM 內容分析，回傳 (llmAnalysis, llmStatus)。

    無內容 → not_provided；Ollama 未回應或輸出不合格 → 略過，不擋整體流程（NFR-08 降級）。
    """
    if not content.strip():
        return None, {"status": "not_provided"}
    # gemma 為多語言模型，原生讀中文、寫繁中：不需翻譯，詐騙判斷與身分比對都在這一次呼叫完成。
    try:
        raw = llm.analyze_email(email, content)
    except Exception:  # Ollama 未啟動／模型未載入／逾時／回應格式
        log.exception("LLM 分析失敗")
        return None, {"status": "unavailable",
                      "detail": "本地 LLM 未回應（Ollama 未啟動或模型未載入），已略過"}
    errors = llm.validate(raw)
    if errors:
        return None, {"status": "invalid_output", "detail": "；".join(errors)}
    return raw, {"status": "ok"}


def apply_llm_to_risk(result: dict, llm_result: dict | None) -> None:
    """風險融合：LLM 判為詐騙時，最多把等級由 Low 提升到「可疑(Medium)」；不自動判惡意、不升 High（PRD §9）。"""
    if not llm_result or not llm_result.get("is_fraud"):
        return
    if result.get("riskLevel") == "Low":
        result["riskLevel"] = "Medium"
        result["isPhishing"] = True
        # 依使用者要求：不再於結果框顯示「LLM 判定為可疑」的 ＊ 訊息（AI 內容分析區已有判定）


def apply_identity_to_risk(result: dict, llm_result: dict | None) -> None:
    """寄件網域與內文自稱身分不符（MISMATCH，疑似冒充）→ v2 綠燈(Low) 升為「可疑」(Medium)；不自動判惡意。

    身分比對已併入 llm.analyze_email 的單次呼叫，不再另跑獨立的一致性檢查。
    """
    if not llm_result or llm_result.get("sender_identity_match") != "MISMATCH":
        return
    if result.get("riskLevel") == "Low":
        result["riskLevel"] = "Medium"
        result["isPhishing"] = True
