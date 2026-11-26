"""Flask API 與前端靜態頁面。

每次請求都從 PostgreSQL 讀取最新規則，因此調整關鍵字庫或黑名單後不需重啟服務。
"""
import os
import re
from contextlib import closing
from pathlib import Path

import psycopg2
from flask import Flask, jsonify, request, send_from_directory


def _load_dotenv(env_path: Path | None = None) -> None:
    """載入專案根目錄 .env（若存在）。已在環境中的變數不覆蓋。無相依套件。

    app.py 讀的是環境變數；Windows 下 .env 不會自動生效，這個 loader 補上，
    讓 IPQS_API_KEY、OLLAMA_MODEL 等寫在 .env 就能被讀到。
    """
    env_path = env_path or (Path(__file__).resolve().parent.parent / ".env")
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())


_load_dotenv()

import intel  # noqa: E402  在 _load_dotenv 之後 import，確保讀得到 .env 的 OLLAMA_MODEL 等
from detector import Detector  # noqa: E402
from rules import (  # noqa: E402
    add_sender_db, append_sender_csv, load_from_db, load_keywords_csv, load_senders_csv,
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
MAX_CONTENT_LENGTH = 100_000  # 字元

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")


def get_connection():
    # 連線參數使用 libpq 標準環境變數：PGHOST、PGPORT、PGDATABASE、PGUSER、PGPASSWORD
    return psycopg2.connect(os.environ.get("DATABASE_URL", ""), connect_timeout=3)


def load_rules():
    """優先從 DB 載入規則；DB 連不上時 fallback 讀 rules/*.csv。

    回傳 (senders, keywords, db_ok)。db_ok=False（免資料庫模式）時情資快取停用。
    """
    try:
        with closing(get_connection()) as conn, conn:
            senders, keywords = load_from_db(conn)
        return senders, keywords, True
    except psycopg2.Error:
        app.logger.warning("DB 連線失敗，改用 rules/*.csv（免資料庫模式，情資快取停用）")
        return load_senders_csv(), load_keywords_csv(), False


@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.post("/api/check-phishing")
def check_phishing():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    content = str(data.get("content", ""))

    if not email and not content.strip():
        return jsonify({"error": "請至少提供寄件者 Email 或郵件內容"}), 400
    if len(content) > MAX_CONTENT_LENGTH:
        return jsonify({"error": f"郵件內容過長（上限 {MAX_CONTENT_LENGTH:,} 字元）"}), 413

    senders, keywords, db_ok = load_rules()
    detector = Detector(senders, keywords)
    result = detector.analyze(email, content).to_dict()

    # 寄件者外部情資（IPQS）：本地名單未命中才查快取，快取 miss 才呼叫 IPQS。
    # 免資料庫模式（db_ok=False）下不查／不寫快取；IPQS 若已設金鑰仍可查，但不快取。
    conn_factory = get_connection if db_ok else None
    sender_intel, db_update = intel.query_sender_intel(conn_factory, detector, result["email"])
    result["senderIntel"] = sender_intel
    result["databaseUpdate"] = db_update
    result["dbMode"] = "postgres" if db_ok else "csv-fallback"
    intel.apply_intel_to_risk(result, sender_intel)

    # 本地 LLM 內容分析（Ollama, gemma 單模型）：一次同時做詐騙判斷＋寄件身分比對，原生繁中；Ollama 未回應則略過
    llm_analysis, llm_status = intel.analyze_content(email, content)
    result["llmAnalysis"] = llm_analysis
    result["llmStatus"] = llm_status
    # v2 綠燈(Low) 才複核升級：LLM 判為詐騙、或寄件身分與內文自稱不符(MISMATCH) → 升為「可疑」(Medium)
    intel.apply_llm_to_risk(result, llm_analysis)
    intel.apply_identity_to_risk(result, llm_analysis)

    return jsonify(result)


_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")


def _to_domain_pattern(raw: str) -> str | None:
    """把寄件者地址或網域正規化成安全的 @domain 黑名單 pattern；非法則回 None。

    只允許標準網域字元（防止注入 % 萬用字元或任意 pattern）。取 @ 之後的部分，涵蓋整個網域。
    """
    domain = str(raw or "").strip().lower().rpartition("@")[2]
    return "@" + domain if _DOMAIN_RE.match(domain) else None


@app.post("/api/blocklist")
def add_blocklist():
    """使用者在前端確認後，把仿冒寄件網域加入黑名單（人工把關，非自動）。立即對後續請求生效。"""
    data = request.get_json(silent=True) or {}
    pattern = _to_domain_pattern(data.get("pattern") or data.get("email", ""))
    if not pattern:
        return jsonify({"error": "無效的網域"}), 400
    description = "使用者確認加入：仿冒寄件網域 (typosquatting)"
    try:
        with closing(get_connection()) as conn, conn:
            added = add_sender_db(conn, pattern, "blacklist", description)
        mode = "postgres"
    except psycopg2.Error:
        added = append_sender_csv(pattern, "blacklist", description)
        mode = "csv-fallback"
    return jsonify({"ok": True, "pattern": pattern, "added": added, "mode": mode})


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5001")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
