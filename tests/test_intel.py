"""IPQS adapter、寄件者情資 router 與風險融合的單元測試（不需 DB／網路）。"""
import json

import psycopg2

import intel
import ipqs
import llm
import translator
from detector import Detector, SenderRule


def test_is_confirmed_risk_needs_abuse_and_high_score():
    assert ipqs.is_confirmed_risk({"recent_abuse": True, "fraud_score": 90})
    assert not ipqs.is_confirmed_risk({"recent_abuse": True, "fraud_score": 50})
    assert not ipqs.is_confirmed_risk({"recent_abuse": False, "fraud_score": 99})
    assert not ipqs.is_confirmed_risk({})


def test_evidence_keeps_only_minimal_fields():
    raw = {"recent_abuse": True, "fraud_score": 90, "first_name": "Jay", "sanitized_email": "a@b.com"}
    assert ipqs.evidence(raw) == {"recent_abuse": True, "fraud_score": 90}


def test_check_email_parses_response_and_does_not_log_key():
    captured = {}

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"recent_abuse": true, "fraud_score": 88}'

    def fake_opener(url, timeout=None):
        captured["url"] = url
        return FakeResp()

    raw = ipqs.check_email("evil@bad.com", api_key="SECRET", opener=fake_opener)
    assert raw["recent_abuse"] is True and raw["fraud_score"] == 88
    assert "SECRET" in captured["url"] and "evil%40bad.com" in captured["url"]


def test_local_sender_list_type():
    d = Detector([SenderRule("@paypalload.net", "blacklist", ""),
                  SenderRule("@paypal.com", "trusted", "")], [])
    assert d.local_sender_list_type("x@paypalload.net") == "blacklist"
    assert d.local_sender_list_type("x@paypal.com") == "trusted"
    assert d.local_sender_list_type("x@unknown.com") is None


def test_local_sender_list_type_blacklist_wins():
    d = Detector([SenderRule("@paypal.com", "trusted", ""),
                  SenderRule("evil@paypal.com", "blacklist", "")], [])
    assert d.local_sender_list_type("evil@paypal.com") == "blacklist"


def test_router_not_provided_when_no_address():
    si, db = intel.query_sender_intel(None, Detector([], []), "")
    assert si["status"] == "not_provided" and db["status"] == "NOT_UPDATED"


def test_router_skips_when_account_known_locally():
    d = Detector([SenderRule("@paypal.com", "trusted", "")], [])

    def boom():  # 不應被呼叫
        raise AssertionError("已在本地名單不該開連線")

    si, db = intel.query_sender_intel(boom, d, "ceo@paypal.com")
    assert si["status"] == "skipped" and db["status"] == "NOT_UPDATED"


def test_router_not_configured_without_key(monkeypatch):
    monkeypatch.delenv("IPQS_API_KEY", raising=False)

    def db_down():  # 快取查詢失敗被吞成 miss，接著因無金鑰回 not_configured
        raise psycopg2.OperationalError("no db")

    si, db = intel.query_sender_intel(db_down, Detector([], []), "x@unknown.com")
    assert si["status"] == "not_configured" and db["status"] == "NOT_UPDATED"


def test_router_no_db_confirmed_but_not_cached(monkeypatch):
    """免資料庫模式（get_conn 為 None）：IPQS 確認風險仍回報，但不寫快取。"""
    monkeypatch.setenv("IPQS_API_KEY", "REALKEY")
    monkeypatch.setattr(ipqs, "check_email", lambda addr, **kw: {"recent_abuse": True, "fraud_score": 95})
    si, db = intel.query_sender_intel(None, Detector([], []), "x@unknown.com")
    assert si["status"] == "confirmed" and si["verdict"] == "CONFIRMED_RISK"
    assert db["status"] == "NOT_UPDATED"


def test_apply_intel_override_to_high():
    result = {"riskLevel": "Low", "isPhishing": False, "totalScore": 0}
    intel.apply_intel_to_risk(result, {"verdict": "CONFIRMED_RISK"})
    assert result["riskLevel"] == "High" and result["isPhishing"] is True and result["overrides"]


def test_apply_intel_noop_when_not_confirmed():
    result = {"riskLevel": "Low", "isPhishing": False}
    intel.apply_intel_to_risk(result, {"status": "no_known_abuse"})
    assert result["riskLevel"] == "Low" and "overrides" not in result


# ---- LLM 內容分析 + 融合 ----

def test_apply_llm_raises_low_to_medium_without_message():
    r = {"riskLevel": "Low", "isPhishing": False}
    intel.apply_llm_to_risk(r, {"is_fraud": True, "risk_score": 40})
    assert r["riskLevel"] == "Medium" and r["isPhishing"] is True
    assert "overrides" not in r  # 依使用者要求：不再加入升級訊息


def test_apply_llm_does_not_upgrade_to_high_or_downgrade():
    r = {"riskLevel": "High", "isPhishing": True}
    intel.apply_llm_to_risk(r, {"is_fraud": True, "risk_score": 90})
    assert r["riskLevel"] == "High" and "overrides" not in r


def test_apply_llm_noop_when_not_fraud_or_none():
    r = {"riskLevel": "Low", "isPhishing": False}
    intel.apply_llm_to_risk(r, {"is_fraud": False})
    intel.apply_llm_to_risk(r, None)
    assert r["riskLevel"] == "Low" and "overrides" not in r


def test_analyze_content_not_provided_for_empty():
    a, st = intel.analyze_content("a@b.com", "   ")
    assert a is None and st["status"] == "not_provided"


def test_analyze_content_ok_and_invalid(monkeypatch):
    good = {"is_fraud": True, "risk_score": 80, "confidence_level": 0.9,
            "sender_identity_match": "UNCLEAR", "detected_threats": ["URGENCY_FEAR"],
            "reason": "r", "suggestion": "s"}
    monkeypatch.setattr(llm, "analyze_email", lambda e, c, **k: good)
    a, st = intel.analyze_content("a@b.com", "urgent click now")
    assert st["status"] == "ok" and a["is_fraud"] is True

    monkeypatch.setattr(llm, "analyze_email", lambda e, c, **k: {"is_fraud": "yes"})
    a2, st2 = intel.analyze_content("a@b.com", "x")
    assert a2 is None and st2["status"] == "invalid_output"


def test_analyze_content_unavailable_on_error(monkeypatch):
    def boom(e, c, **k):
        raise OSError("no ollama")
    monkeypatch.setattr(llm, "analyze_email", boom)
    a, st = intel.analyze_content("a@b.com", "x")
    assert a is None and st["status"] == "unavailable"


# ---- 繁中翻譯 ----

class _FakeResp:
    def __init__(self, content): self._c = content
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return json.dumps({"message": {"content": self._c}}).encode("utf-8")


def test_translate_to_zh_single_call_splits_ab():
    captured = {}

    def fake_opener(req, timeout=None):
        captured["user"] = json.loads(req.data.decode("utf-8"))["messages"][-1]["content"]
        return _FakeResp("[A] 理由譯\n[B] 建議譯\n")  # 尾端換行應被 strip

    out = translator.translate_to_zh({"reason": "r", "suggestion": "s"}, opener=fake_opener)
    assert out == {"reason": "理由譯", "suggestion": "建議譯"}
    assert "[A]" in captured["user"] and "[B]" in captured["user"]  # 單次呼叫同時翻兩欄


def test_translate_to_zh_strips_tags_before_sending():
    captured = {}

    def fake_opener(req, timeout=None):
        captured["user"] = json.loads(req.data.decode("utf-8"))["messages"][-1]["content"]
        return _FakeResp("[A] 乾淨")

    translator.translate_to_zh({"reason": "hi <email>x</email> there", "suggestion": ""}, opener=fake_opener)
    assert "<email>" not in captured["user"] and "</email>" not in captured["user"]


def test_translate_to_zh_skips_empty_fields():
    def boom(req, timeout=None):
        raise AssertionError("空欄位不該呼叫模型")

    out = translator.translate_to_zh({"reason": "", "suggestion": "   "}, opener=boom)
    assert out == {"reason": "", "suggestion": ""}


def test_is_mostly_chinese():
    assert translator.is_mostly_chinese("您好，請立即點擊連結驗證您的帳號密碼") is True
    assert translator.is_mostly_chinese("Hello, please verify your account now") is False
    assert translator.is_mostly_chinese("Meeting with 王經理 at 3pm tomorrow, please reply") is False  # 少量中文夾在英文信裡
    assert translator.is_mostly_chinese("你好") is False  # CJK 太少（<4）


def test_translate_email_to_en_wraps_and_returns():
    captured = {}

    def fake_opener(req, timeout=None):
        captured["user"] = json.loads(req.data.decode("utf-8"))["messages"][-1]["content"]
        return _FakeResp("Please click the link to verify your account.")

    out = translator.translate_email_to_en("請點擊連結驗證帳號", opener=fake_opener)
    assert out == "Please click the link to verify your account."
    assert "<email>" in captured["user"] and "請點擊" in captured["user"]  # 內容包在 <email> 當不可信資料


def test_clean_text_strips_tags():
    assert translator.clean_text("a <email>x</email> b") == "a x b"
    assert translator.clean_text("  <b>hi</b>  ") == "hi"
    assert translator.clean_text("") == ""


# ---- 寄件身分比對融合（gemma 單次呼叫，MISMATCH 才複核升級）----

def test_apply_identity_mismatch_raises_low_to_medium():
    r = {"riskLevel": "Low", "isPhishing": False}
    intel.apply_identity_to_risk(r, {"sender_identity_match": "MISMATCH"})
    assert r["riskLevel"] == "Medium" and r["isPhishing"] is True


def test_apply_identity_noop_when_match_unclear_or_none():
    for v in ("MATCH", "UNCLEAR"):
        r = {"riskLevel": "Low", "isPhishing": False}
        intel.apply_identity_to_risk(r, {"sender_identity_match": v})
        assert r["riskLevel"] == "Low" and r["isPhishing"] is False
    r = {"riskLevel": "Low", "isPhishing": False}
    intel.apply_identity_to_risk(r, None)
    assert r["riskLevel"] == "Low"


def test_apply_identity_does_not_lower_flagged():
    r = {"riskLevel": "High", "isPhishing": True}
    intel.apply_identity_to_risk(r, {"sender_identity_match": "MISMATCH"})
    assert r["riskLevel"] == "High"  # 只升不降；v2 已判 High 不受影響


# ---- gemma 結構化輸出：容錯解析與正規化 ----

def test_llm_parse_json_strips_fences_and_extracts():
    def op(req, timeout=None):
        return _FakeResp('```json\n{"is_fraud": false, "risk_score": 3, "confidence_level": 0.8, '
                         '"sender_identity_match": "UNCLEAR", "detected_threats": [], '
                         '"reason": "正常", "suggestion": "無"}\n```')
    out = llm.analyze_email("a@b.com", "hi", opener=op)
    assert out["is_fraud"] is False and out["sender_identity_match"] == "UNCLEAR"
    assert llm.validate(out) == []


def test_llm_normalizes_bad_identity_and_filters_threats():
    def op(req, timeout=None):
        return _FakeResp('{"is_fraud": true, "risk_score": 90, "confidence_level": 0.9, '
                         '"sender_identity_match": "NOPE", "detected_threats": ["URGENCY_FEAR", "BOGUS"], '
                         '"reason": "r", "suggestion": "s"}')
    out = llm.analyze_email("a@b.com", "x", opener=op)
    assert out["sender_identity_match"] == "UNCLEAR"    # 非法值 → UNCLEAR
    assert out["detected_threats"] == ["URGENCY_FEAR"]  # 過濾掉非列舉 BOGUS
    assert llm.validate(out) == []
