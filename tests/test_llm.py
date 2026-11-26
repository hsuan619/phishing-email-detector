"""Ollama LLM adapter 的單元測試（不需 Ollama／網路）。"""
import json

import llm


def test_validate_accepts_good_and_flags_bad():
    good = {"is_fraud": True, "risk_score": 90, "confidence_level": 0.9,
            "sender_identity_match": "MISMATCH", "detected_threats": ["DOMAIN_MISMATCH"],
            "reason": "x", "suggestion": "y"}
    assert llm.validate(good) == []
    assert llm.validate({**good, "risk_score": 150})               # 超出 0-100
    assert llm.validate({**good, "detected_threats": ["NOPE"]})    # 非列舉值
    assert llm.validate({**good, "confidence_level": 2})           # 超出 0-1
    assert llm.validate({**good, "is_fraud": "yes"})               # 非 boolean
    assert llm.validate({**good, "sender_identity_match": "NOPE"})  # 非 MATCH/MISMATCH/UNCLEAR


def test_analyze_email_builds_request_and_parses_response():
    inner = {"is_fraud": True, "risk_score": 88, "confidence_level": 0.9,
             "sender_identity_match": "MISMATCH", "detected_threats": ["URGENCY_FEAR"],
             "reason": "r", "suggestion": "s"}
    captured = {}

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self):
            return json.dumps({"message": {"content": json.dumps(inner)}}).encode("utf-8")

    def fake_opener(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResp()

    out = llm.analyze_email("a@b.com", "hello", opener=fake_opener)
    assert out == {**inner, "is_typosquat": False}  # analyze_email 正規化補上 is_typosquat
    assert captured["url"].endswith("/api/chat")
    assert captured["body"]["model"] == llm.DEFAULT_MODEL
    assert captured["body"]["format"] == "json"  # 只保證合法 JSON，不綁死 schema
    # 郵件內容包在 <email> 標籤內（prompt injection 防護）
    assert "<email>" in captured["body"]["messages"][1]["content"]
