"""/api/blocklist endpoint 與寄件者名單寫入的單元測試（不需 DB／Ollama／網路）。"""
import psycopg2
import pytest

import app as appmod
import rules


@pytest.fixture
def client():
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


def test_to_domain_pattern_normalizes_and_validates():
    assert appmod._to_domain_pattern("support@paypa1.com") == "@paypa1.com"
    assert appmod._to_domain_pattern("@paypa1.com") == "@paypa1.com"
    assert appmod._to_domain_pattern("Paypa1.COM") == "@paypa1.com"       # 轉小寫
    assert appmod._to_domain_pattern("evil@sub.paypa1.com") == "@sub.paypa1.com"
    # 非法輸入一律 None（擋萬用字元、空白、底線、單標籤、前導連字號）
    for bad in ("", "nope", "a@b", "a@%evil.com", "a@ evil .com", "@-bad.com", "a@bad_domain.com"):
        assert appmod._to_domain_pattern(bad) is None


def test_blocklist_rejects_invalid_domain(client):
    r = client.post("/api/blocklist", json={"pattern": "not-a-domain"})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_blocklist_writes_csv_when_db_down(client, monkeypatch):
    def boom():
        raise psycopg2.OperationalError("no db")
    monkeypatch.setattr(appmod, "get_connection", boom)
    calls = []
    monkeypatch.setattr(appmod, "append_sender_csv",
                        lambda p, lt, d: (calls.append((p, lt, d)) or True))

    r = client.post("/api/blocklist", json={"email": "support@paypa1.com"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["pattern"] == "@paypa1.com"
    assert body["mode"] == "csv-fallback" and body["added"] is True
    assert calls == [("@paypa1.com", "blacklist", "使用者確認加入：仿冒寄件網域 (typosquatting)")]


def test_append_sender_csv_dedups(tmp_path):
    p = tmp_path / "senders.csv"
    p.write_text("pattern,list_type,description\n@x.com,trusted,ok\n", encoding="utf-8")
    assert rules.append_sender_csv("@paypa1.com", "blacklist", "d", path=p) is True
    assert rules.append_sender_csv("@paypa1.com", "blacklist", "d", path=p) is False  # 重複不再加
    assert p.read_text(encoding="utf-8").count("@paypa1.com") == 1
