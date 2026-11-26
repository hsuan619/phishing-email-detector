"""v2 修正項目的回歸測試。"""
from detector import Detector, Keyword, SenderRule, normalize_address


def make(senders=(), keywords=()):
    return Detector(list(senders), list(keywords))


def test_keyword_uses_word_boundary():
    d = make(keywords=[Keyword("ach", 10, "BEC"), Keyword("doc", 15, "Malicious Link")])
    assert d.check_content("Please see the attached document.") == []
    assert [f.detail for f in d.check_content("Pay via ACH today")] == ["ach"]


def test_phrase_and_chinese_keywords():
    d = make(keywords=[Keyword("limited time", 20, "BEC"), Keyword("帳號鎖定", 20, "Brand")])
    hits = d.check_content("Limited  time only! 您的帳號鎖定了")
    assert [f.detail for f in hits] == ["帳號鎖定"]  # 片語中間多一個空白不算命中
    assert d.check_content("limited time offer")[0].detail == "limited time"


def test_each_keyword_counted_once():
    d = make(keywords=[Keyword("wire", 20, "BEC")])
    assert d.analyze("a@b.com", "wire wire wire").total_score == 20


def test_wildcard_sender_rule_matches():
    """v1 的 SQL 把 LIKE 寫反，'mailserveralert@%' 永遠不會命中。"""
    d = make(senders=[SenderRule("mailserveralert@%", "suspicious", "警報")])
    assert d.check_sender("mailserveralert@gmail.com")[0].score == 20


def test_domain_rule_covers_subdomains_and_case():
    d = make(senders=[SenderRule("@paypalload.net", "blacklist", "仿冒")])
    assert d.analyze("Service@Mail.PayPalLoad.NET", "hi").total_score == 100
    assert d.analyze("x@notpaypalload.net", "hi").total_score == 0


def test_trusted_domain_skips_sender_penalty():
    d = make(senders=[SenderRule("@paypal.com", "trusted", "官方網域")])
    assert d.check_sender("security-alert@paypal.com") == []


def test_blacklist_takes_priority_over_trusted():
    d = make(senders=[SenderRule("@paypal.com", "trusted", ""), SenderRule("evil@paypal.com", "blacklist", "")])
    assert d.check_sender("evil@paypal.com")[0].rule == "blacklist"


def test_common_tlds_are_not_suspicious():
    """v1 把 .net / .info 視為可疑 TLD，造成大量誤判。"""
    d = make()
    assert d.check_sender("john@example.net") == []
    assert d.check_sender("john@example.xyz")[0].score == 20


def test_normalize_address():
    assert normalize_address('"Alice" <Alice@Example.COM>') == "alice@example.com"
    assert normalize_address("  bob@example.com ") == "bob@example.com"


def test_ordinary_business_email_is_low_risk(detector):
    """v1 會把這封一般工作信判成 High（110 分）。"""
    result = detector.analyze(
        "alice@company.com.tw",
        "Hi team, the meeting document is attached. Please review the order of the agenda "
        "and let me know. Thanks!",
    )
    assert result.risk_level == "Low", result.to_dict()


def test_result_contains_no_html(detector):
    """回傳結構化資料而非 HTML 字串，前端以 textContent 顯示，避免 XSS。"""
    payload = detector.analyze("<img src=x onerror=alert(1)>@x.com", "hello").to_dict()
    assert "<br>" not in str(payload)
    assert set(payload) == {"email", "isPhishing", "totalScore", "riskLevel", "senderFindings", "keywordHits"}
