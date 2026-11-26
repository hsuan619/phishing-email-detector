"""比賽時使用的 7 個測試案例（寄件者地址已去識別化）。"""
import pytest

CASES = [
    pytest.param(
        "support@apple-id-login.com",
        "How are you doing today? I hope everything is going well with you and your family.\n"
        "I was thinking about our talk last week. Let's grab some chat.\nBest wishes,\nDavid",
        {"High"},
        id="黑名單寄件者-內容正常",
    ),
    pytest.param(
        "12345@microsoft-security.net",
        "We detected a sign-in attempt to your account from an unrecognized device in Russia. "
        "For your protection, your account is locked.\nYou must verify your identity immediately "
        "to restore access. Please click the secure link.",
        {"High"},
        id="黑名單寄件者-內容異常",
    ),
    pytest.param(
        "friend@gmail.com",
        "Hey Jay,\nAre we still playing basketball this monday? I have asked the other guys and "
        "they ready.\nIf the time works for you. I can drive us there.",
        {"Low"},
        id="一般寄件者-內容正常",
    ),
    pytest.param(
        "someone@gmail.com",
        "Please attached invoice for the outstanding.\nKindly wire the to our account listed in "
        "the document immediately.",
        {"Medium", "High"},
        id="一般寄件者-內容異常(BEC)",
    ),
    pytest.param(
        "security-alert@verify-service.tk",
        "System Notice: Access Suspended\n\nWe detected suspicious actions on your profile. Your "
        "session has been terminated to protect your data.\n\nPlease login immediately to secure "
        "your information.",
        {"High"},
        id="高風險",
    ),
    pytest.param(
        "newsletter@daily-info.xyz",
        "Hi!\n\nCheck out our products in the catalog.\n\nWe have a special reward waiting for "
        "you. Do not miss it!",
        {"Medium"},
        id="中風險",
    ),
    pytest.param(
        "student@university.edu",
        "Dear Professor,\nHere is the file for my final project.\nI have included the summary and "
        "the we discussed. Hope this.\nRegards.",
        {"Low"},
        id="低風險",
    ),
]


@pytest.mark.parametrize("email,content,expected", CASES)
def test_competition_case(detector, email, content, expected):
    result = detector.analyze(email, content)
    assert result.risk_level in expected, result.to_dict()
