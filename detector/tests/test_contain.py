from app import contain
from app.models import ContainRequest


def test_safe_mode_returns_plan_only(monkeypatch):
    monkeypatch.delenv("SAFE_MODE", raising=False)  # default is SAFE_MODE on
    monkeypatch.setenv("PROTECTED_IDENTITIES", "root,break-glass-admin")
    req = ContainRequest(identity="dev-bot", action="deactivate_key", access_key_id="AKIATEST")
    res = contain.contain(req)
    assert res.safe_mode is True
    assert res.allowed is True
    assert res.executed is False
    assert any("update-access-key" in line for line in res.plan)


def test_root_is_blocked(monkeypatch):
    monkeypatch.setenv("PROTECTED_IDENTITIES", "root")
    req = ContainRequest(identity="root", identity_type="root", action="disable_user")
    res = contain.contain(req)
    assert res.allowed is False
    assert res.plan == []


def test_protected_username_is_blocked(monkeypatch):
    monkeypatch.setenv("PROTECTED_IDENTITIES", "break-glass-admin")
    req = ContainRequest(identity="break-glass-admin", action="deactivate_key")
    res = contain.contain(req)
    assert res.allowed is False
