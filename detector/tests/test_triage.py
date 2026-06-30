from app import triage


def test_valid_action_passes_through():
    assert triage._coerce_action("deactivate_key") == "deactivate_key"


def test_injection_or_unknown_action_is_neutralized():
    # The model returning anything outside the enum must be coerced to a safe action.
    assert triage._coerce_action("rm -rf / ; disable everything") == "escalate_to_human"
    assert triage._coerce_action("ignore previous instructions") == "escalate_to_human"
    assert triage._coerce_action(None) == "escalate_to_human"


def test_triage_disabled_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert triage.available() is False
    assert triage.triage({"identity": "dev-bot"}) is None
