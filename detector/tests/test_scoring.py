from app import scoring


def test_two_signals_sum():
    assert scoring.score(["NEW_REGION", "PRIV_ESC_CHAIN"]) == 80


def test_threat_intel_adds_to_score():
    assert scoring.score(["NEW_REGION", "TI_HOSTING"]) == 35


def test_score_caps_at_100():
    assert scoring.score(["ROOT_ACTIVITY", "MFA_DISABLED", "TI_HOSTING"]) == 100


def test_no_signals_is_zero():
    assert scoring.score([]) == 0


def test_unknown_signal_ignored():
    assert scoring.score(["NOT_A_REAL_SIGNAL"]) == 0
