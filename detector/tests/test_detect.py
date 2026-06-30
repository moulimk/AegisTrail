from app import detect

US_BASELINE = {"known_countries": ["United States"]}
RU_GEO = {"country": "Russia"}
HOSTING_TI = {"abuseConfidenceScore": 7, "usageType": "Data Center/Web Hosting/Transit"}


def _types(signals):
    return {s["type"] for s in signals}


def test_scenario1_leaked_key_new_region():
    ev = {"action": "ListBuckets", "identity": "dev-bot"}
    signals = detect.run_rules(ev, RU_GEO, HOSTING_TI, US_BASELINE)
    assert _types(signals) == {"NEW_REGION", "TI_HOSTING"}
    assert detect.incident_type(signals) == "SUSPICIOUS_LOCATION"


def test_scenario2_privesc_correlates_to_credential_compromise():
    ev = {"action": "AttachUserPolicy", "identity": "dev-bot"}
    signals = detect.run_rules(ev, RU_GEO, HOSTING_TI, US_BASELINE)
    assert "PRIV_ESC_CHAIN" in _types(signals)
    assert detect.incident_type(signals) == "CREDENTIAL_COMPROMISE"


def test_scenario3_recon_action():
    ev = {"action": "GetAccountAuthorizationDetails", "identity": "dev-bot"}
    signals = detect.run_rules(ev, None, None, None)
    assert "RECON" in _types(signals)
    assert detect.incident_type(signals) == "RECONNAISSANCE"


def test_scenario3_recon_burst():
    ev = {"action": "DescribeInstances", "identity": "dev-bot"}
    signals = detect.run_rules(ev, None, None, None, recon_count=7)
    assert "RECON" in _types(signals)


def test_scenario4_root_and_mfa():
    ev = {"action": "DeactivateMFADevice", "identity": "root",
          "raw_event": {"userIdentity": {"type": "Root"}}}
    signals = detect.run_rules(ev, None, None, None)
    assert {"ROOT_ACTIVITY", "MFA_DISABLED"} <= _types(signals)
    assert detect.incident_type(signals) == "ROOT_USAGE"


def test_benign_event_produces_no_signals():
    ev = {"action": "GetObject", "identity": "dev-bot"}
    signals = detect.run_rules(ev, {"country": "United States"}, None, US_BASELINE)
    assert signals == []


def test_cold_start_does_not_false_positive_on_new_region():
    # No baseline yet -> NEW_REGION must not fire (Round 2: avoid cold-start FPs).
    ev = {"action": "ListBuckets", "identity": "brand-new-user"}
    signals = detect.run_rules(ev, RU_GEO, None, None)
    assert "NEW_REGION" not in _types(signals)
