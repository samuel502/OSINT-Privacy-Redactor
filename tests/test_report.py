from privacy_agent.report import build_report

FP = {"status": "ok", "data": {"confirmed_accounts": ["eventbrite.com", "office365.com", "twitter.com"],
      "rate_limited_or_unchecked": ["github.com", "google.com", "pinterest.com"],
      "holehe_counts": {"registered": 3, "not_registered": 40, "rate_limited": 3}}}
BR = {"status": "ok", "data": {"breaches": ["8fit", "Deezer"]}}
PB = {"twitter.com": {"data": {"matches": [{"name": "X (Twitter)", "opt_out_url": "https://x.com/settings/deactivate",
                                            "verified": False}]}},
      "eventbrite.com": {"data": {"matches": []}}}
LK = [{"name": "EmailOSINT", "opt_out_url": "https://emailosint.org/claim", "verified": True, "needs_captcha": True,
       "steps_summary": "Enter your email, solve the CAPTCHA, confirm via the emailed link."}]


def test_report_has_coverage_links_breaches_and_lookup_optout():
    out = build_report(FP, BR, PB, LK)
    assert "43 of 46 sites checked" in out and "**not checked**" in out
    assert "[X (Twitter) removal page](https://x.com/settings/deactivate)" in out
    assert "unverified" in out and "no playbook yet" in out
    assert "8fit, Deezer" in out and "3 sites not checked" in out
    assert "[EmailOSINT](https://emailosint.org/claim)" in out and "CAPTCHA" in out


def test_report_never_turns_failed_checks_into_clean_results():
    out = build_report({"status": "unavailable", "error": "No footprint source could run.", "data": {}},
                       {"status": "error", "error": "rate limited", "data": {}}, {}, [])
    assert "could not run" in out and "No known breaches" not in out and "None confirmed" not in out


def test_report_empty_breaches_is_not_proof_of_safety():
    out = build_report(FP, {"status": "ok", "data": {"breaches": []}}, {}, [])
    assert "not proof of safety" in out
