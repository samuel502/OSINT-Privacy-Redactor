"""Offline tests for the merge layer. All data here is SYNTHETIC (sample, not live)."""
from privacy_agent.merge import merge_findings, domain_key
from privacy_agent.schema import result


def _email(*hits, errors=0, skipped=0, status="ok"):
    data = {"hits": [{"site": s, "category": "x", "url": u, "label": "registered",
                      "source": "user-scanner", **({"details": d} if d else {})}
                     for s, u, d in hits],
            "hit_count": len(hits), "checked": 10, "absent": 10 - len(hits),
            "errors": errors, "skipped": skipped}
    return result(status, data, "user-scanner")


def _user(*hits):
    data = {"hits": [{"site": s, "category": "x", "url": u, "label": "possible_match",
                      "source": "user-scanner"} for s, u in hits],
            "hit_count": len(hits), "checked": 10, "absent": 0, "errors": 0, "skipped": 0}
    return result("ok", data, "user-scanner")


def _breach(*names, status="ok"):
    return result(status, {"breach_count": len(names), "breaches": [{"name": n} for n in names]},
                  "xposedornot.com")


def test_domain_key_normalises_and_aliases():
    assert domain_key("X (twitter)", "https://x.com") == "x.com"
    assert domain_key("Twitter", "https://twitter.com/foo") == "x.com"
    assert domain_key("Etsy", "https://www.etsy.com") == "etsy.com"
    assert domain_key("Some Site", "") == "name:somesite"


def test_email_hit_is_confirmed():
    r = merge_findings(email_scan=_email(("Etsy", "https://www.etsy.com", None)))
    assert r["accounts"][0]["label"] == "confirmed"
    assert r["summary"]["confirmed"] == 1 and r["summary"]["possible"] == 0


def test_username_only_hit_is_possible_never_confirmed():
    r = merge_findings(username_scans=[_user(("Medium", "https://medium.com/@x"))])
    assert r["accounts"][0]["label"] == "possible_match"
    assert r["summary"]["confirmed"] == 0


def test_same_site_from_two_tools_is_merged_with_both_sources():
    r = merge_findings(
        email_scan=_email(("X (twitter)", "https://x.com", None)),
        username_scans=[_user(("Twitter", "https://twitter.com/me"))])
    assert len(r["accounts"]) == 1
    a = r["accounts"][0]
    assert a["label"] == "confirmed" and set(a["evidence"]) == {"email_registered", "username_match"}


def test_confirmed_sorted_before_possible():
    r = merge_findings(email_scan=_email(("Etsy", "https://www.etsy.com", None)),
                       username_scans=[_user(("Medium", "https://medium.com/@x"))])
    assert [a["label"] for a in r["accounts"]] == ["confirmed", "possible_match"]


def test_errors_and_skips_are_reported_not_hidden():
    r = merge_findings(email_scan=_email(errors=29, skipped=51))
    text = " ".join(r["could_not_check"])
    assert "29" in text and "51" in text


def test_failed_tool_is_listed_and_not_read_as_nothing_found():
    bad = result("error", source="user-scanner", error="Timed out after 280s.")
    r = merge_findings(email_scan=bad, breach=_breach())
    assert r["accounts"] == []
    assert any("Timed out" in c for c in r["could_not_check"])
    assert r["summary"]["checks_ok"] == ["breaches"] and "email accounts" in r["summary"]["checks_failed"]


def test_unavailable_tool_is_listed():
    r = merge_findings(email_scan=result("unavailable", source="user-scanner", error="not installed"))
    assert "email accounts" in r["summary"]["checks_failed"]


def test_breaches_pass_through():
    r = merge_findings(breach=_breach("Deezer", "8fit"))
    assert r["breaches"] == ["Deezer", "8fit"] and r["summary"]["breaches"] == 2


def test_removal_route_attached_and_unverified_is_labelled():
    routes = {"etsy.com": {"opt_out_url": "https://etsy.example/delete", "verified": False},
              "x.com": {"opt_out_url": "https://x.example/deactivate", "verified": True}}
    r = merge_findings(email_scan=_email(("Etsy", "https://www.etsy.com", None),
                                         ("X (twitter)", "https://x.com", None),
                                         ("Pinterest", "https://pinterest.com", None)),
                       routes=routes)
    by = {a["domain"]: a["removal"] for a in r["accounts"]}
    assert by["etsy.com"]["status"] == "unverified" and by["x.com"]["status"] == "verified"
    assert by["pinterest.com"]["status"] == "no_route_known"
    assert by["pinterest.com"]["url"] is None


def test_holehe_fallback_shape_is_understood():
    fb = result("ok", {"confirmed_accounts": ["eventbrite.com", "twitter.com"]}, "holehe+gravatar")
    r = merge_findings(email_scan=fb)
    assert {a["domain"] for a in r["accounts"]} == {"eventbrite.com", "x.com"}
    assert all(a["label"] == "confirmed" for a in r["accounts"])


def test_none_inputs_give_empty_report():
    r = merge_findings()
    assert r["accounts"] == [] and r["breaches"] == [] and r["summary"]["checks_ok"] == []


def test_duplicate_hits_inside_one_tool_do_not_double_count():
    r = merge_findings(email_scan=_email(("Etsy", "https://www.etsy.com", None),
                                         ("Etsy", "https://etsy.com", None)))
    assert len(r["accounts"]) == 1
