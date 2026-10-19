"""Tool 4 (action): draft a legal erasure request. Drafts only; nothing is ever sent."""
from __future__ import annotations

import re

from ..schema import result, validate_email

JURISDICTIONS = {"gdpr", "uk_gdpr", "ccpa", "other"}

_LAW = {
    "gdpr": ("Request for erasure of personal data (GDPR Art. 17)",
             "Under Article 17 of the General Data Protection Regulation (GDPR), I request the erasure "
             "of all personal data you hold about me, and that you notify any recipients or processors "
             "of the erasure as required by Article 19. Under Article 12(3) I expect a response "
             "within one month of receipt."),
    "uk_gdpr": ("Request for erasure of personal data (UK GDPR Art. 17)",
                "Under Article 17 of the UK GDPR, I request the erasure of all personal data you hold "
                "about me, and that you notify any recipients of the erasure as required by Article 19. "
                "I expect a response within one month of receipt."),
    "ccpa": ("Request to delete personal information (CCPA)",
             "Under the California Consumer Privacy Act (Cal. Civ. Code section 1798.105), I request that "
             "you delete all personal information you have collected about me and direct any service "
             "providers to do the same. I expect confirmation within the statutory response period."),
    "other": ("Request for deletion of personal data",
              "Under the data protection law that applies to me, I request that you delete all "
              "personal data you hold about me and confirm in writing once this is done."),
}


def _norm_domain(s: str) -> str:
    s = re.sub(r"^https?://", "", s.strip().lower())
    return re.sub(r"^www\.", "", s).split("/")[0]


def draft_erasure_request(email: str, platform_domain: str, jurisdiction: str = "gdpr",
                          full_name: str | None = None) -> dict:
    email = validate_email(email)
    domain = _norm_domain(platform_domain or "")
    if not domain or "." not in domain:
        return result("error", source="template", error=f"Invalid platform domain: {platform_domain!r}")
    j = (jurisdiction or "other").lower()
    if j not in JURISDICTIONS:
        j = "other"
    subject, legal = _LAW[j]
    name_line = f"Name: {full_name}\n" if full_name else ""
    body = (
        f"To: Privacy / Data Protection Team, {domain}\n\n"
        f"Subject: {subject}\n\n"
        f"{name_line}Account email: {email}\n\n"
        f"{legal}\n\n"
        "Please erase the account and all associated personal data, including backups where "
        "technically feasible, and confirm completion to this address. If you need to verify my "
        "identity, reply to this email and tell me what you need.\n\n"
        "Thank you."
    )
    return result("ok", {"platform": domain, "jurisdiction": j, "subject": subject, "body": body},
                  "template",
                  note="Draft only; NOT sent. Find the service's privacy contact in its privacy policy. "
                       "Not legal advice.")
