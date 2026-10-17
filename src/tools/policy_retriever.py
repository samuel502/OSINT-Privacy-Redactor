import json
import sys

# ==============================================================================
# CORE TOOL FUNCTION (Importable Module)
# ==============================================================================
def fetch_policy_vector(platform_domain: str, target_email: str = "user@example.com") -> dict:
    """
    Retrieves deletion difficulty, compliance rights, opt-out links, 
    and generates a standardized legal erasure notice for a given domain.
    """
    domain_clean = platform_domain.lower().strip()
    
    # Fallback structured database for popular platforms
    known_policy_map = {
        "spotify.com": {
            "opt_out_url": "https://www.spotify.com/account/privacy/",
            "deletion_difficulty": "Easy (Automated)",
            "gdpr_compliance": "Fully Supported",
            "ccpa_compliance": "Fully Supported"
        },
        "twitter.com": {
            "opt_out_url": "https://twitter.com/settings/deactivate",
            "deletion_difficulty": "Medium (30-day deactivation period)",
            "gdpr_compliance": "Supported",
            "ccpa_compliance": "Supported"
        },
        "github.com": {
            "opt_out_url": "https://github.com/settings/security",
            "deletion_difficulty": "Easy (Automated)",
            "gdpr_compliance": "Fully Supported",
            "ccpa_compliance": "Fully Supported"
        }
    }

    # Fetch from known map or fall back to generic statutory assumptions
    policy_data = known_policy_map.get(domain_clean, {
        "opt_out_url": f"https://{domain_clean}/privacy",
        "deletion_difficulty": "Unknown / Manual Verification Required",
        "gdpr_compliance": "Standard Statutory Rights Apply",
        "ccpa_compliance": "Standard Statutory Rights Apply"
    })

    # Generate standard GDPR Art. 17 / CCPA erasure notice draft
    legal_notice = (
        f"Formal Request for Data Erasure (GDPR Art. 17 / CCPA)\n"
        f"To: Privacy Officer / Data Protection Team at {domain_clean}\n"
        f"Target Identifier: {target_email}\n\n"
        f"I hereby request the immediate erasure of all personal data associated with the identifier {target_email} "
        f"pursuant to my rights under applicable data protection laws. Please confirm complete removal."
    )

    return {
        "platform": domain_clean,
        "opt_out_url": policy_data["opt_out_url"],
        "deletion_difficulty": policy_data["deletion_difficulty"],
        "gdpr_compliance": policy_data["gdpr_compliance"],
        "ccpa_compliance": policy_data["ccpa_compliance"],
        "legal_notice_draft": legal_notice
    }


# ==============================================================================
# LOCAL / CLI TEST EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Missing target platform domain argument.")
        print("Usage: python src/tools/policy_retriever.py <domain> [email]")
        sys.exit(1)
        
    target_domain = sys.argv[1]
    target_email = sys.argv[2] if len(sys.argv) > 2 else "test@example.com"
    
    print(f"[CLI RUN] Fetching policy vector for: {target_domain}\n")
    test_output = fetch_policy_vector(target_domain, target_email)
    print(json.dumps(test_output, indent=2))
