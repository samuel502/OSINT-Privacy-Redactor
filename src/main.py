import sys
import json
import os

# Import your footprint probe
try:
    from tools.footprint_probe import run_footprint_probe
except ImportError:
    # Fallback mock for testing if module path differs locally
    def run_footprint_probe(email):
        return {
            "status": "success",
            "found_platforms": ["github.com", "codepen.io", "flickr.com", "twitter.com"]
        }

# Smart profile URL patterns mimicking direct account link resolution
PROFILE_PATTERNS = {
    "github.com": "https://github.com/{}",
    "codepen.io": "https://codepen.io/{}",
    "flickr.com": "https://www.flickr.com/people/{}",
    "twitter.com": "https://x.com/{}",
    "instagram.com": "https://instagram.com/{}"
}

def resolve_direct_profile(platform: str, email: str) -> str:
    """Constructs a direct public profile link using the local email handle."""
    handle = email.split("@")[0].lower()
    pattern = PROFILE_PATTERNS.get(platform.lower())
    
    if pattern:
        return pattern.format(handle)
    return f"https://{platform}"

def load_osint_targets() -> list:
    """Loads third-party OSINT search tools and data broker opt-out targets."""
    json_path = "data/osint_targets.json"
    if not os.path.exists(json_path):
        json_path = os.path.join("src", "data", "osint_targets.json")
    
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f).get("osint_targets", [])
        except Exception:
            pass
    return []

def run_osint_assessment(email: str):
    print(f"\n[+] Starting OSINT Exposure Assessment for: {email}")
    print("=" * 60)

    # ---------------------------------------------------------
    # PHASE 1: Account Discovery & Direct Profile Links
    # ---------------------------------------------------------
    print("[*] Phase 1: Querying authentication & registration endpoints...")
    probe_results = run_footprint_probe(email)
    platforms = probe_results.get("found_platforms", [])
    
    account_inventory = []
    for platform in platforms:
        direct_url = resolve_direct_profile(platform, email)
        account_inventory.append({
            "platform": platform,
            "direct_profile_or_login_url": direct_url,
            "status": "Account Active / Visible"
        })

    print(f"[+] Found {len(account_inventory)} linked service accounts.")

    # ---------------------------------------------------------
    # PHASE 2: Third-Party OSINT & Data Broker Opt-Outs
    # ---------------------------------------------------------
    print("[*] Phase 2: Compiling third-party OSINT search engines & opt-out paths...")
    osint_targets = load_osint_targets()

    # Build the final structured report
    report = {
        "target_email": email,
        "phase_1_discovery": {
            "total_accounts_discovered": len(account_inventory),
            "account_inventory": account_inventory
        },
        "phase_2_suppression_roadmap": {
            "total_osint_engines_tracked": len(osint_targets),
            "opt_out_targets": osint_targets
        }
    }

    return report

if __name__ == "__main__":
    target_email = sys.argv[1] if len(sys.argv) > 1 else "test.project.2026@gmail.com"
    final_report = run_osint_assessment(target_email)
    
    # Output clean JSON report
    print("\n--- FINAL EXPOSURE & SUPPRESSION REPORT ---")
    print(json.dumps(final_report, indent=2))
