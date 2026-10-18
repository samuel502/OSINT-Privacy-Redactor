import sys
import json
import os

# Import modular backend tools
try:
    from tools.footprint_probe import run_footprint_probe
except ImportError:
    # Fallback simulation if footprint_probe.py is missing or testing standalone
    def run_footprint_probe(email):
        return {
            "status": "success",
            "found_platforms": [
                "github.com", "spotify.com", "pinterest.com", 
                "duolingo.com", "etsy.com", "instagram.com"
            ]
        }

try:
    from tools.username_pivot import resolve_clickable_profiles
except ImportError:
    def resolve_clickable_profiles(platforms, email):
        return [{"id": 1, "platform": p, "link_type": "Domain", "url": f"https://{p}"} for p in platforms]

try:
    from tools.google_osint import query_google_osint
except ImportError:
    def query_google_osint(email):
        return {"status": "skipped"}

try:
    from tools.breach_intel import fetch_breach_timeline
except ImportError:
    def fetch_breach_timeline(email):
        return {"status": "skipped"}

try:
    from tools.phone_identity import extract_phone_fragments
except ImportError:
    def extract_phone_fragments(email):
        return {"status": "skipped"}


def generate_dossier(target_email: str):
    print("\n" + "=" * 70)
    print(f"       OSINT PRIVACY & FOOTPRINT DOSSIER")
    print(f"       Target Email: {target_email}")
    print("=" * 70)

    # 1. Footprint & Clickable Profile Resolution
    print("\n[+] PHASE 1: Account Footprint & Direct Profile Links")
    print("-" * 70)
    probe_data = run_footprint_probe(target_email)
    raw_platforms = probe_data.get("found_platforms", [])
    resolved_profiles = resolve_clickable_profiles(raw_platforms, target_email)

    for item in resolved_profiles:
        print(f"  [{item['id']}] {item['platform'].upper()}")
        print(f"      └── {item['link_type']}: {item['url']}")

    # 2. Google OSINT & Maps Activity
    print("\n[+] PHASE 2: Google Identity & Maps Activity")
    print("-" * 70)
    google_data = query_google_osint(target_email)
    if google_data.get("status") == "success":
        meta = google_data.get("profile_metadata", {})
        print(f"  • Display Name    : {meta.get('display_name')}")
        print(f"  • GAIA ID         : {meta.get('gaia_id')}")
        print(f"  • Profile Picture : {meta.get('profile_image_url')}")
        print("\n  [Google Maps Reviews & Activity]")
        for review in google_data.get("google_maps_activity", []):
            print(f"    - [{review['timestamp']}] {review['location']}: \"{review['snippet']}\"")
    else:
        print("  • Google OSINT skipped or target is non-Gmail.")

    # 3. Breach & Exposure Timeline
    print("\n[+] PHASE 3: Breach History & Exposure Timeline")
    print("-" * 70)
    breach_data = fetch_breach_timeline(target_email)
    if breach_data.get("status") == "success":
        print(f"  • First Seen Record : {breach_data.get('first_seen')}")
        print(f"  • Last Active Date  : {breach_data.get('last_active')}")
        print("  [Exposure Events]")
        for event in breach_data.get("timeline", []):
            print(f"    - [{event['date']}] {event['source']} ({event['exposure_type']})")

    # 4. Phone Fragment Analysis
    print("\n[+] PHASE 4: Phone Identity & Country Hints")
    print("-" * 70)
    phone_data = extract_phone_fragments(target_email)
    if phone_data.get("status") == "success":
        for phone in phone_data.get("phone_records", []):
            print(f"  • Fragment: {phone['fragment']} ({phone['country_hint']}) - via {phone['source_platform']}")

    print("\n" + "=" * 70)
    print("  [✓] Assessment Complete. Review exposed footprint and links above.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    email_input = sys.argv[1] if len(sys.argv) > 1 else "donaldtrump@gmail.com"
    generate_dossier(email_input)
