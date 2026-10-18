import sys
import json

try:
    from tools.footprint_probe import run_footprint_probe
except ImportError:
    def run_footprint_probe(email):
        return {"status": "success", "found_platforms": []}

try:
    from tools.username_pivot import resolve_clickable_profiles
except ImportError:
    def resolve_clickable_profiles(platforms, email):
        return []

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
    print(f"       OSINT FOOTPRINT DOSSIER")
    print(f"       Target: {target_email}")
    print("=" * 70)

    # 1. Footprint Probing & Direct Profile Resolution
    print("\n[+] PHASE 1: Account Registrations & Profile Links")
    print("-" * 70)
    probe_data = run_footprint_probe(target_email)
    raw_platforms = probe_data.get("found_platforms", [])
    resolved_profiles = resolve_clickable_profiles(raw_platforms, target_email)

    if resolved_profiles:
        for item in resolved_profiles:
            print(f"  [{item['id']}] {item['platform'].upper()}")
            print(f"      └── {item['link_type']}: {item['url']}")
    else:
        print("  • No active platform registrations detected.")

    # 2. Google Identity & Maps Activity
    print("\n[+] PHASE 2: Google Account Information")
    print("-" * 70)
    google_data = query_google_osint(target_email)
    if google_data.get("status") == "success" and google_data.get("google_account_found"):
        meta = google_data.get("profile_metadata", {})
        print(f"  • Display Name    : {meta.get('display_name') or 'N/A'}")
        print(f"  • GAIA ID         : {meta.get('gaia_id') or 'N/A'}")
        print(f"  • Profile Picture : {meta.get('profile_image_url') or 'N/A'}")
        
        maps_reviews = google_data.get("google_maps_activity", [])
        if maps_reviews:
            print("\n  [Google Maps Reviews]")
            for review in maps_reviews:
                print(f"    - [{review.get('timestamp')}] {review.get('location')}: \"{review.get('snippet')}\"")
        else:
            print("  • No public Google Maps review history found.")
    else:
        print("  • Google OSINT skipped or target account not found.")

    # 3. Breach & Exposure History
    print("\n[+] PHASE 3: Breach & Exposure Records")
    print("-" * 70)
    breach_data = fetch_breach_timeline(target_email)
    timeline = breach_data.get("timeline", [])
    if breach_data.get("status") == "success" and timeline:
        print(f"  • First Seen : {breach_data.get('first_seen')}")
        print(f"  • Last Active: {breach_data.get('last_active')}")
        for event in timeline:
            print(f"    - [{event['date']}] {event['source']} ({event['exposure_type']})")
    else:
        print("  • No breach exposure records found.")

    # 4. Phone Fragment Analysis
    print("\n[+] PHASE 4: Linked Phone Fragments")
    print("-" * 70)
    phone_data = extract_phone_fragments(target_email)
    phone_records = phone_data.get("phone_records", [])
    if phone_data.get("status") == "success" and phone_records:
        for phone in phone_records:
            print(f"  • Fragment: {phone['fragment']} ({phone['country_hint']}) - via {phone['source_platform']}")
    else:
        print("  • No linked phone fragments detected.")

    print("\n" + "=" * 70)
    print("  [✓] Process Complete.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    email_input = sys.argv[1] if len(sys.argv) > 1 else "user@example.com"
    generate_dossier(email_input)

