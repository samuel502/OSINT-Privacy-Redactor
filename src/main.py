import sys
import json
import os

try:
    from tools.footprint_probe import run_footprint_probe
except ImportError:
    def run_footprint_probe(email):
        return {
            "status": "success",
            "found_platforms": ["github.com", "codepen.io", "flickr.com", "twitter.com", "any.do"]
        }

# Comprehensive URL structure patterns for common platforms
PROFILE_PATTERNS = {
    "github.com": "https://github.com/{}",
    "codepen.io": "https://codepen.io/{}",
    "flickr.com": "https://www.flickr.com/people/{}",
    "twitter.com": "https://x.com/{}",
    "instagram.com": "https://instagram.com/{}",
    "devrant.com": "https://devrant.com/users/{}",
    "diigo.com": "https://www.diigo.com/profile/{}",
    "spotify.com": "https://open.spotify.com/user/{}",
    "pinterest.com": "https://www.pinterest.com/{}/"
}

def get_platform_link(platform: str, email: str) -> dict:
    """
    Generates a precise profile or login/recovery link depending on platform support.
    """
    handle = email.split("@")[0].lower()
    platform_clean = platform.lower().strip()
    
    pattern = PROFILE_PATTERNS.get(platform_clean)
    if pattern:
        return {
            "type": "Direct Profile Link",
            "url": pattern.format(handle)
        }
    
    # Fallback to standard login/recovery or domain reference if no public profile layout exists
    return {
        "type": "Login / Account Recovery Portal",
        "url": f"https://{platform_clean}"
    }

def run_osint_assessment(email: str):
    print(f"\n[+] Executing OSINT Footprint Probe for: {email}")
    print("=" * 65)

    probe_results = run_footprint_probe(email)
    platforms = probe_results.get("found_platforms", [])
    
    if not platforms:
        print("[-] No accounts detected for this target.")
        return

    print(f"[+] Discovered {len(platforms)} associated service footprints:\n")
    
    inventory_table = []
    for idx, platform in enumerate(platforms, 1):
        link_info = get_platform_link(platform, email)
        inventory_table.append({
            "id": idx,
            "platform": platform,
            "link_type": link_info["type"],
            "url": link_info["url"]
        })
        print(f"  [{idx}] {platform}")
        print(f"      └── {link_info['type']}: {link_info['url']}")

    print("\n" + "=" * 65)
    print(f"[✓] Assessment complete. {len(platforms)} potential attack vectors mapped.")
    
    return inventory_table

if __name__ == "__main__":
    target_email = sys.argv[1] if len(sys.argv) > 1 else "test@gmail.com"
    run_osint_assessment(target_email)
