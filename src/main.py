import sys
import json
from tools.footprint_probe import run_footprint_probe

def generate_account_inventory(email: str) -> dict:
    """
    Runs footprint discovery and returns an Account Inventory Checklist
    with direct login/recovery links so the user can manage or close accounts directly.
    """
    print(f"[*] Starting Account Inventory Probe for: {email}")
    probe_results = run_footprint_probe(email)

    if probe_results.get("status") != "success":
        return {
            "status": "error",
            "message": probe_results.get("message", "Probe failed"),
            "inventory": []
        }

    platforms = probe_results.get("found_platforms", [])
    inventory = []

    for platform in platforms:
        # Generate direct URL for user login / recovery
        inventory.append({
            "platform": platform,
            "login_recovery_url": f"https://{platform}",
            "action_recommended": "Log in to manage settings, update security, or close account manually."
        })

    return {
        "status": "success",
        "target_email": email,
        "total_platforms_found": len(inventory),
        "account_inventory": inventory
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Missing target email argument.")
        print("Usage: python src/main.py <email>")
        sys.exit(1)

    target_email = sys.argv[1]
    report = generate_account_inventory(target_email)
    print(json.dumps(report, indent=2))
