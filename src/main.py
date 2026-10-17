import json
import sys
import os

# Ensure Python can find modules under src/tools/
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

from footprint_probe import run_footprint_probe
from policy_retriever import fetch_policy_vector

# ==============================================================================
# CORE ORCHESTRATION FUNCTION (Importable Module)
# ==============================================================================
def generate_privacy_report(target_email: str) -> dict:
    """
    Executes the full OSINT privacy report pipeline:
    1. Probes digital footprint via holehe (Tool 1).
    2. Retrieves policy vectors and legal demand drafts for each found platform (Tool 2).
    """
    print(f"[*] Starting Privacy Probe & Report Generation for: {target_email}\n")
    
    # Step 1: Run Footprint Probe
    probe_results = run_footprint_probe(target_email)
    
    if probe_results["status"] != "success":
        return {
            "status": "error",
            "message": f"Footprint probe failed: {probe_results.get('message', 'Unknown error')}",
            "platforms_scanned": 0,
            "reports": []
        }
        
    found_platforms = probe_results.get("found_platforms", [])
    print(f"[+] Footprint scan complete. Discovered {len(found_platforms)} active platform(s).\n")
    
    # Step 2: Retrieve Policy and Legal Vectors for each platform
    platform_reports = []
    for platform in found_platforms:
        # Standardize domain mapping
        domain = f"{platform.lower()}.com" if "." not in platform else platform.lower()
        policy_data = fetch_policy_vector(domain, target_email)
        platform_reports.append(policy_data)
        
    return {
        "status": "success",
        "target_email": target_email,
        "total_platforms_found": len(found_platforms),
        "reports": platform_reports
    }


# ==============================================================================
# LOCAL / CLI TEST EXECUTION BLOCK
# ==============================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Missing target email argument.")
        print("Usage: python src/main.py <email>")
        sys.exit(1)
        
    target = sys.argv[1]
    final_report = generate_privacy_report(target)
    print(json.dumps(final_report, indent=2))
