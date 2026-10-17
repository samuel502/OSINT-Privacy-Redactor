import subprocess
import json
import shutil

# ==============================================================================
# CORE TOOL FUNCTION (Importable Module)
# ==============================================================================
def run_footprint_probe(email: str) -> dict:
    """
    Scans for accounts registered to an email address using holehe.
    Returns structured JSON output containing status and discovered platforms.
    """
    tool_bin = shutil.which("holehe")
    if not tool_bin:
        return {"status": "error", "message": "holehe binary not found in system PATH", "found_platforms": []}

    try:
        # Run holehe via CLI with json/text output parsing
        cmd = [tool_bin, email, "--only-used"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)

        found = []
        if result.returncode == 0 or result.stdout:
            for line in result.stdout.splitlines():
                if "[+]" in line:
                    # Extract platform name from standard holehe output format
                    parts = line.split("[+]")
                    if len(parts) > 1:
                        platform = parts[1].strip().split()[0]
                        found.append(platform)

        return {
            "status": "success",
            "target_email": email,
            "found_count": len(found),
            "found_platforms": found,
            "raw_output": result.stdout.strip()
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "found_platforms": []}


# ==============================================================================
# LOCAL / CLI TEST EXECUTION BLOCK
# This section only runs when executing this file directly (e.g. python footprint_probe.py email@example.com)
# ==============================================================================
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Error: Missing target email argument.")
        print("Usage: python src/tools/footprint_probe.py <email>")
        sys.exit(1)
        
    target_email = sys.argv[1]
    print(f"[CLI RUN] Executing Footprint Probe for: {target_email}\n")
    test_output = run_footprint_probe(target_email)
    print(json.dumps(test_output, indent=2))
