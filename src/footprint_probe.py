!pip install -q holehe

import subprocess
import json
import shutil

def run_footprint_probe(email: str) -> dict:
    tool_bin = shutil.which("holehe")
    if not tool_bin:
        return {"status": "error", "message": "holehe not found", "found_platforms": []}

    try:
        # Run holehe via CLI with json/text output
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

# Test execution
test_email = "test@example.com"
print(f"Running Footprint Probe on {test_email}...")
output = run_footprint_probe(test_email)
print(json.dumps(output, indent=2))
