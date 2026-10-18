import subprocess
import json
import re

def run_holehe(email: str) -> dict:
    """
    Executes holehe CLI via subprocess, parses standard output, 
    and returns structured JSON data for the agentic core.
    """
    try:
        result = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        raw_output = result.stdout
        found_accounts = []
        
        for line in raw_output.splitlines():
            clean_line = line.strip()
            if "[+]" in clean_line:
                match = re.search(r'\[\+\]\s+([^\s]+)', clean_line)
                if match:
                    found_accounts.append({
                        "platform": match.group(1),
                        "status": "registered",
                        "url": f"https://{match.group(1)}.com" # Base structural handle link fallback
                    })

        return {
            "tool": "holehe",
            "status": "success",
            "email": email,
            "total_found": len(found_accounts),
            "platforms": found_accounts,
            "raw": raw_output
        }
        
    except subprocess.TimeoutExpired:
        return {"tool": "holehe", "status": "error", "message": "Execution timed out."}
    except Exception as e:
        return {"tool": "holehe", "status": "error", "message": str(e)}

if __name__ == "__main__":
    import sys
    test_email = sys.argv[1] if len(sys.argv) > 1 else "test@gmail.com"
    print(json.dumps(run_holehe(test_email), indent=2))
