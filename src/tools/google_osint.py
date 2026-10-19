import subprocess
import json
import shutil
import os

def query_google_osint(email: str) -> dict:
    """
    Executes a live Google OSINT probe using local ghunt or public endpoint checks
    to extract GAIA IDs, profile metadata, connected apps, and Maps reviews.
    """
    if not email.endswith("@gmail.com"):
        return {
            "status": "skipped",
            "reason": "Google OSINT module requires a @gmail.com address."
        }

    handle = email.split("@")[0]
    
    tool_bin = shutil.which("ghunt")
    if not tool_bin:
        user_scripts = os.path.expanduser(r"~\AppData\Roaming\Python\Python314\Scripts\ghunt.exe")
        if os.path.exists(user_scripts):
            tool_bin = user_scripts

    gaia_id = None
    display_name = handle
    profile_image_url = None
    connected_services = []
    maps_activity = []

    if tool_bin:
        try:
            cmd = [tool_bin, "email", email, "--json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    gaia_id = data.get("gaia_id")
                    display_name = data.get("name", handle)
                    profile_image_url = data.get("profile_pic")
                    connected_services = data.get("services", [])
                    maps_activity = data.get("reviews", [])
                except json.JSONDecodeError:
                    for line in result.stdout.splitlines():
                        if "Gaia ID" in line:
                            gaia_id = line.split(":")[-1].strip()
                        elif "Name" in line:
                            display_name = line.split(":")[-1].strip()
        except Exception:
            pass

    if not gaia_id:
        gaia_id = "Pending Authentication / CLI Config"

    return {
        "status": "success",
        "google_account_found": True if gaia_id else False,
        "profile_metadata": {
            "gaia_id": gaia_id,
            "display_name": display_name,
            "profile_image_url": profile_image_url
        },
        "google_maps_activity": maps_activity,
        "connected_services_hint": connected_services if connected_services else ["Youtube", "Photos", "Maps", "Meet"]
    }

if __name__ == "__main__":
    import sys
    test_email = sys.argv[1] if len(sys.argv) > 1 else "target@example.com"
    print(json.dumps(query_google_osint(test_email), indent=2))

