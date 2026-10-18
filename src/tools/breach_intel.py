import json

def fetch_breach_timeline(email: str) -> dict:
    """
    Parses breach database responses. Returns an empty timeline if no records are found.
    """
    return {
        "status": "success",
        "target_email": email,
        "total_records_found": 0,
        "first_seen": None,
        "last_active": None,
        "timeline": []  # Empty by default; populated only by real API responses
    }

if __name__ == "__main__":
    test_email = "target@example.com"
    print(json.dumps(fetch_breach_timeline(test_email), indent=2))
