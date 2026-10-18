EXENSIVE_PROFILE_PATTERNS = {
    "github.com": "https://github.com/{}",
    "spotify.com": "https://open.spotify.com/user/{}",
    "pinterest.com": "https://www.pinterest.com/{}/",
    "duolingo.com": "https://www.duolingo.com/profile/{}",
    "etsy.com": "https://www.etsy.com/shop/{}",
    "instagram.com": "https://instagram.com/{}",
    "flickr.com": "https://www.flickr.com/people/{}",
    "twitter.com": "https://x.com/{}",
    "devrant.com": "https://devrant.com/users/{}",
    "diigo.com": "https://www.diigo.com/profile/{}",
    "plex.tv": "https://app.plex.tv/profile/{}",
    "freelancer.com": "https://www.freelancer.com/u/{}",
    "tumblr.com": "https://{}.tumblr.com",
    "soundcloud.com": "https://soundcloud.com/{}"
}

def resolve_clickable_profiles(platforms: list, email: str) -> list:
    """
    Constructs direct URL strings for identified platforms using the local part of the email.
    """
    handle = email.split("@")[0].lower() if "@" in email else email.lower()
    resolved_accounts = []

    for idx, platform in enumerate(platforms, 1):
        platform_clean = platform.lower().strip()
        pattern = EXENSIVE_PROFILE_PATTERNS.get(platform_clean)

        if pattern:
            profile_url = pattern.format(handle)
            link_type = "Direct Profile Link"
        else:
            profile_url = f"https://{platform_clean}"
            link_type = "Domain Portal"

        resolved_accounts.append({
            "id": idx,
            "platform": platform_clean,
            "link_type": link_type,
            "url": profile_url
        })

    return resolved_accounts

if __name__ == "__main__":
    test_platforms = ["github.com", "spotify.com", "example.com"]
    print(resolve_clickable_profiles(test_platforms, "target@example.com"))
