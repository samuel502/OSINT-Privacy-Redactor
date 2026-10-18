import urllib.request
import urllib.error

# Extensive public profile pattern mapping for direct clickable link resolution
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
    Extracts the local handle from the email and builds direct, 
    clickable public profile URLs for discovered platforms.
    """
    handle = email.split("@")[0].lower()
    resolved_accounts = []

    for idx, platform in enumerate(platforms, 1):
        platform_clean = platform.lower().strip()
        pattern = EXENSIVE_PROFILE_PATTERNS.get(platform_clean)

        if pattern:
            profile_url = pattern.format(handle)
            link_type = "Direct Profile Link"
        else:
            profile_url = f"https://{platform_clean}"
            link_type = "Account Recovery / Domain Portal"

        resolved_accounts.append({
            "id": idx,
            "platform": platform_clean,
            "link_type": link_type,
            "url": profile_url
        })

    return resolved_accounts

if __name__ == "__main__":
    # Test block
    test_platforms = ["github.com", "spotify.com", "unknownsite.com"]
    print(resolve_clickable_profiles(test_platforms, "donaldtrump@gmail.com"))
