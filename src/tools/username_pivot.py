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
    "soundcloud.com": "https://soundcloud.com/{}",
    "reddit.com": "https://www.reddit.com/user/{}",
    "steamcommunity.com": "https://steamcommunity.com/id/{}",
    "behance.net": "https://www.behance.net/{}",
    "vimeo.com": "https://vimeo.com/{}",
    "about.me": "https://about.me/{}",
    "scribd.com": "https://www.scribd.com/{}",
    "disqus.com": "https://disqus.com/by/{}",
    "medium.com": "https://medium.com/@{}",
    "substack.com": "https://{}.substack.com",
    "patreon.com": "https://www.patreon.com/{}",
    "goodreads.com": "https://www.goodreads.com/{}",
    "bandcamp.com": "https://{}",
    "last.fm": "https://www.last.fm/user/{}",
    "adobe.com": "https://www.adobe.com",
    "facebook.com": "https://www.facebook.com/{}",
    "glassdoor.com": "https://www.glassdoor.com/member/profile/index.htm?username={}",
    "flipboard.com": "https://flipboard.com/@{}"
}

def resolve_clickable_profiles(platforms: list, email: str) -> list:
    """
    Constructs direct URL strings for identified platforms using the local part of the email.
    Filters out malformed entries and guarantees proper formatting.
    """
    handle = email.split("@")[0].lower() if "@" in email else email.lower()
    resolved_accounts = []
    seen_urls = set()

    valid_idx = 1
    for platform in platforms:
        platform_clean = platform.lower().strip()
        
        # Guard against raw junk words or invalid tokens like 'email'
        if platform_clean in ["email", "none", "n/a", "unknown"] or len(platform_clean) < 3:
            continue

        pattern = EXENSIVE_PROFILE_PATTERNS.get(platform_clean)

        if pattern:
            profile_url = pattern.format(handle)
            link_type = "Direct Profile Link"
        else:
            # Safe fallback: ensure it looks like a valid domain before turning into a portal link
            if "." in platform_clean and " " not in platform_clean:
                profile_url = f"https://{platform_clean}"
                link_type = "Domain Portal"
            else:
                continue

        if profile_url not in seen_urls:
            seen_urls.add(profile_url)
            resolved_accounts.append({
                "id": valid_idx,
                "platform": platform_clean,
                "link_type": link_type,
                "url": profile_url
            })
            valid_idx += 1

    return resolved_accounts

if __name__ == "__main__":
    test_platforms = ["github.com", "spotify.com", "email", "instagram.com"]
    print(resolve_clickable_profiles(test_platforms, "target@example.com"))
