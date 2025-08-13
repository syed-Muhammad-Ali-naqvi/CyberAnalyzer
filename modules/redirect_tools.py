import requests
from urllib.parse import urlparse

def check_redirects(url):
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        response = requests.get(url, allow_redirects=True, timeout=10)

        redirects = [r.url for r in response.history] if response.history else []
        final_url = response.url
        original_domain = urlparse(url).netloc
        final_domain = urlparse(final_url).netloc

        suspicious = False
        reasons = []

        if len(redirects) > 2:
            suspicious = True
            reasons.append("Too many redirects")

        if original_domain != final_domain:
            suspicious = True
            reasons.append(f"Domain mismatch (from {original_domain} to {final_domain})")

        return {
            "final_url": final_url,
            "redirects": redirects,
            "suspicious": suspicious,
            "reason": ", ".join(reasons) if reasons else "No Suspicious redirect detected"
        }

    except requests.exceptions.RequestException:
        return {
            "final_url": None,
            "redirects": [],
            "suspicious": True,
            "reason": "Unable to reach the website. Please ensure the domain is correct and accessible."
        }
