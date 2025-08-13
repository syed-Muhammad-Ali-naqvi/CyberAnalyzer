import re, socket, ssl, requests, urllib.parse, tldextract, whois
from datetime import datetime


def extract_domain_info(url):
    extracted = tldextract.extract(url)
    return f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".strip(".")

def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

def get_redirect_chain(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        chain = [(resp.status_code, resp.url) for resp in response.history]
        chain.append((response.status_code, response.url))
        return chain
    except Exception as e:
        return [(0, f"Error: {e}")]


def get_ssl_info(domain):
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert.get("noAfter")
    except:
        return "Unavailable or Invalid"


def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        if isinstance(info.creation_date, list):
            created = info.creation_date[0]
        else:
            created = info.creation_date
        if created:
            age = (datetime.now() - created).days // 365
            return f"{age} years"
    except:
        pass
    return "Unknown"


def suspicious_keywords_in_url(url):
    flags = []
    keywords = ["login", "verify", "update", "account", "bank", "signin", "submit"]
    for word in keywords:
        if word in url.lower():
            flags.append(word)
        return flags

def contains_obfuscation(url):
    patterns = ["%", "..", "@", "//", "\\"]
    return any(p in url for p in patterns)


def extract_signals(url):
    signals = []
    parsed = urllib.parse.urlparse(url)
    domain = extract_domain_info(url)

    if parsed.scheme == "https":
        signals.append(("✅", "Domain uses HTTPS"))
    else:
        signals.append(("⚠️", "Domain uses HTTP (not secure)"))

    redirects = get_redirect_chain(url)
    if len(redirects) > 1:
        signals.append(("ℹ️", f"Redirected {len(redirects)-1} times"))
        if any(code == 301 and 'http:' in link for code, link in redirects):
            signals.append(("⚠️", "Redirect downgrade from HTTPS to HTTP"))

    age = get_whois_info(domain)
    signals.append(("ℹ️", f"Domain age: {age}"))


    flagged_words = suspicious_keywords_in_url(url)
    if flagged_words:
        signals.append(("⚠️", f"Suspicious keywords found: {', '.join(flagged_words)}"))
    else:
        signals.append(("✅", "No common phishing keywords found"))


    query_params = urllib.parse.parse_qs(parsed.query)
    if len(query_params) > 5:
        signals.append(("⚠️", f"High number of query params: {len(query_params)}"))


    if contains_obfuscation(url):
        signals.append(("⚠️", "Obfuscation patterns detected (%, .., //, etc)"))


    if is_ip_address(parsed.hostname):
        signals.append(("⚠️", "Domain is a raw IP address"))
    else:
        signals.append(("✅", "Normal domain name"))


    ssl_expiry = get_ssl_info(domain)
    signals.append(("ℹ️", f"SSL Certificate expires: {ssl_expiry}"))

    return redirects, signals





















