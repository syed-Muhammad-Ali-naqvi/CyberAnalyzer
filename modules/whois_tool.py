import whois
from datetime import datetime
from dateutil.relativedelta import relativedelta
from urllib.parse import urlparse

def get_domain_age(creation_date):
    try:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        now = datetime.now()
        diff = relativedelta(now, creation_date)
        if diff.years > 0:
            return f"{diff.years} year(s), {diff.months} month(s)"
        elif diff.months > 0:
            return f"{diff.months} month(s), {diff.days} day(s)"
        else:
            return f"{diff.days} day(s)"
    except:
        return "Unknown"

def is_suspicious_tld(domain) :
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".onion"]
    parsed = urlparse(domain if "://" in domain else f"http://{domain}")
    return any(parsed.netloc.endswith(tld) for tld in suspicious_tlds)

def is_shady_registrar(registrar):
    shady_list = ['Freenom', 'Bizcn', 'Alibaba', 'Hostinger']
    return any(bad.lower() in (registrar or "").lower() for bad in shady_list)

def detect_suspicious_status(status):
    suspicious_keywords = ["clientHold", "serverHold", "pendingDelete"]
    if not status:
        return False
    if isinstance(status, list):
        return any(any(word in s for word in suspicious_keywords) for s in status)
    return any(word in status for word in suspicious_keywords)


def format_list_field(field):
    if isinstance(field, list):
        return ", ".join(field)
    return field if field else "Not Available"


def format_date(date_value):
    if isinstance(date_value, list):
        date_value = date_value[0]
    return date_value.strftime("%Y-%m-%d") if isinstance(date_value, datetime) else "Unknown"


def analyze_whois(domain):
    try:
        w = whois.whois(domain)

        domain_name = w.domain_name[0] if isinstance(w.domain_name, list) else w.domain_name
        registrar = w.registrar
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        updated_date = w.updated_date
        name_servers = w.name_servers
        status = w.status
        emails = w.emails
        org = w.org
        country = w.country
        dnssec = w.dnssec
        age = get_domain_age(creation_date)

        suspicious = False
        flags = []

        if "year" not in age and "month" not in age:
            suspicious = True
            flags.append("Very new domain")

        if is_suspicious_tld(domain):
            suspicious = True
            flags.append("Suspicious TLD")

        if is_shady_registrar(registrar):
            suspicious = True
            flags.append("Registrar has questionable history")

        if detect_suspicious_status(status):
            suspicious = True
            flags.append("Suspicious domain status")

        if not dnssec or str(dnssec).lower() in ["unsigned", "no"]:
            flags.append("DNSSEC not enabled")

        return {
            "domain_name": domain_name,
            "registrar": registrar,
            "creation_date": format_date(creation_date),
            "expiration_date": format_date(expiration_date),
            "updated_date": format_date(updated_date),
            "name_servers": format_list_field(name_servers),
            "status": format_list_field(status),
            "emails": format_list_field(emails),
            "organization": org or "Unknown",
            "country": country or "Unknown",
            "dnssec": dnssec or "Unknown",
            "age": age,
            "suspicious": suspicious,
            "risk_analysis": flags or ["No obvious risks detected"]
        }

    except Exception as e:
        return {
            "error": f"WHOIS lookup failed: {str(e)}"
        }







