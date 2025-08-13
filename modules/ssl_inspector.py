import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime
import re
from typing import Dict, Optional, List
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_url(url: str) -> Optional[str]:
    """Validate and normalize the input URL."""
    if not url:
        logger.error("Empty URL provided")
        return None
    url = url.strip()
    if not re.match(r'^https?://', url):
        url = f"https://{url}"
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            logger.error(f"Invalid URL: missing scheme or hostname in {url}")
            return None
        return parsed.geturl()
    except Exception as e:
        logger.error(f"Invalid URL format: {str(e)}")
        return None

def calculate_days_left(expiration_str: str) -> str:
    """Calculate days until SSL certificate expiration."""
    try:
        expiry_date = datetime.strptime(expiration_str, "%b %d %H:%M:%S %Y %Z")
        delta = expiry_date - datetime.utcnow()
        return str(max(0, delta.days)) if delta.days >= 0 else "Expired"
    except ValueError as e:
        logger.error(f"Date parsing error: {str(e)}")
        return "N/A"

def evaluate_header_security(headers: Dict[str, str]) -> Dict[str, any]:
    """Evaluate HTTP security headers with detailed analysis."""
    score = 0
    max_score = 6
    notes = []

    # Check HSTS with basic value validation
    if "Strict-Transport-Security" in headers:
        hsts = headers["Strict-Transport-Security"]
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0])
            if max_age >= 31536000:
                score += 1
                notes.append("✅ HSTS enabled with strong max-age")
            else:
                notes.append("⚠️ HSTS enabled but weak max-age")
        except (IndexError, ValueError):
            notes.append("⚠️ HSTS enabled but invalid max-age")
    else:
        notes.append("⚠️ HSTS missing")

    # Check X-Frame-Options
    if "X-Frame-Options" in headers:
        score += 1
        notes.append("✅ Clickjacking protection (X-Frame-Options)")
    else:
        notes.append("⚠️ Missing X-Frame-Options")

    # Check Content-Security-Policy
    if "Content-Security-Policy" in headers:
        score += 1
        notes.append("✅ Content-Security-Policy present")
    else:
        notes.append("⚠️ Missing CSP")

    # Check X-Content-Type-Options
    if "X-Content-Type-Options" in headers:
        score += 1
        notes.append("✅ MIME sniffing protection")
    else:
        notes.append("⚠️ Missing X-Content-Type-Options")

    # Check Referrer-Policy
    if "Referrer-Policy" in headers:
        score += 1
        notes.append("✅ Referrer policy set")
    else:
        notes.append("⚠️ Missing Referrer-Policy")

    # Check Permissions-Policy
    if "Permissions-Policy" in headers:
        score += 1
        notes.append("✅ Permissions-Policy present")
    else:
        notes.append("⚠️ Missing Permissions-Policy")

    return {"score": f"{score}/{max_score}", "notes": notes if notes else ["No header notes available"]}

def flatten_cert_fields(nested_fields):
    flat = {}
    for outer in nested_fields:
        for inner in outer:
            if isinstance(inner, tuple) and len(inner) == 2:
                k, v = inner
                flat[k] = v
    return flat


def inspect_ssl_and_headers(target_url: str) -> Dict[str, any]:
    """Inspect SSL certificate and HTTP headers for a given URL."""
    result = {
        "headers": {},
        "ssl": {},
        "header_security": {"score": "0/6", "notes": ["No header notes available"]},
        "error": None
    }

    # Validate URL
    valid_url = validate_url(target_url)
    if not valid_url:
        result["error"] = "Invalid URL provided"
        logger.error(result["error"])
        return result

    try:
        parsed_url = urlparse(valid_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443  # Use provided port or default to 443

        # SSL Inspection
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    print("RAW CERT:", cert)

                    cipher = ssock.cipher()
                    expired = datetime.utcnow() > datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = calculate_days_left(cert["notAfter"])

                    issuer_raw = cert.get("issuer", [])
                    subject_raw = cert.get("subject", [])

                    issuer = flatten_cert_fields(cert.get("issuer", []))
                    subject = flatten_cert_fields(cert.get("subject", []))


                    result["ssl"] = {
                        "issuer": issuer,
                        "subject": subject,
                        "version": cert.get("version"),
                        "valid_from": cert.get("notBefore"),
                        "valid_to": cert.get("notAfter"),
                        "expired": datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z") < datetime.utcnow(),
                        "days_left": (datetime.strptime(cert.get("notAfter"),"%b %d %H:%M:%S %Y %Z") - datetime.utcnow()).days,
                        "serial_number": cert.get("serialNumber"),
                        "cipher_suite": ssock.cipher()[0],
                        "signature_algorithm": cert.get("signatureAlgorithm", "N/A")
                    }


        except (socket.timeout, ssl.SSLError, ConnectionError) as e:
            result["error"] = f"SSL inspection failed: {str(e)}"
            logger.error(result["error"])
            return result

        # Header Inspection
        try:
            response = requests.get(valid_url, timeout=10, verify=True)
            headers = dict(response.headers)
            result["headers"] = headers
            result["header_security"] = evaluate_header_security(headers)
        except requests.RequestException as e:
            result["error"] = f"Header inspection failed: {str(e)}"
            logger.error(result["error"])
            return result

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        logger.error(result["error"])

    logger.info(f"SSL inspection completed for {target_url}")
    return result

