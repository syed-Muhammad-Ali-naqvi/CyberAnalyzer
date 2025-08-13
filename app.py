from dateutil.tz import enfold
from flask import Flask, render_template, request, Response
from modules.hash_tools import hash_password, generate_hashes
from modules.password_leak_checker import check_password_leak
from modules.password_analyzer import analyze_password_strength, generate_strong_password
from modules.whois_tool import analyze_whois
import hashlib, bcrypt, requests
from modules.port_scanner import scan_stream
from modules.ip_tools import get_ip_geolocation
from modules.crypto_tool import handle_crypto
from modules.dns_lookup import lookup_dns
from modules.email_checker import check_email_reputation
from modules.url_Scanner import extract_signals
from modules.ssl_inspector import inspect_ssl_and_headers
import logging

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/features")
def features():
    return render_template("features.html")

@app.route("/resources")
def resources():
    return render_template("/resources.html")


@app.route("/hash-generator", methods=["GET", "POST"])
def hash_generator():
    result = None
    selected_algo = None
    text = ""

    hash_methods = {
        "MD5": lambda txt: hashlib.md5(txt.encode()).hexdigest(),
        "SHA-1": lambda txt: hashlib.sha1(txt.encode()).hexdigest(),
        "SHA-224": lambda txt: hashlib.sha224(txt.encode()).hexdigest(),
        "SHA-256": lambda txt: hashlib.sha256(txt.encode()).hexdigest(),
        "SHA-384": lambda txt: hashlib.sha384(txt.encode()).hexdigest(),
        "SHA-512": lambda txt: hashlib.sha512(txt.encode()).hexdigest(),
        "SHA3-256": lambda txt: hashlib.sha3_256(txt.encode()).hexdigest(),
        "SHA3-512": lambda txt: hashlib.sha3_512(txt.encode()).hexdigest(),
        "BLAKE2b": lambda txt: hashlib.blake2b(txt.encode()).hexdigest(),
        "BLAKE2s": lambda txt: hashlib.blake2s(txt.encode()).hexdigest(),
        "bcrypt": lambda txt: bcrypt.hashpw(txt.encode(), bcrypt.gensalt()).decode(),
        "PBKDF2 (SHA256, 100,000 iter)": lambda txt: hashlib.pbkdf2_hmac('sha256', txt.encode(), b'salt', 100000).hex()
    }

    if request.method == "POST":
        text = request.form.get("password")
        selected_algo = request.form.get("algorithm")
        if text and selected_algo in hash_methods:
            result = hash_methods[selected_algo](text)

    return render_template("hash_generator.html", result=result, selected_algo=selected_algo, methods=hash_methods.keys(), input_text=text)


@app.route("/hash-leak", methods=["GET", "POST"])
def hash_leak():
    leak_result = None
    if request.method == "POST":
        password = request.form.get("leak_password")
        try:
            sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]

            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url)

            if response.status_code == 200:
                found = False
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(":")
                    if hash_suffix == suffix:
                        leak_result = {"leaked": True, "count": int(count)}
                        found = True
                        break
                if not found:
                    leak_result = {"leaked": False}
            else:
                leak_result = {"error": "Failed to connect to API"}
        except Exception as e:
            leak_result = {"error": str(e)}

    return render_template("hash_leak.html", leak_result=leak_result)


@app.route("/port-scanner", methods=["GET", "POST"])
def port_scanner_route():
    if request.method == "POST":
        target = request.form['target']
        port_range = request.form['port_range']
        return Response(scan_stream(target, port_range), mimetype='text/event-stream')
    return render_template("port_scanner.html")


@app.route("/ip-lookup", methods=["GET", "POST"])
def ip_geological_route():
    results = None
    error = None
    if request.method == "POST":
        ip = request.form.get('ip')
        try:
            results = get_ip_geolocation(ip)
        except Exception as e:
            error = str(e)
    return render_template("ip_tool.html", results=results, error=error)


@app.route("/crypto", methods=["GET", "POST"])
def crypto_tool():
    result = ""
    error = ""

    if request.method == "POST":
        method = request.form.get("method")
        operation = request.form.get("operation")
        text = request.form.get("text")
        key = request.form.get("key", "")

        if operation == "encrypt":
            operation = "encode"
        elif operation == "decrypt":
            operation = "decode"

        try:
            result = handle_crypto(operation, method, text, key)
        except Exception as v:
            error = str(v)

    return render_template("crypto.html", result=result, error=error)


@app.route("/password-check", methods=["GET", "POST"])
def strength_tool():
    analysis = None
    error = ""
    generated = ""

    if request.method == "POST":
        action = request.form.get("action")

        if action == "analyze":
            password = request.form.get("password", "")
            if not password:
                error = "Please enter a password to analyze"
            else:
                analysis = analyze_password_strength(password)
                if analysis["score"] < 4:
                    generated = generate_strong_password(12, True, True, True, True)

        elif action == "generate":
            try:
                length = int(request.form.get("length", 14))
                use_upper = bool(request.form.get("upper"))
                use_lower = bool(request.form.get("lower"))
                use_digits = bool(request.form.get("digits"))
                use_symbols = bool(request.form.get("symbols"))

                generated = generate_strong_password(length, use_upper, use_lower, use_digits, use_symbols)
            except Exception as ve:
                error = str(ve)

    return render_template("password_analyzer.html", analysis=analysis, error=error, generated=generated)


@app.route("/whois", methods=["GET", "POST"])
def whois_tool():
    result = None
    if request.method == "POST":
        domain = request.form.get("domain")
        if domain:
            result = analyze_whois(domain)
        else:
            result = {"Error": "Please enter a valid domain."}
    return render_template("whois.html", result=result)


@app.route("/dns-lookup", methods=["GET", "POST"])
def dns_lookup():
    result = None
    error = None
    if request.method == "POST":
        domain = request.form.get("domain")
        if domain:
            try:
                result = lookup_dns(domain)
            except Exception as e:
                error = f"Error: {str(e)}"
    return render_template("dns_lookup.html", result=result, error=error)


@app.route('/email-reputation', methods=['GET', 'POST'])
def email_reputation():
    if request.method == 'POST':
        target_email = request.form.get('target_email')
        if not target_email:
            logger.error("No email provided for reputation check")
            return render_template('email_checker.html', result={"error": "No email provided"})
        result = check_email_reputation(target_email)
        return render_template('email_checker.html', result=result)
    return render_template('email_checker.html')


@app.route("/url-scanner", methods=["GET", "POST"])
def url_scanner():
    url = ""
    redirects = []
    signals = []
    error = None

    if request.method == "POST":
        url = request.form.get("url")
        if not url:
            error = "URL is required."
        else:
            if not url.startswith("http"):
                url = "http://" + url
            try:
                redirects, signals = extract_signals(url)
            except Exception as e:
                error = f"Error analyzing URL: {str(e)}"
    return render_template("url_scanner.html", url=url, redirects=redirects, error=error, signals=signals)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@app.route('/ssl-inspector', methods=['GET', 'POST'])
def ssl_inspector():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        if not target_url:
            logger.error("No URL provided for SSL inspection")
            return render_template('ssl_inspector.html', result={"error": "No URL provided"})
        try:
            result = inspect_ssl_and_headers(target_url)
            logger.info(f"SSL inspection completed for {target_url}")
            return render_template('ssl_inspector.html', result=result)
        except Exception as e:
            logger.error(f"Error in SSL inspection for {target_url}: {str(e)}")
            return render_template('ssl_inspector.html', result={"error": f"Inspection failed: {str(e)}"})
    return render_template('ssl_inspector.html')


if __name__ == "__main__":
    app.run(debug=True)



