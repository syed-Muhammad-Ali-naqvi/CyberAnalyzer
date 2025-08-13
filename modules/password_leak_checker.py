import hashlib
import requests

def  check_password_leak(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if response.status_code != 200:
            return {"Error": "Failed to connect to breach database. Please try again later."}

        hashes = (line.split(":") for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return {
                    "leaked": True,
                    "count": int(count)
                }
        return {
            "leaked": False,
            "count": 0
        }
    except Exception as e:
        return {"Error": f"Something went wrong: {str(e)}"}



