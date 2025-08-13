# modules/hash_tools.py

import hashlib
import bcrypt

def generate_hashes(text):
    hashes = {
        "MD5": hashlib.md5(text.encode()).hexdigest(),
        "SHA-1": hashlib.sha1(text.encode()).hexdigest(),
        "SHA-224": hashlib.sha224(text.encode()).hexdigest(),
        "SHA-256": hashlib.sha256(text.encode()).hexdigest(),
        "SHA-384": hashlib.sha384(text.encode()).hexdigest(),
        "SHA-512": hashlib.sha512(text.encode()).hexdigest(),
        "SHA3-256": hashlib.sha3_256(text.encode()).hexdigest(),
        "SHA3-512": hashlib.sha3_512(text.encode()).hexdigest(),
        "BLAKE2b": hashlib.blake2b(text.encode()).hexdigest(),
        "BLAKE2s": hashlib.blake2s(text.encode()).hexdigest(),
        "bcrypt": bcrypt.hashpw(text.encode(), bcrypt.gensalt()).decode(),
        "PBKDF2 (SHA256, 100,000 iter)": hashlib.pbkdf2_hmac('sha256', text.encode(), b'salt', 100000).hex()
    }
    return hashes


def hash_password(password=None, format=None):
    if not password or not format:
        return "Password or format missing!"

    format = format.lower()
    valid_format = ["md5", "sha1", "sha256"]

    if format in valid_format:
        encoded_password = password.encode()
        if format == "md5":
            return hashlib.md5(encoded_password).hexdigest()
        elif format == "sha1":
            return hashlib.sha1(encoded_password).hexdigest()
        elif format == "sha256":
            return hashlib.sha256(encoded_password).hexdigest()
        else:
            return "Something went wrong."
    else:
        return "This method is not supported"














