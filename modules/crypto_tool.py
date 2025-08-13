import base64
import codecs
from cryptography.fernet import Fernet

def handle_crypto(operation, method, text, key=None, extra=None):
    try:
        if method == 'base64':
            return base64_handler(operation, text)
        elif method == "base32":
            return base32_handler(operation, text)
        elif method == "base85":
            return base85_handler(operation, text)
        elif method == "hex":
            return hex_handler(operation, text)
        elif method == "rot13":
            return codecs.encode(text, "rot_13")
        elif method == "caesar":
            shift = int(key) if key else 3
            return caesar_cipher(text, shift, operation)
        elif method == "vigenere":
            return vigenere_cipher(text, key, operation)
        elif method == "fernet":
            return fernet_handler(operation, text, key)
        else:
            return "Unsupported method"
    except Exception as e:
        return f"Error: {str(e)}"



def base64_handler(op, txt):
    if op == 'encode':
        return base64.b64encode(txt.encode()).decode()
    elif op == 'decode':
        return base64.b64decode(txt.encode()).decode()

def base32_handler(op, txt):
    if op == "encode":
        return base64.b32encode(txt.encode()).decode()
    elif op == "decode":
        return base64.b32encode(txt.encode()).decode()

def base85_handler(op, txt):
    if op == "encode":
        return base64.b85encode(txt.encode()).decode()
    elif op == "decode":
        return base64.b85encode(txt.encode()).decode()

def hex_handler(op, txt):
    if op == "encode":
        return txt.encode().hex()
    elif op == 'decode':
        return bytes.fromhex(txt).decode()


def caesar_cipher(text, shift, operation):
    result = ""
    if operation == "decode":
        shift = -shift
    for char in text:
        if char.islapha():
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result



def vigenere_cipher(text, keyword, operation):
    if not keyword:
        raise ValueError("Keyword required for Vigenere Cipher.")
    result = ""
    keyword = keyword.lower()
    k_len = len(keyword)
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(keyword[i % k_len]) - ord("a")
            if operation == "decode":
                shift = -shift
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result



def fernet_handler(op, text, key):
    if not key:
        raise ValueError("Key is required for Fernet.")
    f = Fernet(key.encode())
    if op == "encode":
        return f.encrypt(text.encode()).decode()
    elif op == "decode":
        return f.decrypt(text.encode()).decode()
















