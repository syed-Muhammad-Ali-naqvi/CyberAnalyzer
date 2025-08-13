import math, string, random, re


def analyze_password_strength(password):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digits = bool(re.search(r"\d",password))
    has_symbols = bool(re.search(r'[^a-zA-Z0-9]', password))

    score = 0
    details = []

    if length >= 8:
        score += 1
    else:
        details.append("Too short (minimum 8 characters).")

    if has_upper:
        score += 1
    else:
        details.append("No uppercase letters.")

    if has_lower:
        score += 1
    else:
        details.append("No lowercase letters.")

    if has_digits:
        score += 1
    else:
        details.append("No digits.")

    if has_symbols:
        score += 1
    else:
        details.append("No special character.")

    if length >= 14:
        score += 1

    strenght = {
        0: "Very Weak", 1: "Weak", 2:"Weak", 3: "Moderate",
        4: "Strong", 5: "Very Strong", 6: "Excellent"
    }

    return {
        "score": score,
        "rating": strenght.get(score, "Unknown"),
        "length": length,
        "issues": details
    }



def generate_strong_password(length=16, use_uppper=True, use_lower=True, use_digits=True, use_symbols=True):
    if not any([use_uppper, use_lower, use_digits, use_symbols]):
        raise ValueError("At least one character type must be selected")

    chars = ""
    if use_uppper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation

    return " ".join(random.choice(chars) for _ in range(length))





















