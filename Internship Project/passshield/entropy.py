import math

def calculate_entropy(password):
    """
    Calculate Shannon entropy using H = L * log2(N)
    where L = password length, N = character set size
    """
    if not password:
        return 0, 0

    char_set_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_lower:
        char_set_size += 26
    if has_upper:
        char_set_size += 26
    if has_digit:
        char_set_size += 10
    if has_symbol:
        char_set_size += 33

    if char_set_size == 0:
        return 0, 0

    L = len(password)
    N = char_set_size
    entropy = L * math.log2(N)

    return entropy, N


def classify_strength(entropy, score, is_compromised=False):
    """
    Classify password strength based on entropy and score.
    """
    if is_compromised:
        return "Weak"

    if entropy < 28:
        return "Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        if score < 30:
            return "Weak"
        return "Moderate"
    else:
        if score < 40:
            return "Moderate"
        return "Strong"
