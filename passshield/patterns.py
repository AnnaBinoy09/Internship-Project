import re

KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "!@#$%^&*()"
]

COMMON_SUBSTITUTIONS = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i',
    '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't',
    '8': 'b', '6': 'g', '2': 'z', '9': 'g'
}

COMMON_WORDS_WITH_SUBS = [
    "password", "passw0rd", "p@ssword", "p@ssw0rd",
    "admin", "letmein", "welcome", "monkey", "dragon",
    "master", "login", "access", "shadow", "sunshine"
]


def detect_repeated_chars(password):
    """Detect 3+ consecutive repeated characters."""
    return bool(re.search(r'(.)\1{2,}', password, re.IGNORECASE))


def detect_sequential_alpha(password):
    """Detect 3+ sequential alphabetical characters."""
    lower = password.lower()
    for i in range(len(lower) - 2):
        a, b, c = lower[i], lower[i+1], lower[i+2]
        if a.isalpha() and b.isalpha() and c.isalpha():
            if ord(b) == ord(a) + 1 and ord(c) == ord(b) + 1:
                return True
            if ord(b) == ord(a) - 1 and ord(c) == ord(b) - 1:
                return True
    return False


def detect_sequential_digits(password):
    """Detect 3+ sequential numeric characters."""
    for i in range(len(password) - 2):
        a, b, c = password[i], password[i+1], password[i+2]
        if a.isdigit() and b.isdigit() and c.isdigit():
            if int(b) == int(a) + 1 and int(c) == int(b) + 1:
                return True
            if int(b) == int(a) - 1 and int(c) == int(b) - 1:
                return True
    return False


def detect_keyboard_pattern(password):
    """Detect keyboard walk patterns like qwerty, asdf."""
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 2):
            pattern = row[i:i+3]
            if pattern in lower or pattern[::-1] in lower:
                return True
    return False


def detect_common_substitution(password):
    """Detect leet-speak substitutions like P@ssw0rd."""
    normalized = password.lower()
    for sub_char, real_char in COMMON_SUBSTITUTIONS.items():
        normalized = normalized.replace(sub_char, real_char)

    for word in COMMON_WORDS_WITH_SUBS:
        normalized_word = word.lower()
        for sub_char, real_char in COMMON_SUBSTITUTIONS.items():
            normalized_word = normalized_word.replace(sub_char, real_char)
        if normalized_word in normalized:
            return True
    return False


def detect_date_pattern(password):
    """Detect common date patterns like 1990, 01/01, ddmmyyyy."""
    return bool(re.search(
        r'(19|20)\d{2}|0[1-9][0-3]\d|[0-3]\d0[1-9]|\d{2}[/-]\d{2}',
        password
    ))


def detect_patterns(password):
    """Run all pattern detectors and return list of detected pattern names."""
    detected = []

    if detect_repeated_chars(password):
        detected.append("repeated_characters")
    if detect_sequential_alpha(password):
        detected.append("sequential_letters")
    if detect_sequential_digits(password):
        detected.append("sequential_digits")
    if detect_keyboard_pattern(password):
        detected.append("keyboard_pattern")
    if detect_common_substitution(password):
        detected.append("common_substitution")
    if detect_date_pattern(password):
        detected.append("date_pattern")

    return detected


def generate_feedback(password, entropy, patterns, is_common, previously_weak):
    """Generate actionable feedback messages."""
    feedback = []

    if is_common:
        feedback.append("This is a very commonly used password — avoid it entirely")
    if previously_weak:
        feedback.append("This password was previously identified as weak")

    if len(password) < 8:
        feedback.append("Password must be at least 8 characters long")
    elif len(password) < 12:
        feedback.append("Increase length to at least 12 characters for better security")

    if not any(c.islower() for c in password):
        feedback.append("Add lowercase letters (a–z)")
    if not any(c.isupper() for c in password):
        feedback.append("Add uppercase letters (A–Z)")
    if not any(c.isdigit() for c in password):
        feedback.append("Include at least one number (0–9)")
    if not any(not c.isalnum() for c in password):
        feedback.append("Include special characters (!, @, #, $, etc.)")

    pattern_messages = {
        "repeated_characters": "Avoid repeating the same character multiple times",
        "sequential_letters": "Avoid sequential letters like 'abc' or 'xyz'",
        "sequential_digits": "Avoid sequential numbers like '1234' or '9876'",
        "keyboard_pattern": "Avoid keyboard patterns like 'qwerty' or 'asdf'",
        "common_substitution": "Leet-speak substitutions (@ for a, 0 for o) are well-known — use truly random characters",
        "date_pattern": "Avoid using dates or years in your password"
    }

    for pattern in patterns:
        if pattern in pattern_messages:
            feedback.append(pattern_messages[pattern])

    if entropy < 36 and not feedback:
        feedback.append("Try a longer, more complex password or use a passphrase")

    if not feedback:
        feedback.append("Great password! Consider storing it in a password manager")

    return feedback
