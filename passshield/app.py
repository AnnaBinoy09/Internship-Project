from flask import Flask, request, jsonify, render_template
import hashlib
import os

from entropy import calculate_entropy, classify_strength
from patterns import detect_patterns, generate_feedback

app = Flask(__name__)

BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), "blacklist.txt")
HASHES_FILE = os.path.join(os.path.dirname(__file__), "hashes.txt")

def load_blacklist():
    blacklist = set()
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                blacklist.add(line.strip().lower())
    return blacklist

def load_hashes():
    hashes = set()
    if os.path.exists(HASHES_FILE):
        with open(HASHES_FILE, "r") as f:
            for line in f:
                hashes.add(line.strip())
    return hashes

def save_weak_hash(password_hash):
    hashes = load_hashes()
    if password_hash not in hashes:
        with open(HASHES_FILE, "a") as f:
            f.write(password_hash + "\n")

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

BLACKLIST = load_blacklist()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check-password", methods=["POST"])
def check_password():
    data = request.get_json()
    if not data or "password" not in data:
        return jsonify({"error": "No password provided"}), 400

    password = data["password"]

    if not password:
        return jsonify({
            "entropy": 0,
            "strength": "None",
            "score": 0,
            "feedback": ["Please enter a password"],
            "patterns_detected": [],
            "is_common": False,
            "previously_weak": False,
            "crack_time": "instantly"
        })

    # Hash for secure comparison (never store raw)
    pwd_hash = hash_password(password)

    # Check blacklist
    is_common = password.lower() in BLACKLIST

    # Check previously flagged weak hashes
    known_hashes = load_hashes()
    previously_weak = pwd_hash in known_hashes

    # Entropy
    entropy, char_set_size = calculate_entropy(password)

    # Pattern detection
    patterns_detected = detect_patterns(password)

    # Base score from entropy
    score = min(100, int(entropy * 1.5))

    # Deductions for patterns
    score -= len(patterns_detected) * 12
    score = max(0, score)

    # Override for common/weak
    if is_common or previously_weak:
        score = min(score, 10)

    # Strength classification
    strength = classify_strength(entropy, score, is_common or previously_weak)

    # Feedback
    feedback = generate_feedback(password, entropy, patterns_detected, is_common, previously_weak)

    # Save hash if weak (secure learning)
    if strength == "Weak":
        save_weak_hash(pwd_hash)

    # Crack time estimate
    crack_time = estimate_crack_time(entropy)

    return jsonify({
        "entropy": round(entropy, 2),
        "strength": strength,
        "score": score,
        "feedback": feedback,
        "patterns_detected": patterns_detected,
        "is_common": is_common,
        "previously_weak": previously_weak,
        "crack_time": crack_time,
        "char_set_size": char_set_size
    })

def estimate_crack_time(entropy):
    guesses_per_second = 1e10  # 10 billion/sec (modern GPU)
    total_guesses = 2 ** entropy
    seconds = total_guesses / guesses_per_second

    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds/60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds/3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds/86400)} days"
    elif seconds < 3.154e9:
        return f"{int(seconds/31536000)} years"
    elif seconds < 3.154e12:
        return f"{int(seconds/3.154e9)} thousand years"
    elif seconds < 3.154e15:
        return f"{int(seconds/3.154e12)} million years"
    else:
        return "billions of years"

if __name__ == "__main__":
    app.run(debug=True, port=5000)
