# PassShield — Password Strength Analyzer

A full-stack password strength checker with entropy analysis, pattern detection, and a secure learning mechanism. Built with Python (Flask) + HTML/CSS/JS.

---

## Features

- **Entropy Calculation** — Uses `H = L × log₂(N)` to measure password unpredictability in bits
- **Rule Validation** — Checks length, character types, and complexity
- **Pattern Detection** — Catches repeated chars, keyboard walks, sequential sequences, leet-speak substitutions, and date patterns
- **Blacklist Check** — Compares against a curated list of common passwords
- **Secure Learning** — Stores SHA-256 hashes (never raw passwords) of weak passwords for future flagging
- **Crack Time Estimate** — Estimates time to brute-force at 10B guesses/sec (GPU)
- **Strength Score** — Combines entropy, rule checks, and pattern penalties into a 0–100 score
- **Modern UI** — Cyberpunk terminal aesthetic, real-time feedback, animated strength meter

---

## Security Design

> ⚠️ Raw passwords are **never** stored.

The system uses a two-pronged approach:
1. **Blacklist** — A file of known weak passwords checked by value comparison at runtime only
2. **Hash Learning** — When a password is classified as Weak, its SHA-256 hash is stored in `hashes.txt`. On future checks, password hashes are compared — if matched, the password is flagged as "previously weak" without ever knowing the original

---

## File Structure

```
project/
├── app.py              # Flask app, API endpoint, hash management
├── entropy.py          # Entropy calculation and strength classification
├── patterns.py         # Pattern detection and feedback generation
├── blacklist.txt       # Common weak passwords list
├── hashes.txt          # SHA-256 hashes of previously detected weak passwords
├── requirements.txt
├── templates/
│   └── index.html      # Full frontend (HTML + CSS + JS)
└── README.md
```

---

## Setup & Run

```bash
# 1. Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py

# 4. Open browser
# Go to http://127.0.0.1:5000
```

---

## API

**POST** `/check-password`

Request:
```json
{ "password": "MyP@ssw0rd" }
```

Response:
```json
{
  "entropy": 52.44,
  "strength": "Moderate",
  "score": 61,
  "feedback": ["Leet-speak substitutions are well-known..."],
  "patterns_detected": ["common_substitution"],
  "is_common": false,
  "previously_weak": false,
  "crack_time": "3 days",
  "char_set_size": 95
}
```

---

## Strength Classification

| Entropy (bits) | Base Strength |
|----------------|---------------|
| < 36           | Weak          |
| 36 – 59        | Moderate      |
| ≥ 60           | Strong        |

Score and pattern penalties may downgrade the classification.

---

## Tech Stack

- **Backend**: Python 3, Flask
- **Frontend**: Vanilla HTML5, CSS3 (custom properties, animations), JavaScript (ES6+)
- **Security**: hashlib SHA-256, no raw password storage
- **Fonts**: Orbitron, Rajdhani, Share Tech Mono (Google Fonts)
