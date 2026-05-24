# 🛡️ Password Fortress

**Advanced Password Security Analyzer & Generator**

A modern, dark-themed desktop application that provides real-time password strength analysis with detailed security checks, entropy calculation, crack-time estimation, and a cryptographically secure password generator.

![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-94a3b8?style=flat-square)

---

## ✨ Features

### Security Analysis
- **Real-time scoring** — live analysis as you type with a 0–100 point breakdown
- **Dual entropy calculation** — combines charset entropy with Shannon entropy for accuracy
- **Common password detection** — checks against a curated list with leet-speak normalization (`p@55w0rd` → `password`)
- **Keyboard pattern detection** — catches QWERTY rows, diagonal walks (`qazwsx`), and common sequences
- **Repeating character detection** — flags runs like `aaa` or `111`
- **Sequential character detection** — catches ascending/descending runs like `abc` or `987`
- **Crack-time estimation** — models a 10 billion guesses/second attacker

### Password Generator
- **Cryptographically secure** — uses Python's `secrets` module (CSPRNG)
- **Configurable length** — slider from 8 to 64 characters
- **Character type toggles** — independently enable/disable uppercase, lowercase, digits, and symbols
- **Guaranteed diversity** — ensures at least one character from each enabled pool

### User Interface
- Dark-themed modern UI built with CustomTkinter
- Toggle password visibility
- One-click copy to clipboard
- Per-check point breakdown with pass/fail/partial indicators
- Color-coded strength levels: Critical → Weak → Moderate → Strong → Excellent

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher

### Setup

```bash
# Clone the repository
git clone https://github.com/Waqarahmd222/password-fortress.git
cd password-fortress

# Install dependencies
pip install -r requirements.txt

# Run the application
python password_fortress.py
```

---

## 🔒 Scoring System

| Check                  | Points     |
|------------------------|------------|
| Length (8–20+ chars)   | 0 to +25   |
| Character diversity    | 0 to +20   |
| Unique character ratio | 0 to +15   |
| Entropy bonus          | 0 to +20   |
| Common password        | −30        |
| Keyboard pattern       | −10        |
| Repeating characters   | −5         |
| Sequential characters  | −5         |

### Strength Levels

| Score   | Level      |
|---------|------------|
| 85–100  | Excellent  |
| 70–84   | Strong     |
| 50–69   | Moderate   |
| 30–49   | Weak       |
| 0–29    | Critical   |

---

## 🔐 Privacy

All analysis runs **entirely locally** on your machine. No passwords or data are transmitted anywhere — there is no network activity whatsoever.

---

## 📁 Project Structure

```
password-fortress/
├── password_fortress.py   # Main application
├── requirements.txt       # Python dependencies
├── LICENSE                 # MIT License
└── README.md              # This file
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
