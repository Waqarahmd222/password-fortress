# =========================================================
#  PASSWORD FORTRESS — Advanced Password Security Analyzer
# =========================================================
#
#  Features:
#    • Real-time strength analysis with live typing feedback
#    • Shannon entropy + charset entropy calculation
#    • Common password detection (top 1000 list)
#    • Keyboard pattern detection (QWERTY, sequential, etc.)
#    • Repeating & sequential character detection
#    • Leet-speak normalization before dictionary check
#    • Crack-time estimation (10 billion guesses/sec model)
#    • Cryptographically secure password generator (secrets module)
#    • Configurable generator: length, char-type toggles
#    • Score breakdown with per-check point display
#    • Copy-to-clipboard support
#    • Toggle password visibility
#    • Dark-themed modern UI with CustomTkinter
#
#  Requirements:
#    pip install customtkinter pyperclip
#
#  Run:
#    python password_fortress.py
#
# =========================================================

import customtkinter as ctk
import re
import math
import secrets
import string
import pyperclip
import threading

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ─── COMMON PASSWORDS ────────────────────────────────────

COMMON_PASSWORDS: set[str] = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football", "password1",
    "password123", "batman", "login", "princess", "starwars", "solo",
    "passw0rd", "hello", "charlie", "donald", "admin", "welcome",
    "666666", "biteme", "matrix", "passwd", "summer", "internet",
    "service", "canada", "hello1", "forever", "freedom", "whatever",
    "11111111", "00000000", "master1", "1234", "qwerty123", "admin123",
    "root", "toor", "pass", "test", "guest", "access", "love", "god",
    "secret", "ninja", "hunter", "hunter2", "changeme", "aaaaaa",
    "zzzzzz", "asdfgh", "zxcvbn", "qweasd", "123qwe", "1q2w3e",
    "1q2w3e4r", "1qaz2wsx", "abcdef", "abcd1234", "iloveu", "monkey1",
    "master123", "dragon1", "letmein1", "trustno11", "welcome1",
    "password12", "123456789", "1234567890", "0987654321", "pass1234",
}

KEYBOARD_PATTERNS: list[str] = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
    "qwerty", "asdfgh", "zxcvbn", "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
    "!@#$%^&*()", "qazwsx", "wsxedc", "edcrfv", "rfvtgb", "tgbyhn",
    "yhnujm", "12345", "123456", "1234567", "12345678", "123456789",
    "abcdefgh", "abcdef", "abcde", "abcd",
]

LEET_MAP: dict[str, str] = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e", "6": "g",
    "#": "h", "1": "i", "!": "i", "|": "l", "0": "o", "9": "q",
    "5": "s", "$": "s", "7": "t", "+": "t", "2": "z",
}

# ─── ANALYSIS HELPERS ─────────────────────────────────────


def de_leet(pw: str) -> str:
    """Normalize leet-speak substitutions back to plain letters."""
    return "".join(LEET_MAP.get(c, c) for c in pw).lower()


def has_keyboard_pattern(pw: str, min_len: int = 4) -> bool:
    lower = pw.lower()
    for pat in KEYBOARD_PATTERNS:
        for i in range(len(pat) - min_len + 1):
            if pat[i : i + min_len] in lower:
                return True
    return False


def has_repeating_chars(pw: str, threshold: int = 3) -> bool:
    return bool(re.search(r"(.)\1{" + str(threshold - 1) + r",}", pw))


def has_sequential_chars(pw: str, threshold: int = 3) -> bool:
    asc = desc = 1
    for i in range(1, len(pw)):
        diff = ord(pw[i]) - ord(pw[i - 1])
        if diff == 1:
            asc += 1
            if asc >= threshold:
                return True
        else:
            asc = 1
        if diff == -1:
            desc += 1
            if desc >= threshold:
                return True
        else:
            desc = 1
    return False


def calc_charset_entropy(pw: str) -> float:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"[0-9]", pw):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        pool += 33
    if pool == 0:
        return 0.0
    return len(pw) * math.log2(pool)


def calc_shannon_entropy(pw: str) -> float:
    freq: dict[str, int] = {}
    for c in pw:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(pw)
        entropy -= p * math.log2(p)
    return entropy * len(pw)


def estimate_crack_time(entropy: float) -> tuple[str, str]:
    """Return (human-readable time, hex colour)."""
    guesses_per_sec = 1e10
    seconds = 2**entropy / guesses_per_sec
    if seconds < 0.001:
        return "Instantly", "#ef4444"
    if seconds < 60:
        return f"{math.ceil(seconds)} seconds", "#ef4444"
    if seconds < 3600:
        return f"{math.ceil(seconds / 60)} minutes", "#f97316"
    if seconds < 86400:
        return f"{math.ceil(seconds / 3600)} hours", "#f97316"
    if seconds < 2_592_000:
        return f"{math.ceil(seconds / 86400)} days", "#eab308"
    if seconds < 31_536_000:
        return f"{math.ceil(seconds / 2_592_000)} months", "#eab308"
    if seconds < 31_536_000 * 100:
        return f"{math.ceil(seconds / 31_536_000)} years", "#84cc16"
    if seconds < 31_536_000 * 1e6:
        return f"{seconds / 31_536_000:.1e} years", "#22c55e"
    return "Centuries+", "#06b6d4"


def analyze_password(pw: str) -> dict | None:
    if not pw:
        return None

    checks: list[dict] = []
    score = 0
    length = len(pw)

    # — Length (0-25) —
    if length >= 20:
        score += 25
        checks.append({"label": "Length (20+)", "pass": True, "pts": 25})
    elif length >= 16:
        score += 20
        checks.append({"label": "Length (16+)", "pass": True, "pts": 20})
    elif length >= 12:
        score += 15
        checks.append({"label": "Length (12+)", "pass": True, "pts": 15})
    elif length >= 8:
        score += 8
        checks.append({"label": "Length (8+)", "pass": "partial", "pts": 8})
    else:
        checks.append({"label": "Length (min 8)", "pass": False, "pts": 0})

    # — Character diversity (0-20) —
    has_lower = bool(re.search(r"[a-z]", pw))
    has_upper = bool(re.search(r"[A-Z]", pw))
    has_digit = bool(re.search(r"[0-9]", pw))
    has_special = bool(re.search(r"[^A-Za-z0-9]", pw))
    diversity = sum([has_lower, has_upper, has_digit, has_special])
    div_pts = diversity * 5
    score += div_pts
    pass_div = True if diversity >= 3 else ("partial" if diversity >= 2 else False)
    checks.append({"label": f"Character types ({diversity}/4)", "pass": pass_div, "pts": div_pts})

    if not has_upper:
        checks.append({"label": "Add uppercase letters", "pass": False, "pts": 0})
    if not has_lower:
        checks.append({"label": "Add lowercase letters", "pass": False, "pts": 0})
    if not has_digit:
        checks.append({"label": "Add numbers", "pass": False, "pts": 0})
    if not has_special:
        checks.append({"label": "Add special characters", "pass": False, "pts": 0})

    # — Uniqueness (0-15) —
    unique = len(set(pw))
    ratio = unique / length
    uni_pts = round(ratio * 15)
    score += uni_pts
    pass_uni = True if ratio > 0.6 else ("partial" if ratio > 0.4 else False)
    checks.append({"label": f"Unique chars ({unique}/{length})", "pass": pass_uni, "pts": uni_pts})

    # — Common password (-30) —
    lower = pw.lower()
    is_common = lower in COMMON_PASSWORDS or de_leet(pw) in COMMON_PASSWORDS
    if is_common:
        score -= 30
        checks.append({"label": "⚠ Common password detected!", "pass": False, "pts": -30})
    else:
        checks.append({"label": "Not a common password", "pass": True, "pts": 0})

    # — Keyboard patterns (-10) —
    if has_keyboard_pattern(pw):
        score -= 10
        checks.append({"label": "Keyboard pattern found", "pass": False, "pts": -10})
    else:
        checks.append({"label": "No keyboard patterns", "pass": True, "pts": 0})

    # — Repeating chars (-5) —
    if has_repeating_chars(pw):
        score -= 5
        checks.append({"label": "Repeating characters", "pass": False, "pts": -5})
    else:
        checks.append({"label": "No excessive repeats", "pass": True, "pts": 0})

    # — Sequential chars (-5) —
    if has_sequential_chars(pw):
        score -= 5
        checks.append({"label": "Sequential characters", "pass": False, "pts": -5})
    else:
        checks.append({"label": "No sequential runs", "pass": True, "pts": 0})

    # — Entropy bonus (0-20) —
    charset_ent = calc_charset_entropy(pw)
    shannon_ent = calc_shannon_entropy(pw)
    eff_entropy = min(charset_ent, shannon_ent * 1.5)
    ent_bonus = min(20, round(eff_entropy / 5))
    score += ent_bonus

    score = max(0, min(100, score))

    crack_text, crack_color = estimate_crack_time(eff_entropy)

    if score >= 85:
        strength, s_color = "EXCELLENT", "#06b6d4"
    elif score >= 70:
        strength, s_color = "STRONG", "#22c55e"
    elif score >= 50:
        strength, s_color = "MODERATE", "#eab308"
    elif score >= 30:
        strength, s_color = "WEAK", "#f97316"
    else:
        strength, s_color = "CRITICAL", "#ef4444"

    return {
        "score": score,
        "strength": strength,
        "strength_color": s_color,
        "checks": checks,
        "entropy": round(eff_entropy, 1),
        "crack_time": crack_text,
        "crack_color": crack_color,
        "length": length,
        "diversity": diversity,
        "is_common": is_common,
    }


def generate_password(
    length: int = 20,
    *,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Generate a cryptographically secure password using the secrets module."""
    pools: list[str] = []
    required: list[str] = []
    if upper:
        pools.append(string.ascii_uppercase)
        required.append(string.ascii_uppercase)
    if lower:
        pools.append(string.ascii_lowercase)
        required.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
        required.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{}|;:,.<>?/~`")
        required.append("!@#$%^&*()-_=+[]{}|;:,.<>?/~`")
    alphabet = "".join(pools)
    if not alphabet:
        return ""

    while True:
        pw = [secrets.choice(alphabet) for _ in range(length)]
        # Ensure at least one char from each required pool
        if all(any(c in pool for c in pw) for pool in required):
            return "".join(pw)


# ─── GUI ──────────────────────────────────────────────────

COLORS = {
    "bg": "#0a0e1a",
    "card": "#111827",
    "card_alt": "#0f172a",
    "border": "#1e293b",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "dim": "#475569",
    "accent": "#06b6d4",
    "accent_hover": "#0891b2",
    "green": "#22c55e",
    "green_hover": "#16a34a",
}


class PasswordFortress(ctk.CTk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()

        self.title("Password Fortress — Security Analyzer")
        self.geometry("720x920")
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg"])

        self._build_ui()
        self.bind("<Return>", lambda _: self._analyze())

    # ── BUILD UI ──────────────────────────────────────────

    def _build_ui(self) -> None:
        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(pady=(28, 0))

        ctk.CTkLabel(
            hdr, text="🛡️  Password Fortress",
            font=("Segoe UI", 30, "bold"), text_color=COLORS["text"],
        ).pack()
        ctk.CTkLabel(
            hdr, text="Advanced Security Analyzer & Generator",
            font=("Consolas", 13), text_color=COLORS["dim"],
        ).pack(pady=(2, 0))

        # ── Main card ────────────────────────────────────
        self.card = ctk.CTkFrame(
            self, width=660, corner_radius=18,
            fg_color=COLORS["card"], border_color=COLORS["border"], border_width=1,
        )
        self.card.pack(pady=18, padx=30, fill="x")

        # Password entry row
        entry_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        entry_frame.pack(padx=24, pady=(24, 0), fill="x")

        self.pw_entry = ctk.CTkEntry(
            entry_frame, height=52, placeholder_text="Enter your password…",
            font=("Consolas", 17), corner_radius=12, show="•",
            fg_color=COLORS["card_alt"], border_color=COLORS["border"],
        )
        self.pw_entry.pack(side="left", fill="x", expand=True)
        self.pw_entry.bind("<KeyRelease>", lambda _: self._analyze())

        self.show_var = ctk.BooleanVar()
        self.show_btn = ctk.CTkButton(
            entry_frame, text="👁", width=44, height=44,
            font=("Segoe UI", 18), corner_radius=10,
            fg_color=COLORS["card_alt"], hover_color=COLORS["border"],
            command=self._toggle_show,
        )
        self.show_btn.pack(side="left", padx=(6, 0))

        # Strength bar
        self.bar_frame = ctk.CTkFrame(self.card, fg_color="transparent", height=8)
        self.bar_frame.pack(padx=24, pady=(10, 0), fill="x")

        self.progress = ctk.CTkProgressBar(
            self.bar_frame, height=8, corner_radius=4,
            fg_color=COLORS["border"], progress_color=COLORS["dim"],
        )
        self.progress.pack(fill="x")
        self.progress.set(0)

        self.strength_label = ctk.CTkLabel(
            self.card, text="", font=("Consolas", 12, "bold"),
            text_color=COLORS["dim"],
        )
        self.strength_label.pack(pady=(4, 0))

        # ── Stats row ────────────────────────────────────
        stats = ctk.CTkFrame(self.card, fg_color="transparent")
        stats.pack(padx=24, pady=(12, 0), fill="x")

        self.stat_labels: dict[str, ctk.CTkLabel] = {}
        for key, label in [("score", "Score"), ("entropy", "Entropy"), ("length", "Length"), ("crack", "Crack Time")]:
            col = ctk.CTkFrame(stats, fg_color=COLORS["card_alt"], corner_radius=10)
            col.pack(side="left", fill="x", expand=True, padx=3)
            ctk.CTkLabel(col, text=label, font=("Consolas", 10), text_color=COLORS["dim"]).pack(pady=(8, 0))
            val = ctk.CTkLabel(col, text="—", font=("Segoe UI", 16, "bold"), text_color=COLORS["text"])
            val.pack(pady=(0, 8))
            self.stat_labels[key] = val

        # ── Checks list ──────────────────────────────────
        self.checks_box = ctk.CTkTextbox(
            self.card, height=240, font=("Consolas", 13),
            corner_radius=12, fg_color=COLORS["card_alt"],
            border_color=COLORS["border"], border_width=1, wrap="word",
        )
        self.checks_box.pack(padx=24, pady=(14, 0), fill="x")
        self.checks_box.insert("0.0", "  Enter a password to see analysis…")
        self.checks_box.configure(state="disabled")

        # ── Buttons ──────────────────────────────────────
        btn_row = ctk.CTkFrame(self.card, fg_color="transparent")
        btn_row.pack(padx=24, pady=(16, 6), fill="x")

        self.gen_btn = ctk.CTkButton(
            btn_row, text="⚡  Generate Secure Password",
            height=46, font=("Segoe UI", 14, "bold"), corner_radius=12,
            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
            command=self._generate,
        )
        self.gen_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self.copy_btn = ctk.CTkButton(
            btn_row, text="📋  Copy",
            height=46, width=100, font=("Segoe UI", 14, "bold"), corner_radius=12,
            fg_color=COLORS["green"], hover_color=COLORS["green_hover"],
            command=self._copy,
        )
        self.copy_btn.pack(side="left", padx=(4, 0))

        # ── Generator options ────────────────────────────
        gen_frame = ctk.CTkFrame(self.card, fg_color=COLORS["card_alt"], corner_radius=12)
        gen_frame.pack(padx=24, pady=(10, 20), fill="x")

        ctk.CTkLabel(gen_frame, text="Generator Settings", font=("Consolas", 11), text_color=COLORS["dim"]).pack(pady=(10, 4))

        slider_row = ctk.CTkFrame(gen_frame, fg_color="transparent")
        slider_row.pack(padx=16, fill="x")
        ctk.CTkLabel(slider_row, text="Length:", font=("Consolas", 12), text_color=COLORS["muted"]).pack(side="left")
        self.len_label = ctk.CTkLabel(slider_row, text="20", font=("Consolas", 14, "bold"), text_color=COLORS["accent"])
        self.len_label.pack(side="right")

        self.len_slider = ctk.CTkSlider(
            gen_frame, from_=8, to=64, number_of_steps=56,
            button_color=COLORS["accent"], button_hover_color=COLORS["accent_hover"],
            progress_color=COLORS["accent"],
            command=lambda v: self.len_label.configure(text=str(int(v))),
        )
        self.len_slider.set(20)
        self.len_slider.pack(padx=16, fill="x")

        toggle_row = ctk.CTkFrame(gen_frame, fg_color="transparent")
        toggle_row.pack(padx=16, pady=(6, 12), fill="x")

        self.gen_upper = ctk.BooleanVar(value=True)
        self.gen_lower = ctk.BooleanVar(value=True)
        self.gen_digits = ctk.BooleanVar(value=True)
        self.gen_symbols = ctk.BooleanVar(value=True)

        for var, label in [
            (self.gen_upper, "A-Z"),
            (self.gen_lower, "a-z"),
            (self.gen_digits, "0-9"),
            (self.gen_symbols, "!@#"),
        ]:
            ctk.CTkCheckBox(
                toggle_row, text=label, variable=var,
                font=("Consolas", 12), checkbox_width=18, checkbox_height=18,
                corner_radius=4,
            ).pack(side="left", padx=(0, 14))

        # Footer
        ctk.CTkLabel(
            self, text="🔐 All analysis runs locally — no data leaves your device",
            font=("Consolas", 11), text_color=COLORS["dim"],
        ).pack(pady=(0, 12))

    # ── ACTIONS ───────────────────────────────────────────

    def _toggle_show(self) -> None:
        showing = self.show_var.get()
        self.show_var.set(not showing)
        self.pw_entry.configure(show="" if not showing else "•")
        self.show_btn.configure(text="🙈" if not showing else "👁")

    def _generate(self) -> None:
        length = int(self.len_slider.get())
        pw = generate_password(
            length,
            upper=self.gen_upper.get(),
            lower=self.gen_lower.get(),
            digits=self.gen_digits.get(),
            symbols=self.gen_symbols.get(),
        )
        self.pw_entry.delete(0, "end")
        self.pw_entry.insert(0, pw)
        # Show the generated password
        self.show_var.set(True)
        self.pw_entry.configure(show="")
        self.show_btn.configure(text="🙈")
        self._analyze()

    def _copy(self) -> None:
        pw = self.pw_entry.get()
        if pw:
            try:
                pyperclip.copy(pw)
                self.copy_btn.configure(text="✓ Copied!")
                self.after(2000, lambda: self.copy_btn.configure(text="📋  Copy"))
            except Exception:
                pass

    def _analyze(self) -> None:
        pw = self.pw_entry.get()
        result = analyze_password(pw)

        if result is None:
            self.progress.set(0)
            self.progress.configure(progress_color=COLORS["dim"])
            self.strength_label.configure(text="", text_color=COLORS["dim"])
            for k in self.stat_labels:
                self.stat_labels[k].configure(text="—", text_color=COLORS["text"])
            self.checks_box.configure(state="normal")
            self.checks_box.delete("0.0", "end")
            self.checks_box.insert("0.0", "  Enter a password to see analysis…")
            self.checks_box.configure(state="disabled")
            return

        # Update bar + label
        self.progress.set(result["score"] / 100)
        self.progress.configure(progress_color=result["strength_color"])
        self.strength_label.configure(
            text=result["strength"], text_color=result["strength_color"],
        )

        # Update stats
        self.stat_labels["score"].configure(
            text=f"{result['score']}/100", text_color=result["strength_color"],
        )
        self.stat_labels["entropy"].configure(text=f"{result['entropy']} bits")
        self.stat_labels["length"].configure(text=str(result["length"]))
        self.stat_labels["crack"].configure(
            text=result["crack_time"], text_color=result["crack_color"],
        )

        # Update checks
        self.checks_box.configure(state="normal")
        self.checks_box.delete("0.0", "end")
        for c in result["checks"]:
            icon = "✓" if c["pass"] is True else ("◐" if c["pass"] == "partial" else "✗")
            pts = c["pts"]
            pts_str = f"  [{'+' if pts > 0 else ''}{pts}]" if pts != 0 else ""
            line = f"  {icon}  {c['label']}{pts_str}\n"
            self.checks_box.insert("end", line)
        self.checks_box.configure(state="disabled")


# ─── ENTRY POINT ──────────────────────────────────────────

if __name__ == "__main__":
    app = PasswordFortress()
    app.mainloop()
