import math
import re
import string

# 1. Common leaked / weak password blacklist
COMMON_LEAKED_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "admin",
    "welcome",
    "iloveyou",
    "abc123",
    "monkey",
}


def calculate_entropy(password: str) -> tuple[float, int]:
    """Calculate Shannon password entropy based on character pool size.

    Formula: E = L * log2(R) where L is length and R is character pool size.
    """
    length = len(password)
    if length == 0:
        return 0.0, 0

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    # Checks for punctuation and printable symbols
    if re.search(f"[{re.escape(string.punctuation)}]", password):
        pool_size += 32

    # Account for whitespace or non-standard characters
    other_chars = sum(
        1
        for c in set(password)
        if c not in string.ascii_letters + string.digits + string.punctuation
    )
    pool_size += other_chars

    if pool_size == 0:
        return 0.0, 0

    entropy = length * math.log2(pool_size)
    return round(entropy, 2), pool_size


def check_policy_compliance(password: str) -> tuple[dict, list[str]]:
    """Validate password against security policy criteria and generate actionable feedback."""
    feedback = []

    criteria = {
        "min_length": len(password) >= 12,
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(
            re.search(f"[{re.escape(string.punctuation)}]", password)
        ),
    }

    if not criteria["min_length"]:
        feedback.append(
            f"Increase length to at least 12 characters (currently {len(password)})."
        )
    if not criteria["has_lowercase"]:
        feedback.append("Include at least one lowercase letter (a-z).")
    if not criteria["has_uppercase"]:
        feedback.append("Include at least one uppercase letter (A-Z).")
    if not criteria["has_digit"]:
        feedback.append("Include at least one numerical digit (0-9).")
    if not criteria["has_special"]:
        feedback.append(
            "Include at least one special character (!@#$%^&* etc.)."
        )

    return criteria, feedback


def evaluate_password(password: str) -> dict:
    """Classify overall strength based on entropy, blacklist, and policy compliance."""
    is_leaked = password.lower().strip() in COMMON_LEAKED_PASSWORDS
    entropy, pool_size = calculate_entropy(password)
    policy_results, feedback = check_policy_compliance(password)

    if is_leaked:
        rating = "Weak"
        feedback.insert(
            0,
            "CRITICAL: This password appears on known leaked/default password lists.",
        )
    else:
        # Standard classification tiers by entropy (bits):
        # < 36: Weak | 36-59: Moderate | 60-79: Strong | >= 80: Exceptional
        if entropy < 36 or len(password) < 8:
            rating = "Weak"
        elif entropy < 60:
            rating = "Moderate"
        elif entropy < 80 and all(policy_results.values()):
            rating = "Strong"
        elif entropy >= 80 and all(policy_results.values()):
            rating = "Exceptional"
        else:
            # High entropy but failed explicit policy requirements
            rating = "Moderate"

    return {
        "password": password,
        "is_leaked": is_leaked,
        "entropy_bits": entropy,
        "pool_size": pool_size,
        "policy_checks": policy_results,
        "strength": rating,
        "feedback": feedback
        if feedback
        else ["Password meets strong security guidelines!"],
    }


# --- Demonstration / Testing ---
if __name__ == "__main__":
    test_passwords = [
        "123456",  # Blacklisted
        "secretpass",  # Low entropy, lowercase only
        "P@ssw0rd2026",  # Policy compliant, moderate length
        "correct-horse-battery-staple-9!",  # High entropy passphrase
    ]

    for pwd in test_passwords:
        result = evaluate_password(pwd)
        print("=" * 60)
        print(f"Password:    {result['password']}")
        print(f"Strength:    {result['strength']}")
        print(
            f"Entropy:     {result['entropy_bits']} bits (Pool size: {result['pool_size']})"
        )
        print(f"Leaked List: {'Yes' if result['is_leaked'] else 'No'}")
        print("Feedback:")
        for item in result["feedback"]:
            print(f"  - {item}")