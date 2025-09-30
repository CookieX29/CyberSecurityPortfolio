import re
import hashlib
import requests

def check_strength(password: str) -> dict:
    """Evaluate password strength based on length and character diversity."""
    strength = {"length": False, "upper": False, "lower": False, "digit": False, "special": False}

    # Criteria checks
    strength["length"] = len(password) >= 12
    strength["upper"] = bool(re.search(r"[A-Z]", password))
    strength["lower"] = bool(re.search(r"[a-z]", password))
    strength["digit"] = bool(re.search(r"\d", password))
    strength["special"] = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    score = sum(strength.values())
    return {"criteria": strength, "score": score}


def check_pwned(password: str) -> int:
    """Check password against HaveIBeenPwned using k-anonymity."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError("Error fetching from API")

    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0


def main():
    password = input("Enter a password to check: ")

    # Strength check
    result = check_strength(password)
    print(f"\nPassword Strength Score: {result['score']}/5")
    for crit, passed in result["criteria"].items():
        print(f"- {crit.capitalize()}: {'✔️' if passed else '❌'}")

    # Breach check
    pwned_count = check_pwned(password)
    if pwned_count:
        print(f"\n⚠️ WARNING: This password has been seen {pwned_count} times in data breaches!")
    else:
        print("\n✅ Good news: This password has NOT been found in known breaches.")

    # Recommendations
    if result['score'] < 5:
        print("\nSuggestions:")
        if not result["length"]: print("- Use at least 12 characters.")
        if not result["upper"]: print("- Add uppercase letters.")
        if not result["lower"]: print("- Add lowercase letters.")
        if not result["digit"]: print("- Include numbers.")
        if not result["special"]: print("- Include special characters.")


if __name__ == "__main__":
    main()
