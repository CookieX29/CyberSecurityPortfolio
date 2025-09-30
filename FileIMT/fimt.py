import os
import hashlib
import time 
import json
from datetime import datetime

MONITOR_DIR = "monitor_this_folder"
HASH_FILE = "file_hashes.json"
INTERVAL = 10  # seconds


def hash_file(filepath):
    """Generate SHA-256 hash for a given file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None


def build_baseline():
    """Create baseline hashes for all files in the directory."""
    hashes = {}
    for root, _, files in os.walk(MONITOR_DIR):
        for file in files:
            path = os.path.join(root, file)
            file_hash = hash_file(path)
            if file_hash:
                hashes[path] = file_hash
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)
    print(f"[+] Baseline created with {len(hashes)} files.")


def monitor():
    """Continuously monitor files for changes."""
    if not os.path.exists(HASH_FILE):
        print("[!] No baseline found. Run baseline creation first.")
        return

    with open(HASH_FILE, "r") as f:
        baseline = json.load(f)

    while True:
        current = {}
        for root, _, files in os.walk(MONITOR_DIR):
            for file in files:
                path = os.path.join(root, file)
                file_hash = hash_file(path)
                if file_hash:
                    current[path] = file_hash

        # Compare baseline and current state
        for path, old_hash in baseline.items():
            if path not in current:
                print(f"[DELETED] {path} at {datetime.now()}")
            elif current[path] != old_hash:
                print(f"[MODIFIED] {path} at {datetime.now()}")

        for path in current:
            if path not in baseline:
                print(f"[NEW FILE] {path} at {datetime.now()}")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    print("1. Create Baseline\n2. Monitor Directory")
    choice = input("Choose option (1/2): ")

    if choice == "1":
        build_baseline()
    elif choice == "2":
        monitor()
    else:
        print("Invalid choice.")
