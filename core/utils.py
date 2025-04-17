import getpass, json, os
from datetime import datetime

def get_password():
    return getpass.getpass("Enter encryption password: ")

def save_metadata(filename, salt, iv):
    meta = {
        "salt": salt.hex(),
        "iv": iv.hex()
    }
    with open(f'storage/keys/{os.path.basename(filename)}.meta.json', 'w') as f:
        json.dump(meta, f, indent=2)

def log_action(action):
    os.makedirs("logs", exist_ok=True)
    with open("logs/actions.log", "a") as f:
        f.write(f"[{datetime.now()}] {action}\n")