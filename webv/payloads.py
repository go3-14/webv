"""Load/save payloads.json — unchanged schema from v1 so existing files keep working."""

import json
import logging

PAYLOAD_FILE = "payloads.json"

DEFAULTS = {
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "sqli": ["'", "' OR 1=1 --"],
}


def load_payloads(path: str = PAYLOAD_FILE) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key, default in DEFAULTS.items():
            data.setdefault(key, default)
        return data
    except FileNotFoundError:
        logging.warning("Payload file '%s' not found. Using defaults.", path)
        return dict(DEFAULTS)
    except json.JSONDecodeError as e:
        logging.error("Payload file is malformed JSON: %s. Using defaults.", e)
        return dict(DEFAULTS)


def save_payloads(data: dict, path: str = PAYLOAD_FILE) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except OSError as e:
        logging.error("Could not save payloads: %s", e)


def add_payload(vtype: str, payload: str, path: str = PAYLOAD_FILE) -> bool:
    if not vtype or not payload:
        logging.error("Both --type and --payload are required for the add command.")
        return False
    data = load_payloads(path)
    if vtype not in data:
        logging.error("Unknown type '%s'. Use 'xss' or 'sqli'.", vtype)
        return False
    data[vtype].append(payload)
    save_payloads(data, path)
    logging.info("Payload added to '%s': %s", vtype, payload)
    return True


def list_payloads(path: str = PAYLOAD_FILE) -> None:
    data = load_payloads(path)
    for k, v in data.items():
        print(f"\n{k.upper()}:")
        for p in v:
            print(f"- {p}")
