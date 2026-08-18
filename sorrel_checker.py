#!/usr/bin/env python3
"""
Sorrel OTA Checker
Reads serial numbers from serials.txt, performs checkin requests with
the google/sorrel build fingerprint, and reports new OTA URLs to logs
and Discord.

Usage:
    python sorrel_checker.py --sorrel
"""

import sys
import os
import re
import gzip
import urllib.request
import urllib.error
import json
import struct
import time
import argparse
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────────────────────────────────────

SORREL_FINGERPRINT = "google/sorrel/sorrel:9/1/1:user/dev-keys,test-keys,release-keys"
SERIALS_FILE       = "serials.txt"
ARCHIVED_FILE      = "archived.txt"
LOG_FILE           = "sorrel_checker.log"
CHECKIN_URL        = "http://android.googleapis.com/checkin"

DISCORD_WEBHOOK    = os.environ.get("DISCORD_WEBHOOK", "")

REQUEST_DELAY_SEC  = 0.2   # delay between serial requests to avoid rate-limiting


# ─────────────────────────────────────────────────────────────────────────────
#  Protobuf helpers (extracted from sorrel-dog.py)
# ─────────────────────────────────────────────────────────────────────────────

def encode_varint(value):
    parts = []
    while value > 0x7f:
        parts.append((value & 0x7f) | 0x80)
        value >>= 7
    parts.append(value & 0x7f)
    return bytes(parts)


def encode_string(field_number, value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    tag = (field_number << 3) | 2
    return encode_varint(tag) + encode_varint(len(value)) + value


def encode_int64(field_number, value):
    tag = (field_number << 3) | 0
    return encode_varint(tag) + encode_varint(value & 0xFFFFFFFFFFFFFFFF)


def encode_bool(field_number, value):
    tag = (field_number << 3) | 0
    return encode_varint(tag) + bytes([1 if value else 0])


def decode_varint(data, offset):
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if byte < 0x80:
            break
        shift += 7
    return result, offset


def decode_string(data, offset, length):
    return data[offset : offset + length].decode("utf-8", errors="ignore"), offset + length


# ─────────────────────────────────────────────────────────────────────────────
#  Fingerprint parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_fingerprint(fingerprint):
    """
    Parses a standard Android build fingerprint.
    Format: oem/product/device:api/build_tag/incremental:build_type/key_type
    """
    parts = fingerprint.split("/")
    if len(parts) != 6:
        raise ValueError(
            f"Invalid fingerprint format. Expected 6 parts, got {len(parts)}: {parts}"
        )

    oem     = parts[0]
    product = parts[1]

    device_api = parts[2].split(":")
    if len(device_api) != 2:
        raise ValueError(f"Invalid device:api in part 3: {parts[2]}")
    device    = device_api[0]
    api_level = device_api[1]

    build_tag = parts[3]

    incremental_type = parts[4].split(":")
    if len(incremental_type) != 2:
        raise ValueError(f"Invalid incremental:build_type in part 5: {parts[4]}")
    incremental = incremental_type[0]
    build_type  = incremental_type[1]

    key_type = parts[5]

    return {
        "fingerprint": fingerprint,
        "oem":         oem,
        "product":     product,
        "device":      device,
        "api_level":   api_level,
        "build_tag":   build_tag,
        "incremental": incremental,
        "build_type":  build_type,
        "key_type":    key_type,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Checkin request builder
# ─────────────────────────────────────────────────────────────────────────────

def build_checkin_request(fingerprint, locale="en-US", timezone_str="America/New_York", device_sn="", imei=""):
    parsed = parse_fingerprint(fingerprint)
    device = parsed["device"]

    build  = b""
    build += encode_string(1, fingerprint)
    build += encode_int64(7, 0)
    build += encode_string(9, device)

    checkin  = b""
    tag      = (1 << 3) | 2
    checkin += encode_varint(tag) + encode_varint(len(build)) + build
    checkin += encode_int64(2, 0)
    checkin += encode_string(8, "WIFI::")
    checkin += encode_int64(9, 0)
    checkin += encode_int64(12, 0)
    checkin += encode_int64(14, 2)
    checkin += encode_bool(18, False)
    checkin += encode_string(19, "WIFI")

    request  = b""
    if imei:
        request += encode_string(1, imei)
    tag       = (4 << 3) | 2
    request  += encode_varint(tag) + encode_varint(len(checkin)) + checkin
    request  += encode_int64(2, 0)
    request  += encode_string(3, "1-0000000000000000000000000000000000000000")
    request  += encode_string(6, locale)
    if imei:
        request += encode_string(10, imei)
    request  += encode_string(12, timezone_str)
    request  += encode_int64(14, 3)
    if device_sn:
        request += encode_string(16, device_sn)
    request  += encode_int64(20, 0)
    request  += encode_int64(22, 0)

    return request


# ─────────────────────────────────────────────────────────────────────────────
#  Protobuf response parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_protobuf_response(data):
    settings = {}
    offset   = 0

    while offset < len(data):
        tag, offset   = decode_varint(data, offset)
        field_number  = tag >> 3
        wire_type     = tag & 0x07

        if field_number == 5 and wire_type == 2:
            length, offset = decode_varint(data, offset)
            end  = offset + length
            name = None
            value = None

            while offset < end:
                inner_tag, offset  = decode_varint(data, offset)
                inner_field        = inner_tag >> 3
                inner_wire         = inner_tag & 0x07

                if inner_wire == 2:
                    str_len, offset = decode_varint(data, offset)
                    if inner_field == 1:
                        name,  offset = decode_string(data, offset, str_len)
                    elif inner_field == 2:
                        value, offset = decode_string(data, offset, str_len)
                else:
                    offset += 1

            if name and value:
                settings[name] = value
        else:
            if wire_type == 0:
                _, offset = decode_varint(data, offset)
            elif wire_type == 2:
                length, offset = decode_varint(data, offset)
                offset += length
            elif wire_type == 5:
                offset += 4
            elif wire_type == 1:
                offset += 8

    return settings


def find_ota_link(settings):
    if "update_url" not in settings:
        return None
    return {
        "url":         settings["update_url"],
        "title":       settings.get("update_title", ""),
        "description": settings.get("update_description", ""),
        "size":        settings.get("update_size", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Checkin performer
# ─────────────────────────────────────────────────────────────────────────────

def perform_checkin(fingerprint, device_sn="", url=None):
    parsed       = parse_fingerprint(fingerprint)
    request_data = build_checkin_request(fingerprint, device_sn=device_sn)
    compressed   = gzip.compress(request_data)

    url    = (url or CHECKIN_URL).strip()
    device = parsed["device"]
    version = parsed["api_level"]
    build  = parsed["build_tag"]

    headers = {
        "Accept-Encoding": "gzip, deflate",
        "Content-Encoding": "gzip",
        "Content-Type":    "application/x-protobuffer",
        "User-Agent":      f"Dalvik/2.1.0 (Linux; U; Android {version}; {device} Build/{build})",
    }

    req = urllib.request.Request(url, data=compressed, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as response:
        response_data = response.read()
        try:
            response_data = gzip.decompress(response_data)
        except Exception:
            pass
        settings = parse_protobuf_response(response_data)
        return settings


# ─────────────────────────────────────────────────────────────────────────────
#  Archived URL helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_archived_urls(path=ARCHIVED_FILE):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def save_archived_url(url, path=ARCHIVED_FILE):
    with open(path, "a", encoding="utf-8") as f:
        f.write(url + "\n")


# ─────────────────────────────────────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────────────────────────────────────

def log(message, also_print=True):
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{ts}] {message}"
    if also_print:
        print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def format_finding(ota):
    lines = [
        f"URL: {ota['url']}",
    ]
    if ota.get("title"):
        lines.append(f"Title: {ota['title']}")
    if ota.get("description"):
        lines.append(f"Description: {ota['description']}")
    if ota.get("size"):
        lines.append(f"Size: {ota['size']}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Discord notifier
# ─────────────────────────────────────────────────────────────────────────────

def send_discord(findings):
    """
    findings: list of OTA dicts that were found new this run.
    Sends a single message per run with all new findings.
    """
    if not DISCORD_WEBHOOK:
        log("[Discord] DISCORD_WEBHOOK not set, skipping notification.")
        return

    if not findings:
        return

    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    count = len(findings)

    body_parts = []
    for ota in findings:
        body_parts.append(format_finding(ota))

    body = "\n\n".join(body_parts)
    if len(body) > 1900:
        body = body[:1900] + "\n...(truncated)"

    content = f"**New Sorrel OTA ({count} update{'s' if count > 1 else ''}) — {ts}**\n```\n{body}\n```"

    payload = {"content": content}

    webhook_url = DISCORD_WEBHOOK.strip()
    log(f"[Discord] Webhook URL length: {len(webhook_url)}")
    log(f"[Discord] Webhook starts with: {webhook_url[:50]}")

    try:
        data    = json.dumps(payload).encode("utf-8")
        req     = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            log(f"[Discord] Notification sent (HTTP {resp.status}).")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        log(f"[Discord] Failed to send notification: {e} — Response: {body}")
    except Exception as e:
        log(f"[Discord] Failed to send notification: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  Main sorrel run
# ─────────────────────────────────────────────────────────────────────────────

def run_sorrel():
    log("=" * 60)
    log("Sorrel OTA checker started.")

    # Load serial numbers
    if not os.path.exists(SERIALS_FILE):
        log(f"[ERROR] {SERIALS_FILE} not found. Aborting.")
        sys.exit(1)

    with open(SERIALS_FILE, "r", encoding="utf-8") as f:
        serials = [line.strip() for line in f if line.strip()]

    log(f"Loaded {len(serials)} serial number(s) from {SERIALS_FILE}.")

    archived_urls = load_archived_urls()
    log(f"Loaded {len(archived_urls)} archived URL(s) from {ARCHIVED_FILE}.")

    new_findings = []

    for idx, serial in enumerate(serials, 1):
        log(f"[{idx}/{len(serials)}] Checking serial: {serial}")

        try:
            settings = perform_checkin(SORREL_FINGERPRINT, device_sn=serial)
            ota      = find_ota_link(settings)

            if ota and ota["url"]:
                url = ota["url"]
                if url not in archived_urls:
                    log(f"  *** NEW URL FOUND ***")
                    finding_text = format_finding(ota)
                    for line in finding_text.splitlines():
                        log(f"  {line}")
                    log("")  # blank line separator

                    new_findings.append(ota)
                    archived_urls.add(url)
                    save_archived_url(url)
                else:
                    log(f"  URL already archived, skipping.")
            else:
                log(f"  No OTA update found.")

        except Exception as e:
            log(f"  [ERROR] {e}")

        if idx < len(serials):
            time.sleep(REQUEST_DELAY_SEC)

    log(f"Run complete. {len(new_findings)} new finding(s) this run.")
    log("=" * 60)

    if new_findings:
        send_discord(new_findings)


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OTA Prober")
    parser.add_argument(
        "--sorrel",
        action="store_true",
        help="Run sorrel OTA checker using serials from serials.txt",
    )
    args, _ = parser.parse_known_args()

    if args.sorrel:
        run_sorrel()
    else:
        print("No mode specified. Use --sorrel to run the sorrel OTA checker.")
        print("Example: python sorrel_checker.py --sorrel")
        sys.exit(0)


if __name__ == "__main__":
    main()
