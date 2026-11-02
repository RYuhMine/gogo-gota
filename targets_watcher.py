#!/usr/bin/env python3
"""
Fuchsia targets watcher.

Every run it downloads targets.json of the Fuchsia update repository. If the file CHANGED since the last
run, it reads the build ID / incremental (e.g. ZP1A.261007.002/16538212) from the build-info and update
packages, posts a message to one or two Discord webhooks, and records this targets file so the same
targets is never reported twice.

Only the Python standard library is used. Webhook URLs come from environment variables (never stored in files):
    DISCORD_WEBHOOK     first webhook   (optional)
    DISCORD_WEBHOOK_2   second webhook  (optional)

Usage:
    python targets_watcher.py                 normal run (what GitHub Actions executes)
    python targets_watcher.py --dry-run       show what would be sent, change nothing
    python targets_watcher.py --test-webhook  send a test message to the configured webhooks
    python targets_watcher.py --force         re-send the message for the current targets
"""
import argparse, hashlib, json, os, re, struct, sys, time
import urllib.request, urllib.error
from datetime import datetime, timezone

REPO_HOST = os.environ.get("FUCHSIA_REPO_HOST") or "8wfkwlaymr5vljmon1vczjlm3.fuchsia-updates.googleusercontent.com"
BLOB_HOST = os.environ.get("FUCHSIA_BLOB_HOST") or "fuchsia-blobs.googleusercontent.com"
WEBHOOKS = [("1", "DISCORD_WEBHOOK"), ("2", "DISCORD_WEBHOOK_2")]

STATE_FILE = "state.json"
LAST_TARGETS_FILE = "last_targets.json"
HISTORY_FILE = "history.jsonl"
HISTORY_DIR = "targets_history"

FAIL_ALERT_AFTER = int(os.environ.get("FAIL_ALERT_AFTER") or 6)       # consecutive failed checks before an alert
INFO_RETRIES = int(os.environ.get("INFO_RETRIES") or 3)               # checks to wait for build info to appear
NOTIFY_ONLY_BUILD_CHANGE = os.environ.get("NOTIFY_ONLY_BUILD_CHANGE", "0") == "1"
NOTIFY_ON_FIRST_RUN = os.environ.get("NOTIFY_ON_FIRST_RUN", "1") == "1"
SAVE_TARGETS_HISTORY = os.environ.get("SAVE_TARGETS_HISTORY", "0") == "1"

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 targets-watcher/1.0"
FAR_MAGIC = bytes([0xC8, 0xBF, 0x0B, 0x48, 0xAD, 0xAB, 0xC5, 0x11])
LOCAL = None          # test hook: directory with fixture files
OUT = "."             # directory for state files


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    print(f"[{now()}] {msg}", flush=True)


def path(name):
    return os.path.join(OUT, name)


# ---------------------------------------------------------------- network
def http_get(url, timeout=30, retries=3):
    if LOCAL:
        p = os.path.join(LOCAL, url.rsplit("/", 1)[-1])
        if not os.path.exists(p):
            raise FileNotFoundError(url.rsplit("/", 1)[-1])
        return open(p, "rb").read()
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (400, 401, 403, 404, 410):
                break
        except Exception as e:
            last = e
        time.sleep(2 * (i + 1))
    raise last


def parse_far(d):
    if d[:8] != FAR_MAGIC:
        raise ValueError("not a FAR archive")
    il = struct.unpack_from("<Q", d, 8)[0]
    pos, ch = 16, {}
    while pos < 16 + il:
        o, l = struct.unpack_from("<QQ", d, pos + 8)
        ch[d[pos:pos + 8]] = (o, l)
        pos += 24
    do, dl = ch[b"DIR-----"]
    no, nl = ch[b"DIRNAMES"]
    names, out = d[no:no + nl], {}
    for i in range(dl // 32):
        a, b = struct.unpack_from("<IH", d, do + i * 32)
        c, e = struct.unpack_from("<QQ", d, do + i * 32 + 8)
        out[names[a:a + b].decode()] = d[c:c + e]
    return out


# ---------------------------------------------------------------- state
def load_json(name, default):
    try:
        with open(path(name), encoding="utf8") as f:
            return json.load(f)
    except Exception:
        return default


def save_bytes(name, data):
    os.makedirs(os.path.dirname(path(name)) or ".", exist_ok=True)
    tmp = path(name) + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path(name))


def save_json(name, obj):
    save_bytes(name, (json.dumps(obj, indent=1, ensure_ascii=False) + "\n").encode("utf8"))


# ---------------------------------------------------------------- build info
def target_merkle(targets, key):
    return targets.get(key, {}).get("custom", {}).get("merkle")


def collect_info(targets):
    """Reads build ID / incremental etc. Returns a dict; info['complete'] tells whether the build was identified."""
    info = {"update_merkle": target_merkle(targets, "update/0"),
            "build_info_merkle": target_merkle(targets, "build-info/0"), "errors": []}
    inline, update_version = {}, None
    if info["build_info_merkle"]:
        try:
            far = parse_far(http_get(f"https://{BLOB_HOST}/{info['build_info_merkle']}"))
            for k, v in far.items():
                if k.startswith("meta/fuchsia.domain_config/data/"):
                    inline[k.rsplit("/", 1)[-1]] = v.decode("utf8", "replace").strip()
        except Exception as e:
            info["errors"].append(f"build-info: {str(e)[:80]}")
    if info["update_merkle"]:
        try:
            far = parse_far(http_get(f"https://{BLOB_HOST}/{info['update_merkle']}"))
            contents = dict(l.split("=", 1) for l in far["meta/contents"].decode().splitlines() if "=" in l)
            if "version" in contents:
                update_version = http_get(f"https://{BLOB_HOST}/{contents['version']}").decode("utf8", "replace").strip()
        except Exception as e:
            info["errors"].append(f"update/0: {str(e)[:80]}")
    pv = inline.get("product_version") or update_version
    info.update({"product_version": pv, "update_version": update_version,
                 "product": inline.get("product"), "board": inline.get("board"),
                 "platform_version": inline.get("platform_version"),
                 "commit_date": inline.get("latest-commit-date")})
    m = re.match(r"^(.+?)/(\d+)$", pv or "")
    info["build_id"], info["incremental"] = (m.group(1), m.group(2)) if m else (None, None)
    info["complete"] = bool(pv)
    return info


def diff_targets(old, new):
    """old/new: {package: merkle}. -> dict of changed/added/removed names."""
    old, new = old or {}, new or {}
    return {"changed": sorted(k for k in new if k in old and old[k] != new[k]),
            "added": sorted(k for k in new if k not in old),
            "removed": sorted(k for k in old if k not in new)}


def merkle_map(targets):
    return {k: v.get("custom", {}).get("merkle") for k, v in targets.items()}


# ---------------------------------------------------------------- Discord
def short_list(names, limit=12):
    if not names:
        return "-"
    s = ", ".join(names[:limit])
    return s + (f" ... (+{len(names) - limit} more)" if len(names) > limit else "")


def build_payload(rec, kind="update"):
    info = rec["info"]
    build = info.get("product_version") or "unknown build"
    prev = rec.get("prev_build")
    changed_build = bool(prev) and prev != build
    d = rec.get("diff") or {"changed": [], "added": [], "removed": []}
    if kind == "first":
        head, color = "Watcher started - current build", 0x95a5a6
    elif not info.get("product_version"):
        head, color = "Targets changed (build not identified)", 0xe67e22
    elif changed_build or not prev:
        head, color = "New build", 0x2ecc71
    else:
        head, color = "Targets changed (same build)", 0x3498db
    f = lambda n, v, inline=True: {"name": n, "value": (str(v) if v else "-")[:1000], "inline": inline}
    fields = [f("Build ID", info.get("build_id") or "-"), f("Incremental", info.get("incremental") or "-"),
              f("Product", info.get("product")), f("Board", info.get("board")),
              f("Platform version", info.get("platform_version")), f("Commit date", info.get("commit_date")),
              f("Targets version", f"{rec.get('version')}" + (f" (was {rec['prev_version']})" if rec.get("prev_version") else "")),
              f("update/0", f"`{info.get('update_merkle')}`" if info.get("update_merkle") else "-", False)]
    if prev:
        fields.append(f("Previous build", prev, False))
    if info.get("update_version") and info["update_version"] != info.get("product_version"):
        fields.append(f("update/version differs", info["update_version"], False))
    if d["changed"] or d["added"] or d["removed"]:
        fields.append(f(f"Changed packages ({len(d['changed'])})", short_list(d["changed"]), False))
        if d["added"]:
            fields.append(f(f"Added ({len(d['added'])})", short_list(d["added"]), False))
        if d["removed"]:
            fields.append(f(f"Removed ({len(d['removed'])})", short_list(d["removed"]), False))
    return {"content": f"**{head}: {build}**",
            "embeds": [{"title": f"{head}: {build}", "color": color, "fields": fields[:25],
                        "timestamp": rec.get("detected"), "footer": {"text": REPO_HOST[:100]}}]}


def configured_webhooks():
    return [(label, os.environ[env].strip()) for label, env in WEBHOOKS if os.environ.get(env, "").strip()]


def send_webhook(url, payload):
    """-> (ok, detail). The URL is never printed."""
    data = json.dumps(payload).encode("utf8")
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/json", "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as r:
                return True, f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf8", "replace")[:200]
            if e.code == 429:
                try:
                    wait = float(json.loads(body).get("retry_after", 2))
                except Exception:
                    wait = 2
                time.sleep(min(wait, 10) + 0.5)
                continue
            if e.code >= 500 and attempt < 2:
                time.sleep(2)
                continue
            return False, f"HTTP {e.code} {body}"
        except Exception as e:
            if attempt < 2:
                time.sleep(2)
                continue
            return False, str(e)[:120]
    return False, "rate limited"


def deliver(rec, state, kind="update", dry=False):
    """Sends rec to every webhook that has not received it yet. Saves progress after each success."""
    hooks = dict(configured_webhooks())
    pending = [l for l, done in state.get("notified", {}).items() if not done and l in hooks]
    if not pending:
        return
    payload = build_payload(rec, kind)
    for label in pending:
        if dry:
            print(f"--- would send to webhook {label}:\n{json.dumps(payload, indent=1, ensure_ascii=False)}")
            continue
        ok, detail = send_webhook(hooks[label], payload)
        log(f"webhook {label}: {'sent' if ok else 'FAILED'} ({detail})")
        if ok:
            state["notified"][label] = True
            save_json(STATE_FILE, state)


def broadcast_text(text, color=0xe74c3c):
    for label, url in configured_webhooks():
        ok, detail = send_webhook(url, {"content": text, "embeds": [{"description": text, "color": color}]})
        log(f"webhook {label}: {'sent' if ok else 'FAILED'} ({detail})")


# ---------------------------------------------------------------- main logic
def run(dry=False, force=False):
    state = load_json(STATE_FILE, {})
    try:
        raw = http_get(f"https://{REPO_HOST}/targets.json")
        targets_doc = json.loads(raw)
        targets = targets_doc["signed"]["targets"]
        version = targets_doc["signed"].get("version")
    except Exception as e:
        state["fail_count"] = state.get("fail_count", 0) + 1
        log(f"cannot fetch targets.json ({state['fail_count']} in a row): {e}")
        if state["fail_count"] >= FAIL_ALERT_AFTER and not state.get("fail_alerted") and not dry:
            broadcast_text(f"Fuchsia targets.json has been unreachable for {state['fail_count']} checks in a row: "
                           f"{str(e)[:150]}")
            state["fail_alerted"] = True
        if not dry:
            save_json(STATE_FILE, state)
        return 0
    if state.get("fail_alerted") and not dry:
        broadcast_text("Fuchsia targets.json is reachable again.", 0x2ecc71)
    state["fail_count"], state["fail_alerted"] = 0, False

    sha = hashlib.sha256(raw).hexdigest()
    if sha == state.get("sha256") and not force:
        if state.get("notified") and not all(state["notified"].get(l, True) for l, _ in configured_webhooks()
                                              if l in state["notified"]):
            log("same targets as before, retrying webhooks that did not receive it")
            if state.get("record"):
                deliver(state["record"], state, state["record"].get("kind", "update"), dry)
        else:
            log(f"targets unchanged (version {version}, sha256 {sha[:12]}) - nothing to do")
        if not dry:
            save_json(STATE_FILE, state)
        return 0

    if sha == state.get("sha256") and force and state.get("record"):
        rec = state["record"]
        state["notified"] = {l: False for l, _ in configured_webhooks()}
        log("--force: re-sending the message for the current targets")
        deliver(rec, state, rec.get("kind", "update"), dry)
        if not dry:
            save_json(STATE_FILE, state)
        return 0

    log(f"targets CHANGED: version {state.get('version')} -> {version}, sha256 {sha[:12]}")
    info = collect_info(targets)
    att = state.get("attempts", {})
    n = att.get("n", 0) + 1 if att.get("sha") == sha else 1
    if not info["complete"] and n < INFO_RETRIES:
        log(f"build info not available yet ({'; '.join(info['errors']) or 'no version'}); attempt {n}/{INFO_RETRIES}, will retry")
        state["attempts"] = {"sha": sha, "n": n}
        if not dry:
            save_json(STATE_FILE, state)
        return 0
    if not info["complete"]:
        log("build info still unavailable, reporting without it")

    old_doc = load_json(LAST_TARGETS_FILE, None)
    old_targets = (old_doc or {}).get("signed", {}).get("targets")
    first = old_doc is None and not state.get("sha256")
    rec = {"version": version, "sha256": sha, "detected": now(), "info": info,
           "prev_version": state.get("version"), "prev_build": (state.get("record") or {}).get("info", {}).get("product_version"),
           "diff": None if first else diff_targets(merkle_map(old_targets), merkle_map(targets)),
           "kind": "first" if first else "update"}
    build = info.get("product_version")
    silent = (first and not NOTIFY_ON_FIRST_RUN) or \
             (NOTIFY_ONLY_BUILD_CHANGE and not first and build and build == rec["prev_build"])
    hooks = configured_webhooks()
    if not hooks:
        log("WARNING: no webhook configured (DISCORD_WEBHOOK / DISCORD_WEBHOOK_2); the change is only recorded")
    log(f"build: {build or 'unknown'}  | incremental {info.get('incremental')}  | "
        f"changed packages: {len((rec['diff'] or {}).get('changed', []))}")

    new_state = {"sha256": sha, "version": version, "updated": now(), "record": rec,
                 "notified": {} if silent else {l: False for l, _ in hooks}}
    if dry:
        state = new_state
        deliver(rec, state, rec["kind"], dry=True)
        log("dry run: nothing was written")
        return 0
    save_bytes(LAST_TARGETS_FILE, raw)                      # record this targets
    if SAVE_TARGETS_HISTORY:
        save_bytes(f"{HISTORY_DIR}/{version}.targets.json", raw)
    with open(path(HISTORY_FILE), "a", encoding="utf8") as h:
        h.write(json.dumps({"time": rec["detected"], "version": version, "sha256": sha, "build": build,
                            "update_0": info.get("update_merkle")}) + "\n")
    new_state.update({"fail_count": 0, "fail_alerted": False})
    save_json(STATE_FILE, new_state)                        # state first: even if sending fails, no duplicates
    deliver(rec, new_state, rec["kind"])
    save_json(STATE_FILE, new_state)
    return 0


def main():
    global LOCAL, OUT
    ap = argparse.ArgumentParser(description="Fuchsia targets watcher")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true", help="re-send the message for the current targets")
    ap.add_argument("--test-webhook", action="store_true")
    ap.add_argument("--dir", default=".", help="where state files are stored (default: current directory)")
    ap.add_argument("--local", help=argparse.SUPPRESS)
    a = ap.parse_args()
    LOCAL, OUT = a.local, a.dir
    if a.test_webhook:
        if not configured_webhooks():
            sys.exit("No webhook configured. Set DISCORD_WEBHOOK (and optionally DISCORD_WEBHOOK_2).")
        broadcast_text("Test message from targets-watcher: webhook works.", 0x2ecc71)
        return
    sys.exit(run(dry=a.dry_run, force=a.force))


if __name__ == "__main__":
    main()
