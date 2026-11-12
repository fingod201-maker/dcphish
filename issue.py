#!/usr/bin/env python3
"""Issue Microsoft device codes and mail them through SendGrid.

REALITY NOTE — roadtx 1.22.1 flags, captured from the live binaries:
  `roadtx device -h` is the DEVICE REGISTRATION command
      (-a {join,register,delete}, -c, -k, -n, -d, --access-token, ...).
  Device-code generation therefore uses `roadtx gettokens --device-code`
      (-c/--client, -t/--tenant, -s/--scope, -f/--tokenfile).
  `roadtx prt -h` uses -r/--refresh-token, -f/--prt-file, -c/--cert-pem,
      -k/--key-pem (no -o).
  `roadtx mailboxsearch` does not exist in this release, so poll.py queries
      Microsoft Graph /me/messages directly with the acquired access token.
  The device-code prompt printed by roadtx is the Microsoft message: "... enter
  the code XXXXXXXXX to authenticate." The regex below is unchanged from the
  spec and matches it.
"""

import argparse
import atexit
import csv
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time

import requests
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))

import db  # noqa: E402

CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "1b730954-1686-4b9f-9bfd-dac224a7b894",
    "1950a258-227b-4e31-a9cf-717495945fc2",
]
SCOPE = (
    "openid profile offline_access https://graph.microsoft.com/Mail.ReadWrite "
    "https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/Files.ReadWrite"
)
SG_KEY = os.environ.get("SENDGRID_KEY", "")
FROM_ADDR = os.environ.get("FROM_ADDR", "")
FROM_NAME = os.environ.get("FROM_NAME", "Accounts")
RATE = int(os.environ.get("RATE_PER_MIN", "10"))
CAP = int(os.environ.get("DAILY_CAP", "200"))
R_CANDIDATE = os.path.join(os.path.dirname(sys.executable), "roadtx.exe" if os.name == "nt" else "roadtx")
ROADTX = R_CANDIDATE if os.path.exists(R_CANDIDATE) else (shutil.which("roadtx") or "roadtx")
CODE_RE = re.compile(r"enter the code\s+([A-Z0-9]{9})", re.IGNORECASE)
BAD_CLIENT = re.compile(r"invalid_client|AADSTS700016|Application with identifier", re.IGNORECASE)

children = []
atexit.register(lambda: [p.kill() for p in children if p.poll() is None])


class Bucket:
    def __init__(self, per_min):
        self.capacity = max(1, per_min)
        self.tokens = float(self.capacity)
        self.rate = per_min / 60.0
        self.ts = time.time()
        self.lock = threading.Lock()

    def take(self):
        while True:
            with self.lock:
                now = time.time()
                self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
                self.ts = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                wait = (1 - self.tokens) / self.rate
            time.sleep(wait)


def drain(proc):
    def run():
        for _ in proc.stdout:
            pass
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def get_code(uid, client_idx):
    """Spawn roadtx, wait <=20s for a code. Returns (code, proc, client_idx)."""
    path = os.path.join(HERE, "tokens", f"{uid}.json")
    attempts = 0
    while attempts < 4:
        attempts += 1
        client = CLIENT_IDS[client_idx]
        cmd = [
            ROADTX, "gettokens", "--device-code", "-c", client, "-t", "organizations",
            "-s", SCOPE, "-f", path,
        ]
        print(f"  client {client}")
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=HERE,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        children.append(proc)
        deadline = time.time() + 20
        seen = []
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            seen.append(line)
            print(f"  roadtx: {line.strip()[:200]}")
            m = CODE_RE.search(line)
            if m:
                return m.group(1).upper(), proc, client_idx
            if BAD_CLIENT.search(line):
                print(f"  invalid_client on {client} — rotating")
                proc.kill()
                client_idx = (client_idx + 1) % len(CLIENT_IDS)
                break
        else:
            print(f"  code not seen within 20s on {client}")
        if proc.poll() is None:
            proc.kill()
        if seen and not any(BAD_CLIENT.search(l) for l in seen) and not any(CODE_RE.search(l) for l in seen):
            return None, proc, client_idx


def render(template, code, sender, company):
    raw = open(os.path.join(HERE, "templates", template), encoding="utf-8").read()
    subject, body = raw.split("\n---\n", 1)
    subject = subject.replace("Subject: ", "", 1)
    n = f"{random.randint(0, 9999):04d}"
    vals = {"{{code}}": code, "{{n}}": n, "{{sender}}": sender, "{{company}}": company}
    for k, v in vals.items():
        subject = subject.replace(k, v)
        body = body.replace(k, v)
    return subject.strip(), body


def send(to, subject, body):
    payload = {
        "personalizations": [{"to": [{"email": to}]}],
        "from": {"email": FROM_ADDR, "name": FROM_NAME},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
        "tracking_settings": {
            "click_tracking": {"enable": False},
            "open_tracking": {"enable": False},
            "ganalytics": {"enable": False},
        },
        "mail_settings": {"sandbox_mode": {"enable": False}},
    }
    for attempt in range(3):
        r = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {SG_KEY}", "Content-Type": "application/json"},
            json=payload, timeout=30,
        )
        print(f"  SendGrid HTTP {r.status_code}")
        if r.status_code in (200, 201, 202):
            return True, r.status_code, ""
        if r.status_code == 429 and attempt < 2:
            print("  429 — sleeping 60s")
            time.sleep(60)
            continue
        return False, r.status_code, r.text[:300]
    return False, 0, "rate limit retries exhausted"


def load_rows(args):
    rows = []
    if args.input:
        with open(args.input, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("email"):
                    rows.append((row.get("domain", ""), row["email"].strip().lower()))
    for e in [x.strip().lower() for x in (args.to or "").split(",") if x.strip()]:
        rows.append((e.split("@")[-1], e))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="input", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--variant", choices=["a", "b", "ab"], default="a")
    ap.add_argument("--to", default="", help="extra comma-separated self-test addresses")
    args = ap.parse_args()
    if not SG_KEY or not FROM_ADDR:
        print("SENDGRID_KEY and FROM_ADDR must be set")
        return 1

    os.makedirs(os.path.join(HERE, "tokens"), exist_ok=True)
    os.makedirs(os.path.join(HERE, "prt"), exist_ok=True)
    db.init_db()
    bucket = Bucket(RATE)
    company = os.environ.get("DOMAIN", "")
    sender = FROM_NAME

    rows = load_rows(args)
    sent_count = 0
    client_idx = 0
    variants = 0
    for domain, email in rows:
        if args.limit and sent_count >= args.limit:
            break
        if db.is_sent(email):
            print(f"- skip {email} (already sent)")
            continue
        if db.sent_today() >= CAP:
            print(f"daily cap {CAP} reached")
            break
        bucket.take()
        uid = __import__("uuid").uuid4().hex
        print(f"+ {email} ({uid})")
        code, proc, client_idx = get_code(uid, client_idx)
        if not code:
            db.add_fail(email, "CODEGEN_FAIL", "no device code within 20s", domain)
            print("  CODEGEN_FAIL")
            continue
        drain(proc)
        if args.variant == "ab":
            variant = "a" if variants % 2 == 0 else "b"
        else:
            variant = args.variant
        variants += 1
        template = "device_code.txt" if variant == "a" else "device_code_b.txt"
        subject, body = render(template, code, sender, company)
        ok, status, detail = send(email, subject, body)
        if ok:
            db.add_sent(domain, email, code, variant)
            sent_count += 1
            print(f"  issued {code} variant={variant}")
        else:
            db.add_fail(email, "SEND_FAIL", f"{status} {detail}", domain)
            print(f"  SEND_FAIL {status} {detail[:120]}")
    print(f"done: {sent_count} sent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
