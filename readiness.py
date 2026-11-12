#!/usr/bin/env python3
"""Pre-flight gate. Exits non-zero unless every check passes."""

import os
import re
import shutil
import stat
import subprocess
import sys
import time

import dns.resolver
import requests
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))

from dns_setup import check_cname, check_txt, DOMAIN, LINK_DOMAIN, VM_IP, is_cf, resolves  # noqa: E402

TOKEN = os.environ.get("CF_API_TOKEN", "")
ZONE_ID = os.environ.get("CF_ZONE_ID", "")
SENDGRID = os.environ.get("SENDGRID_KEY", "")
TG_TOKEN = os.environ.get("TG_TOKEN", "")
TG_CHAT = os.environ.get("TG_CHAT", "")
CLIENT_ID = os.environ.get("CLIENT_ID", "d3590ed6-52b3-4102-aeff-aad2292ab01c")
SCOPE = (
    "openid profile offline_access https://graph.microsoft.com/Mail.ReadWrite "
    "https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/Files.ReadWrite"
)

R_CANDIDATE = os.path.join(os.path.dirname(sys.executable), "roadtx.exe" if os.name == "nt" else "roadtx")
ROADTX = R_CANDIDATE if os.path.exists(R_CANDIDATE) else (shutil.which("roadtx") or "roadtx")

results = []


def record(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def check_sendgrid():
    if not SENDGRID:
        return False, "SENDGRID_KEY empty"
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/whitelabel/domains",
            headers={"Authorization": f"Bearer {SENDGRID}"},
            timeout=20,
        )
        print(f"  HTTP {r.status_code} GET /v3/whitelabel/domains")
        if r.status_code != 200:
            return False, r.text[:120]
        for d in r.json():
            if d.get("domain") == DOMAIN:
                return bool(d.get("valid")), f"valid={d.get('valid')}"
        return False, "domain not in whitelabel list"
    except Exception as e:
        return False, str(e)[:120]


def check_dns():
    spf_ok, _ = check_txt(DOMAIN, "v=spf1 include:sendgrid.net -all")
    dmarc_ok, _ = check_txt(f"_dmarc.{DOMAIN}", "v=DMARC1")
    d1, det1 = check_cname(f"s1._domainkey.{DOMAIN}")
    d2, det2 = check_cname(f"s2._domainkey.{DOMAIN}")
    records = []
    try:
        for line in __import__("dns_setup").existing_records() or []:
            if line["type"] == "CNAME" and line["name"].startswith("em"):
                records.append(line["name"])
    except Exception:
        pass
    em_ok = True
    for em in records:
        ok, det = check_cname(em)
        em_ok = em_ok and ok
    link_ips = resolves(LINK_DOMAIN, "A")
    link_ok = bool(VM_IP) and VM_IP in link_ips and not any(is_cf(i) for i in link_ips)
    return spf_ok and dmarc_ok and d1 and d2 and em_ok and link_ok, (
        f"spf={spf_ok} dmarc={dmarc_ok} dkim={d1 and d2} link={link_ok}"
    )


def check_telegram():
    if not TG_TOKEN:
        return False, "TG_TOKEN empty"
    try:
        import notify

        chat = notify.resolve_chat()
        r = requests.get(f"https://api.telegram.org/bot{TG_TOKEN}/getMe", timeout=20)
        print(f"  HTTP {r.status_code} getMe")
        if r.status_code != 200 or not r.json().get("ok"):
            return False, r.text[:120]
        if not chat:
            return False, "no chat id (send /start to the bot)"
        s = requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            data={"chat_id": chat, "text": "dcphish readiness ping", "disable_web_page_preview": True},
            timeout=20,
        )
        print(f"  HTTP {s.status_code} sendMessage")
        return s.status_code == 200 and s.json().get("ok", False), ""
    except Exception as e:
        return False, str(e)[:120]


def check_dirs():
    ok = True
    for d in ("tokens", "prt"):
        path = os.path.join(HERE, d)
        os.makedirs(path, exist_ok=True)
        try:
            os.chmod(path, 0o600 if os.name != "nt" else stat.S_IREAD | stat.S_IWRITE)
        except OSError:
            pass
        if os.name != "nt":
            ok = ok and (stat.S_IMODE(os.stat(path).st_mode) == 0o600)
        ok = ok and os.path.isdir(path) and os.access(path, os.W_OK)
    return ok, "tokens/ prt/"


def check_disk():
    free = shutil.disk_usage(HERE).free
    return free > 5 * 1024 ** 3, f"{free / 1024 ** 3:.1f} GB free"


def check_roadtx():
    try:
        p = subprocess.run([ROADTX, "device", "-h"], capture_output=True, text=True, timeout=60)
        return p.returncode == 0, ROADTX
    except Exception as e:
        return False, str(e)[:120]


def check_device_code():
    cmd = [
        ROADTX, "gettokens", "--device-code", "-c", CLIENT_ID, "-t", "organizations",
        "-s", SCOPE, "-f", os.path.join(HERE, "tokens", "_readiness.json"),
    ]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env={**os.environ, "PYTHONUNBUFFERED": "1"})
    except Exception as e:
        return False, str(e)[:120]
    deadline = time.time() + 25
    code = None
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            if p.poll() is not None:
                break
            continue
        print(f"  roadtx: {line.strip()[:160]}")
        m = re.search(r"enter the code\s+([A-Za-z0-9]{9})", line)
        if m:
            code = m.group(1)
            break
    p.kill()
    try:
        os.remove(os.path.join(HERE, "tokens", "_readiness.json"))
    except OSError:
        pass
    return bool(code), f"code={code or 'none'}"


def main():
    print("== readiness ==")
    record("SendGrid domain authenticated", *check_sendgrid())
    record("SPF/DKIM/DMARC + link not proxied", *check_dns())
    record("Telegram getMe + test send", *check_telegram())
    record("tokens/ prt/ mode 0600", *check_dirs())
    record("disk free > 5 GB", *check_disk())
    record("roadtx device -h exits 0", *check_roadtx())
    record("live device code generates", *check_device_code())
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("FAILED: " + ", ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
