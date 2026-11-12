#!/usr/bin/env python3
"""Cloudflare DNS setup/verification for SendGrid authentication and the lure link.

Idempotent. Every CNAME is created with "proxied": false, because a proxied
record returns Cloudflare anycast addresses instead of sendgrid.net.
"""

import argparse
import ipaddress
import os
import random
import sys
import time

import dns.resolver
import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

CF_API = "https://api.cloudflare.com/client/v4"
TOKEN = os.environ.get("CF_API_TOKEN", "")
ZONE_ID = os.environ.get("CF_ZONE_ID", "")
DOMAIN = os.environ.get("DOMAIN", "")
LINK_DOMAIN = os.environ.get("LINK_DOMAIN", "")
VM_IP = os.environ.get("VM_IP", "")
DKIM = os.environ.get("SENDGRID_DKIM", "")

CF_NETS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
    "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
    "131.0.72.0/22",
]
CF_NETWORKS = [ipaddress.ip_network(n) for n in CF_NETS]


def headers():
    return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def api(method, path, **kwargs):
    url = f"{CF_API}/zones/{ZONE_ID}/dns_records{path}"
    r = requests.request(method, url, headers=headers(), timeout=30, **kwargs)
    print(f"  HTTP {r.status_code} {method} dns_records{path}")
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code >= 400 or not body.get("success", False):
        print(f"  Cloudflare error: {body.get('errors') or r.text[:300]}")
        return None
    return body


def existing_records():
    if not TOKEN or not ZONE_ID:
        return []
    body = api("GET", "?per_page=200")
    return body.get("result", []) if body else []


def desired_records():
    em = f"em{random.randint(100000, 999999)}"
    dkim_target = (
        f"sendgrid.domainkey.{DKIM}.sendgrid.net" if DKIM else
        "sendgrid.domainkey.PLACEHOLDER.sendgrid.net"
    )
    return [
        {"type": "CNAME", "name": em, "content": "sendgrid.net", "proxied": False, "ttl": 1},
        {"type": "CNAME", "name": "s1._domainkey", "content": dkim_target, "proxied": False, "ttl": 1},
        {"type": "CNAME", "name": "s2._domainkey", "content": dkim_target, "proxied": False, "ttl": 1},
        {"type": "TXT", "name": "@", "content": "v=spf1 include:sendgrid.net -all", "proxied": False, "ttl": 1},
        {"type": "TXT", "name": "_dmarc", "content": f"v=DMARC1; p=none; rua=mailto:dmarc@{DOMAIN}; adkim=s; aspf=s", "proxied": False, "ttl": 1},
        {"type": "A", "name": LINK_DOMAIN, "content": VM_IP, "proxied": False, "ttl": 1},
    ]


def full_name(rec_name):
    if rec_name in ("@", DOMAIN) or rec_name.endswith("." + DOMAIN):
        return DOMAIN if rec_name == "@" else rec_name
    return f"{rec_name}.{DOMAIN}"


def apply():
    if not TOKEN or not ZONE_ID:
        print("CF_API_TOKEN and CF_ZONE_ID are required")
        return 1
    if not DKIM:
        print("WARNING: SENDGRID_DKIM is empty; DKIM CNAMEs point at PLACEHOLDER")
    have = existing_records()
    if have is None:
        return 1
    wanted = desired_records()
    # Re-use an em* CNAME if it already exists so re-running does not proliferate.
    for r in have:
        if r["type"] == "CNAME" and r["name"].startswith("em") and r["content"].rstrip(".") == "sendgrid.net":
            wanted[0]["name"] = r["name"].split(".")[0]
            break
    for rec in wanted:
        fqdn = full_name(rec["name"])
        match = next((h for h in have if h["type"] == rec["type"] and h["name"] == fqdn), None)
        if match:
            if match["content"].rstrip(".") == rec["content"].rstrip(".") and not match.get("proxied"):
                print(f"  ok   {rec['type']:5} {fqdn}")
                continue
            body = api("PATCH", f"/{match['id']}", json=rec)
            print(f"  fixed {rec['type']:5} {fqdn}" if body else f"  FAIL {rec['type']} {fqdn}")
            continue
        body = api("POST", "", json=rec)
        print(f"  made {rec['type']:5} {fqdn}" if body else f"  FAIL {rec['type']} {fqdn}")
    return 0


def resolves(name, rtype):
    try:
        return [str(a) for a in dns.resolver.resolve(name, rtype, lifetime=5)]
    except Exception:
        return []


def is_cf(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CF_NETWORKS)


def check_txt(name, must_start):
    vals = resolves(name, "TXT")
    joined = " ".join(v.strip('"') for v in vals)
    if joined.startswith(must_start):
        return True, joined[:80]
    return False, joined[:80] or "no TXT"


def check_cname(name):
    cnames = resolves(name, "CNAME")
    ips = resolves(name, "A")
    proxied = any(is_cf(ip) for ip in ips)
    if cnames and any("sendgrid.net" in c.rstrip(".") for c in cnames) and not proxied:
        return True, cnames[0]
    if proxied:
        return False, f"PROXIED -> {', '.join(ips)}"
    return False, f"cname={cnames or 'none'} a={ips or 'none'}"


def check():
    rows = []
    rows.append(("TXT @ SPF", *check_txt(DOMAIN, "v=spf1 include:sendgrid.net -all")))
    rows.append(("TXT _dmarc", *check_txt(f"_dmarc.{DOMAIN}", "v=DMARC1")))
    rows.append(("CNAME s1._domainkey", *check_cname(f"s1._domainkey.{DOMAIN}")))
    rows.append(("CNAME s2._domainkey", *check_cname(f"s2._domainkey.{DOMAIN}")))
    ems = []
    for rec in existing_records() or []:
        if rec["type"] == "CNAME" and rec["name"].startswith("em"):
            ems.append(rec["name"])
    if not ems:
        rows.append(("CNAME em*", False, "no em* CNAME found"))
    for em in ems:
        rows.append((f"CNAME {em}", *check_cname(em)))
    link_ips = resolves(LINK_DOMAIN, "A")
    rows.append((
        f"A {LINK_DOMAIN}",
        bool(VM_IP) and VM_IP in link_ips and not any(is_cf(i) for i in link_ips),
        ", ".join(link_ips) or "no A",
    ))

    print(f"\n{'RECORD':38} {'RESULT':6} DETAIL")
    print("-" * 78)
    ok = True
    for label, passed, detail in rows:
        ok = ok and passed
        print(f"{label:38} {'PASS' if passed else 'FAIL':6} {detail}")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--apply", action="store_true")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.apply:
        rc = apply()
        time.sleep(2)
        return rc
    return check()


if __name__ == "__main__":
    sys.exit(main())
