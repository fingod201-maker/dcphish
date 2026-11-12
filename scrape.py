#!/usr/bin/env python3
"""Domain -> verified business e-mail harvester.

Stages run strictly in order; every stage prints a funnel count and raises
loudly (naming the stage) if it would emit an empty set.
"""

import argparse
import csv
import io
import os
import random
import re
import smtplib
import socket
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import requests
import tldextract
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))

TLD = tldextract.TLDExtract(suffix_list_urls=())

NA_TLDS = (".com", ".us", ".ca")
EU_TLDS = (
    ".co.uk", ".de", ".fr", ".nl", ".be", ".ie", ".it", ".es", ".pl", ".se",
    ".dk", ".no", ".fi", ".at", ".ch", ".pt", ".cz", ".ro",
)
ANZ_TLDS = (".com.au", ".net.au", ".co.nz")
GEO_TLDS = {"na": NA_TLDS, "eu": EU_TLDS, "anz": ANZ_TLDS}
COUNTRIES = {
    "US", "CA", "GB", "IE", "DE", "FR", "NL", "BE", "AU", "NZ", "SE", "DK",
    "NO", "FI", "IT", "ES", "PL", "AT", "CH", "PT",
}
GUESSES = (
    "accounts", "ap", "invoices", "creditcontrol", "bookkeeping", "finance",
    "remittance",
)
VERTICALS_DEFAULT = (
    "logistic,freight,import,export,solicitor,conveyanc,estate,construction,"
    "recruit,shipping,trade,wholesale,distribut"
)
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}


def registrable(host):
    ext = TLD(host.lower().strip("."))
    if not ext.domain or not ext.suffix:
        return None
    return ext.top_domain_under_public_suffix or f"{ext.domain}.{ext.suffix}"


def stage(n, label, count, error=None):
    print(f"stage {n} {label}: {count}")
    if count == 0 and error is not None:
        raise SystemExit(f"STAGE {n} ({label}) produced zero rows: {error}")


def download_tranco():
    print("downloading tranco top-1m ...")
    r = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=120, headers=UA)
    print(f"  HTTP {r.status_code}")
    r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    name = next(n for n in zf.namelist() if n.endswith(".csv"))
    return zf.read(name).decode("utf-8", "replace")


def read_source(args):
    if args.source == "tranco":
        data = download_tranco()
    else:
        if not args.file:
            raise SystemExit("--source file requires --file")
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    domains, seen = [], set()
    for line in data.splitlines():
        cell = line.split(",")[-1].strip().lower()
        if not cell or cell.isdigit() or "rank" in cell:
            continue
        reg = registrable(cell)
        if reg and reg not in seen:
            seen.add(reg)
            domains.append(reg)
    return domains


def tld_gate(domains, geos):
    suffixes = []
    for g in geos:
        suffixes.extend(GEO_TLDS[g])
    out = []
    for d in domains:
        if d.endswith(".com"):
            out.append((d, True))
        elif any(d.endswith(s) for s in suffixes):
            out.append((d, False))
    return out


def mx_gate(domains, workers):
    def lookup(d):
        res = dns.resolver.Resolver()
        res.lifetime = 3
        res.timeout = 3
        for attempt in range(3):
            try:
                answers = res.resolve(d, "MX", lifetime=3)
                hosts = [str(a.exchange).rstrip(".").lower() for a in answers]
                if any(h.endswith("mail.protection.outlook.com") for h in hosts):
                    return d, hosts[0]
                return None
            except Exception:
                if attempt == 2:
                    return None
                time.sleep(0.5)
        return None

    out = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = [pool.submit(lookup, d) for d in domains]
        for i, fut in enumerate(as_completed(futs), 1):
            if i % 500 == 0:
                print(f"  mx {i}/{len(domains)}")
            r = fut.result()
            if r:
                out.append((r[0], r[1]))
    return out


def geo_confirm(pairs):
    kept = []
    batch = []
    for domain, mx in pairs:
        try:
            a = dns.resolver.resolve(domain, "A", lifetime=3)
            batch.append((domain, mx, str(next(iter(a)))))
        except Exception:
            continue
    for i in range(0, len(batch), 100):
        chunk = batch[i:i + 100]
        payload = [{"query": ip, "fields": "countryCode"} for _, _, ip in chunk]
        try:
            r = requests.post("http://ip-api.com/batch", json=payload, timeout=30, headers=UA)
            print(f"  ip-api HTTP {r.status_code} ({len(chunk)} IPs)")
            if r.status_code == 200:
                for (domain, mx, ip), geo in zip(chunk, r.json()):
                    if geo.get("countryCode") in COUNTRIES:
                        kept.append((domain, mx, "confirmed"))
        except Exception as e:
            print(f"  ip-api error: {e}")
        time.sleep(1.5)
    return kept


def vertical_gate(pairs, verticals):
    if not verticals:
        return pairs
    needles = [v.strip().lower() for v in verticals.split(",") if v.strip()]
    return [p for p in pairs if any(n in p[0] for n in needles)]


CF_HEX = re.compile(r'(?:data-cfemail="|/cdn-cgi/l/email-protection#)([0-9a-fA-F]+)')
MAILTO = re.compile(r'mailto:([^"\'?>\s]+)')


def decode_cf(hexstr):
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if not raw:
        return None
    key = raw[0]
    out = "".join(chr(b ^ key) for b in raw[1:])
    return out if "@" in out else None


def harvest_domains(domain, mx_host):
    found, guesses = [], []
    for path in ("", "/contact"):
        try:
            r = requests.get(f"https://{domain}{path}", timeout=15, headers=UA, verify=False)
            print(f"  {domain}{path or '/'} HTTP {r.status_code}")
            if r.status_code != 200:
                continue
            html = r.text
            for m in MAILTO.findall(html):
                e = m.strip().lower()
                if "@" in e and domain.split(".")[-2] in e:
                    found.append(e)
            for h in CF_HEX.findall(html):
                e = decode_cf(h)
                if e:
                    found.append(e.lower())
        except Exception as e:
            print(f"  {domain}{path or '/'} error: {str(e)[:80]}")
    found = list(dict.fromkeys(found))
    guesses = [f"{g}@{domain}" for g in GUESSES]

    verified = set()
    if mx_host:
        try:
            smtp = smtplib.SMTP(mx_host, 25, timeout=10)
            smtp.ehlo_or_helo_if_needed()
            smtp.mail(f"postmaster@{domain}")
            for e in list(dict.fromkeys(found + guesses)):
                code, _ = smtp.rcpt(e)
                if code in (250, 251):
                    verified.add(e)
            smtp.quit()
        except Exception as e:
            print(f"  smtp {mx_host}: port 25 unusable ({str(e)[:60]})")
    else:
        print("  smtp: no MX host")
    return found, guesses, verified


def existing_rows(path):
    seen = set()
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                seen.add((row.get("domain"), row.get("email")))
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["tranco", "file"], required=True)
    ap.add_argument("--file")
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--geo", default=os.environ.get("GEO", "na"))
    ap.add_argument("--verticals", default=os.environ.get("VERTICALS", VERTICALS_DEFAULT))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="candidates.csv")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()
    geos = [g.strip() for g in args.geo.split(",") if g.strip()]
    bad = [g for g in geos if g not in GEO_TLDS]
    if bad:
        raise SystemExit(f"unknown geo(s): {bad}")

    raw = read_source(args)
    stage(1, "source", len(raw), "source was empty")
    pairs = tld_gate(raw, geos)
    stage(2, "tld gate", len(pairs), "no TLD matches")
    pairs = mx_gate([d for d, _ in pairs], args.workers)
    stage(3, "mx gate", len(pairs), "no Outlook MX survivors")
    # ambiguous (".com") was lost in the tuple above; recompute ambiguity from TLD.
    with_mx = []
    for d, mx in pairs:
        with_mx.append((d, mx, d.endswith(".com")))
    # Non-ambiguous TLDs already encode geography and skip geo. Ambiguous .com
    # survivors must be proven by ip-api or they are dropped.
    kept_static = [(d, mx, "tld") for d, mx, amb in with_mx if not amb]
    kept_geo = geo_confirm([(d, mx) for d, mx, amb in with_mx if amb])
    confirmed = kept_static + kept_geo
    stage(4, "geo confirm", len(confirmed), "ip-api returned no in-geo hosts")
    confirmed = vertical_gate(confirmed, args.verticals)
    stage(5, "vertical gate", len(confirmed), "no vertical matches")

    out_path = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
    seen = existing_rows(out_path)
    new_file = not os.path.exists(out_path)
    written = 0
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["domain", "email", "geo_method", "verified"])
        for domain, mx, geo_method in confirmed:
            if args.limit and written >= args.limit:
                break
            found, guesses, verified = harvest_domains(domain, mx)
            for e in list(dict.fromkeys(found + guesses)):
                if args.limit and written >= args.limit:
                    break
                if (domain, e) in seen:
                    continue
                is_verified = 1 if e in verified else 0
                w.writerow([domain, e, geo_method, is_verified])
                seen.add((domain, e))
                written += 1
                print(f"  + {domain},{e},{geo_method},{is_verified}")
    stage(6, "address harvest", written, "no addresses written")
    print(f"wrote {written} rows to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
