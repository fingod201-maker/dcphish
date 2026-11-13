#!/usr/bin/env bash
# cron: */10 * * * * /opt/dcphish/systemd/watchdog.sh
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

if pgrep -f "python .*poll.py" >/dev/null; then
  exit 0
fi

# Dead? Confirm process age is genuinely gone for >10 min via systemd timestamp.
LAST=$(systemctl show dcphish-poll.service -p ActiveEnterTimestampMonotonic --value 2>/dev/null || echo 0)
NOW=$(awk '{printf "%d", $1*1000000}' /proc/uptime)
if [ "${LAST:-0}" -gt 0 ] 2>/dev/null; then
  AGE=$(( (NOW - LAST) / 1000000 ))
  [ "$AGE" -lt 600 ] && exit 0
fi

curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  -d "chat_id=${TG_CHAT}" \
  -d "text=dcphish: poll.py is dead (>10 min), systemd did not revive it" \
  -d "disable_web_page_preview=true" >/dev/null || true
