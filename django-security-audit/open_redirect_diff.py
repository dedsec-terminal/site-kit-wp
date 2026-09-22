#!/usr/bin/env python3
"""Differential test: django.utils.http.url_has_allowed_host_and_scheme() (Django verdict)
vs WHATWG URL parsing (browser verdict, via Node).

An interesting case = Django says SAFE but the browser navigates cross-origin.
"""
import json
import subprocess
import sys

sys.path.insert(0, "/home/user/django-audit")
from django.utils.http import url_has_allowed_host_and_scheme

ALLOWED = {"good.test"}  # typical: request.get_host()
BASE = "https://good.test/"

# ---------- corpus ----------
seps = ["//", "/\\", "\\/", "\\\\", "/%5c", "%5c/", "//\\", "\\//", "///", "////"]
hosts = ["evil.com", "good.test@evil.com", "evil.com@good.test", "good.test\\.evil.com",
         "good.test/evil.com", "good.test.evil.com"]
schemes = ["javascript:", "data:", "vbscript:", "http:", "https:", "file:", "JaVaScRiPt:",
           "java\tscript:", "java\nscript:", "java\rscript:"]
cases = []
for s in seps:
    for h in hosts:
        cases.append(s + h)
        cases.append(s + h + "/x")
for sc in schemes:
    cases.append(sc + "alert(1)")
    cases.append(sc + "//evil.com")
cases += [
    # userinfo / at-sign games
    "//good.test%40evil.com", "//good.test%2540evil.com", "//good.test@@evil.com",
    "//@good.test", "//good.test@", "//good.test:443@evil.com",
    # scheme + no netloc tricks
    "http:///evil.com", "http:/\\evil.com", "http:\\evil.com", "http:/evil.com",
    "http:evil.com", "https:/\evil.comevil.com", "https:／／evil.com",
    # fullwidth / unicode
    "http：//evil.com", "//evil。com", "//evil．com", "//evil%2ecom",
    "//good.test\x00.evil.com", "\x00//evil.com", "//evil.com\x00",
    "　//evil.com", "//　evil.com",
    # control chars not at pos 0
    "//e\tvil.com", "//e\nvil.com", "//e\rvil.com", "h\ttp://evil.com",
    # ipv6
    "//[::1]/x", "//[::1", "http://[::1]evil.com/", "//[2001:db8::1%25good.test]/",
    # drive letters / file
    "c:\\evil.com", "c:/evil.com", "file:///c:/evil.com", "file://evil.com/c$/",
    # dots in host
    "//good.test./", "//good.test../", "//..evil.com", "//../evil",
    # path-relative that browsers normalize oddly
    "/..//evil.com", "/%2e%2e//evil.com", "/.//evil.com",
    # whitespace embedded (browsers strip tab/newline everywhere)
    "//good.test\t.evil.com", "http://good.test\n@evil.com/",
    " ja\tvascript:alert(1)",
    # long URL edge
    "//good.test/" + "a" * 3000,
    # weird ports
    "//good.test:99999/", "//good.test:-1/", "//good.test:80evil.com/",
    # multiple schemes
    "javascript:http://good.test", "data:text/html,<script>alert(1)</script>",
    # backslash before scheme-colon
    "java\\script:alert(1)", "\\javascript:alert(1)",
]

cases = list(dict.fromkeys(cases))  # dedupe, keep order

# ---------- Django verdicts ----------
django_results = []
for u in cases:
    try:
        django_results.append(bool(url_has_allowed_host_and_scheme(u, ALLOWED)))
    except Exception as e:
        django_results.append("EXC:" + type(e).__name__)

# ---------- WHATWG verdicts via Node ----------
node_script = r"""
const readline = require('readline');
const rl = readline.createInterface({input: process.stdin});
const out = [];
rl.on('line', l => { out.push(l); });
rl.on('close', () => {
  const cases = out.filter(Boolean);
  const res = cases.map(u => {
    try {
      const url = new URL(u, 'https://good.test/');
      return {u, ok: true, host: url.hostname, href: url.href};
    } catch (e) {
      return {u, ok: false};
    }
  });
  process.stdout.write(JSON.stringify(res));
});
"""
proc = subprocess.run(["node", "-e", node_script], input=json.dumps(cases)[1:-1].replace('","', '"\n"').replace('"', ''),
                      capture_output=True, text=True)
# simpler: pass via argv-free stdin JSON
proc = subprocess.run(
    ["node", "-e", """
const chunks=[];process.stdin.on('data',d=>chunks.push(d));process.stdin.on('end',()=>{
const cases=JSON.parse(Buffer.concat(chunks).toString());
const res=cases.map(u=>{try{const url=new URL(u,'https://good.test/');return{ok:true,host:url.hostname,href:url.href};}catch(e){return{ok:false};}});
process.stdout.write(JSON.stringify(res));});
"""],
    input=json.dumps(cases), capture_output=True, text=True)
browser = json.loads(proc.stdout)

# ---------- report ----------
print(f"{'idx':>3} {'DJANGO':>7} {'BROWSER':>16}  URL")
interesting = 0
for i, (u, d) in enumerate(zip(cases, django_results)):
    b = browser[i]
    bverdict = "nav:" + b["host"] if b["ok"] else "parse-fail"
    cross = b["ok"] and b["host"] not in ("good.test", "")
    flag = ""
    if (d is True) and cross:
        flag = "  <<< OPEN REDIRECT BYPASS?"
        interesting += 1
    print(f"{i:>3} {str(d):>7} {bverdict:>22}  {u!r}{flag}")
print(f"\ninteresting mismatches: {interesting} / {len(cases)}")
