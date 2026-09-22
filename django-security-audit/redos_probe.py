#!/usr/bin/env python3
"""ReDoS probe for Django core validators (URLValidator, EmailValidator,
DomainNameValidator). Measures match-time growth on pathological families.
Super-linear growth at practical lengths = potential DoS report.
"""
import sys, time, statistics
sys.path.insert(0, "/home/user/django-audit")
from django.core.validators import URLValidator, EmailValidator, DomainNameValidator
from django.core.exceptions import ValidationError

def timed_call(fn, value, repeats=3):
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        try:
            fn(value)
        except ValidationError:
            pass
        best = min(best, time.perf_counter() - t0)
    return best

def probe(name, fn, make, sizes=(64, 128, 256, 512, 1024, 2048)):
    rows = []
    for n in sizes:
        v = make(n)
        if len(v) > 2000:  # URLValidator caps at MAX_URL_LENGTH
            rows.append((n, None)); continue
        t = timed_call(fn, v)
        rows.append((n, t))
    print(f"\n### {name}")
    prev_t = None
    for n, t in rows:
        if t is None:
            print(f"  n={n:>5} skipped (> maxlen)")
            continue
        ratio = f"{t/prev_t:6.1f}x" if prev_t else "     -"
        print(f"  n={n:>5} {t*1000:9.2f} ms  growth {ratio}")
        prev_t = t
    return rows

uv = URLValidator()
ev = EmailValidator()
dv = DomainNameValidator()

families = [
    ("URL: host label dashes", uv, lambda n: "http://" + "a" * 30 + "-" * n + "b" + ".x.com/y"),
    ("URL: many subdomains", uv, lambda n: "http://" + ("a." * n) + "x.com/y"),
    ("URL: long a-run then dot-dash", uv, lambda n: "http://" + ("a" * 60 + ".") * (n // 61) + "a" * (n % 61) + "/y"),
    ("URL: dot-dash alternating", uv, lambda n: "http://" + ("a-" * (n // 2)) + "!" + "/y"),
    ("URL: userinfo long", uv, lambda n: "http://" + "u" * (n // 2) + ":" + "p" * (n // 2) + "@x.com/y"),
    ("URL: hostname_re vs a{59}a", uv, lambda n: "http://" + "a" * 59 + "a-" * (n // 2) + "/y"),
    ("EMAIL: local dots", ev, lambda n: ("a." * (n // 2)) + "a@x.com"),
    ("EMAIL: local a-run", ev, lambda n: ("a" * (n // 2)) + "." + ("a" * (n - n // 2)) + "@x.com"),
    ("EMAIL: quoted local", ev, lambda n: '"' + ("a" * (n // 2)) + "\\" + ('a' * (n - n // 2 - 1)) + '"@x.com'),
    ("EMAIL: domain dashes", ev, lambda n: "a@" + "a" * 30 + "-" * n + "b" + ".x.com"),
    ("EMAIL: domain many labels", ev, lambda n: "a@" + ("a." * n) + "x.com"),
    ("DOMAIN: dot-dash", dv, lambda n: "a-" * (n // 2) + "!"),
    ("DOMAIN: many labels", dv, lambda n: ("a." * n) + "x.com"),
]
for name, fn, make in families:
    probe(name, fn, make)
