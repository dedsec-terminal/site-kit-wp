# Django Security Audit — utils/http.py, views/static.py, core/validators.py

| | |
|---|---|
| **Target** | `github.com/django/django` — **main** @ `dd6f6b1` (6.2.dev20260920174155) and **stable/5.2.x** @ `a3d7103` (5.2.18.dev) |
| **Date** | 2026-09-22 |
| **Method** | Source review + **differential testing**: browser-semantics oracle (Node `WHATWG URL`), live runserver corpus, regex timing harness — everything below is executed evidence, not just reading |
| **Headline result** | **No CVE-worthy bug in the three scoped modules (all dynamically verified clean).** 2 verified LTS↔main deltas found, both below Django's CVE bar (details + rationale included), plus a map of where the 2026 bug pattern actually is |

---

## 1. A: Open redirect — `url_has_allowed_host_and_scheme()` : **CLEAN (0/192)**

Harness: `open_redirect_diff.py` — 192 adversarial cases, each scored by **Django's function** (`allowed_hosts={"good.test"}`) and by the **WHATWG URL parser via Node v22** (what a browser actually does with `Location:`).

Coverage: separator classes (`//`, `/\`, `\\`, `/%5c`, `///`, `////`), userinfo/`@` tricks, userinfo-encoding (`%40`, `%2540`, `@@`), scheme smuggling (`javascript:`, `java\tscript:`, `data:`, `vbscript:`, mixed case), scheme-relative-with-no-host (`http:///evil.com`, `http:evil.com`), fullwidth/unicode (`http：//`, `evil。com`, `evil．com`), control chars at various offsets, NUL, IPv6 (`[::1]`, zone ids, malformed brackets), drive letters, `file:`, trailing multi-dots, dot-segment paths (`/../..//`), ports (`:99999`, `:-1`, `:80evil.com`), 3KB+ length edge.

**0 mismatches.** The defense is structurally sound because it:
1. rejects empty/whitespace URLs, `///`-leading URLs, and `> MAX_URL_LENGTH`,
2. rejects `scheme` with empty `netloc` (kills the `http:evil.com` class Chrome normalizes),
3. rejects any control-category first character,
4. compares the **whole netloc** (incl. userinfo/port) against allowed hosts (kills every `@` trick), and
5. requires the check to pass on both the raw **and** `\`→`/` normalized string (kills the IE/Chrome backslash class — the reason `\\evil.com`, `/\evil.com`, `//good.test\.evil.com` all fail).

Verdict: bypassing this function now requires breaking Python `urlsplit` vs WHATWG alignment itself, which is upstream Python territory (and Django already defends the known deltas).

## 2. B: ReDoS — `core/validators.py` : **CLEAN (linear across 12 families)**

Harness: `redos_probe.py` against `URLValidator`, `EmailValidator`, `DomainNameValidator` — host-label dash runs, multi-label subdomain chains, dot-dash alternation, user:pass stuffing, local-part dot/atom/quoted-string runs, at sizes 64→2048.

Result: **sub-linear/linear everywhere** (worst = 0.06 ms at n=1024 for URL host patterns). Structural reasons: all quantifiers are **bounded** (`{0,61}`, `{1,63}`), `URLValidator` hard-caps input at 2048 chars (`MAX_URL_LENGTH`), `EmailValidator` at 320, and no nested-unbounded alternation exists in any pattern.

> Context: Django's accepted DoS CVEs (e.g. Truncator CVE-2025-26699, IPv6 CVE-2025-27556) came from *every-other-module* helpers — the core validators are the wrong tree for this class in 2026.

## 3. C: Static serve — `views/static.py` : **CLEAN (0/20 over live HTTP)**

Ran a real `runserver` on 5.2.x with `serve(document_root=…, show_indexes=True)` and a trap file above the root. 20-case corpus (`--path-as-is` to stop client-side normalization):

| Class | Sample | Result |
|---|---|---|
| raw traversal | `/static/../../etc/passwd` | **400** (`SuspiciousFileOperation`) |
| URL-encoded | `%2e%2e%2f`, `..%2f`, `%2e%2e%2f%2e%2e%2fetc%2fpasswd` | **400** |
| backslash | `%2e%2e%5c…` | **404** (no separator confusion on POSIX) |
| double-encoded | `%252e%252e%252f` | **404** (single decode layer) |
| absolute injection | `/static//etc/passwd`, `%2fetc%2fpasswd` | **404** (folded under root by `normpath().lstrip('/')`) |
| wrapped traversal | `nested/../../secret` | **400** |
| overlong UTF-8 / dot4 | `%c0%ae%c0%ae`, `....//` | **404** |
| NUL | `public.txt%00`, `%00…` | **404** |
| control: legit joins | `nested/../nested/inner.txt` | **200 (correct, stays in root)** |

`safe_join`'s `abspath`+prefix check catches everything the OS would resolve outside; `serve()` never hits the filesystem for rejected paths.

---

## 4. Two verified branch deltas (observations, below CVE bar)

Both are **already fixed on main** under *regular* (non-security) tickets — Django's own triage rated them non-CVE — but they are real, reproducible differences on the currently supported **5.2 LTS** branch, and finding them independently is exactly the kind of evidence worth including in a research portfolio. Not worth reporting as *new* security issues; worth mentioning if you report something adjacent.

**D1 — `URLValidator` accepts NUL bytes on 5.2 LTS** (main: rejected, #37279)
```python
URLValidator()("http://example.com/a\x00b")   # 5.2 LTS → passes; main → ValidationError
```
`unsafe_chars = frozenset("\t\r\n")` vs main's `frozenset("\t\r\n\x00")`. NULs in URLs are rejected downstream by HTTP clients/proxies, so impact is limited (validation/serialization disagreement); that's why it's hardening, not a CVE.

**D2 — `content_disposition_header()` `$`-vs-`\Z` newline slip on 5.2 LTS** (main: fixed, #37198)
```python
content_disposition_header(True, "poison\n")
# 5.2 LTS → 'attachment; filename="poison\n"'   ($ matches before trailing \n)
# main    → "attachment; filename*=utf-8''x%0A"
```
The raw newline never reaches the wire: Django's header layer raises `BadHeaderError` at assignment — **verified** for both direct `response[...]=` and `FileResponse(filename=…)`, on WSGI *and* ASGI (check happens in `HttpHeaders`, before handler emission). Worst case is a deterministic 500 in apps that pass attacker-controlled filenames — self-inflicted, not exploitable. Correct non-security rating.

**Already-fixed confirmed:** CVE-2026-53878 (newlines in `DomainNameValidator`) — class bodies are byte-identical in 5.2.x and main, i.e. properly backported; *not* a live lead. `EmailValidator`'s domain path was never vulnerable (newline excluded by char classes).

## 5. Where the live 2026 pattern is (next leads, ranked by freshness)

The 2026 Django fixes (CVE-2026-35193 cache-control directives, CVE-2026-48587 header-value splitting) cluster around **header-tokenization agreement** — and main added brand-new, lightly-reviewed code there:

1. **`django/utils/http.py: split_header_value()` / `split_directive_names()`** — new helpers (only exist on main). Audit every consumer: `middleware/cache` Vary-key construction, cache-control parsing — look for *splitting disagreement* (naive `.split(',')` consumers still elsewhere in the codebase using different rules than the new helpers) → cache-poisoning/key-confusion class.
2. **`MAX_HEADER_LENGTH = 10_000` (new on main)** — find where it is *not* applied (any header-building path that skips the ceiling).
3. **`django/utils/text.py` & string helpers** — the Truncator precedent; check newer truncator/word-wrap paths for polynomial regexes with unbounded input (they have no length caps like validators do).
4. **Branch-diff mining (the method that found D1/D2):** `diff -r` the security-sensitive files between `stable/5.2.x` and `main`; anything fixed on main under a *quiet* ticket that isn't backported is a candidate — your job is then to demonstrate *impact* beyond where it caps out (that's the part D1/D2 fail).

## 6. Filing info (when you do land one)

Django security team: **security@djangoproject.com** (GPG optional), coordinated disclosure + official CVEs; bounty via the **Internet Bug Bounty (HackerOne)** for qualifying findings. They explicitly publish what they will/won't call security issues in `docs/internals/security.txt` — read the "not considered security issues" list before writing up (it saves a rejection round).

## 7. Deliverables

- `DJANGO_AUDIT.md` (this), `open_redirect_diff.py` (192-case WHATWG differential), `redos_probe.py` (12-family timing harness), static-serve test project (`srv_project.py`, `run_srv.py`)

*Audit performed locally against the two public branches; no production systems touched.*
