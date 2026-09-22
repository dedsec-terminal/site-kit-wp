# Security Audit Report — ComfyUI (v2, corrected)

| | |
|---|---|
| **Target** | ComfyUI (`comfyanonymous/ComfyUI`) |
| **Version tested** | v0.37.0 — master @ `b33e2b55cae074eca5aec96283cceac19aa249ba` (2026-09-22) |
| **Audit date** | 2026-09-22 |
| **Environment** | Linux x86_64, Python 3.11, CPU build, stock `requirements.txt` deps (incl. PyAV≥17) |
| **Method** | Manual source review + dynamic reproduction against a live server; peer-reviewed; bypass/escalation attempts performed and documented |
| **Result** | **1 in-scope verified vulnerability (Medium)** — pre-auth / workflow-file arbitrary file write with constrained naming |

> **v2 changelog:** corrected which node is deprecated (the more dangerous one is NOT); downgraded the CSRF note after verifying the `Sec-Fetch-Site` guard; re-scored impact per peer review with a full constraints/escalation appendix. v1 overstated severity and incorrectly claimed browser-CSRF feasibility.

---

## 1. Executive summary

ComfyUI's HTTP/file surface is well hardened (containment checks after canonicalization almost everywhere). One write site was missed: `save_images_to_folder()` in `comfy_extras/nodes_dataset.py`. In `overwrite` mode the user-controlled `filename_prefix` goes straight into the final filesystem path with no sanitization and no containment check, while the sibling `increment` branch (and every other save node in the codebase) is protected.

This yields **pre-authenticated file creation and silent file overwrite at an absolute path or via `../` traversal**, from a single `/prompt` request or a crafted workflow file, with **no models, no GPU, and no authentication**. Verified end-to-end on a live 0.37.0 server.

**Key severity correction (favorable to the reporter):** the *more* dangerous of the two nodes — `SaveImageTextDataSetToFolder`, which writes **fully attacker-controlled text content** — is **not deprecated** (only `is_experimental=True`). It is a fully supported built-in. Only the PNG-only variant (`SaveImageDataSetToFolder`) is deprecated, and even that deprecation is a UI hint that does not affect server-side execution.

**Impact ceilings (verified, see §4):** filenames are structurally forced to `<prefix>_NNNNN.png` / `<prefix>_NNNNN.txt`; the target's parent directory must already exist; NUL-byte truncation of the suffix is not possible; the `.png` payload is a valid PIL-encoded image. Net: a solid integrity/availability primitive and escalation building block — **not direct RCE**. This is the practical ceiling of this bug; see §4 for everything tried.

**Suggested score:** ≈ **6.5 Medium** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`) for the unauthenticated-API vector; ≈ 5.0–5.5 via the workflow-file vector (UI required). The attack is trivially reliable, so AC:L.

---

## 2. Finding 1 (in-scope, verified): unsanitized `filename_prefix` in dataset save nodes → arbitrary file write (CWE-22 / CWE-73)

### 2.1 Root cause

`comfy_extras/nodes_dataset.py` — `save_images_to_folder()`:

```python
435:        if overwrite:
436:            filename = f"{prefix}_{idx:05d}.png"                  # UNSANITIZED user input
437:        else:
438:            _, _, counter, _, resolved_prefix = folder_paths.get_save_image_path(prefix, output_dir)  # safe
439:            filename = f"{resolved_prefix}_{counter:05}_{idx:05d}.png"
440:        filepath = os.path.join(output_dir, filename)             # no containment check
441:        img.save(filepath)
```

Callers (exactly two):

| Node | Writes | Deprecated? |
|---|---|---|
| `SaveImageDataSetToFolder` (L491) | PNG (PIL-encoded pixels, attacker-influenced) | **Yes** (`is_deprecated=True`) — but still executes; `validate_prompt` only checks `class_type ∈ NODE_CLASS_MAPPINGS` (`execution.py:1147`) |
| `SaveImageTextDataSetToFolder` (L545) | PNG **+ `.txt` caption with fully attacker-controlled content** (`caption_filename = filename.replace(".png", ".txt")`) | **No** (`is_experimental=True` only) |

Both nodes are registered by default (`DatasetExtension`, `nodes_dataset.py:2127`, → `NODE_CLASS_MAPPINGS`, `nodes.py:2328`), both are `is_output_node=True` (so `validate_prompt` accepts them as execution outputs). Note the file was clearly traversal-audited before: `folder_name` goes through `secure_subfolder_path()` (realpath containment) and `increment` mode through `get_save_image_path()` (`is_within_directory` check, `folder_paths.py:552`). **Only the overwrite-mode prefix was missed** — the asymmetry demonstrates oversight, not design.

### 2.2 Verification (all executed on the live server)

**A. Absolute-path write (CWE-73):**
```
POST /prompt {"prompt":{"1":{"class_type":"EmptyImage","inputs":{"width":16,"height":16,"color":16711680,"batch_size":1}},"2":{"class_type":"SaveImageDataSetToFolder","inputs":{"images":["1",0],"folder_name":"dataset","filename_prefix":"/tmp/comfyui_pwn/arena_owned_abs","mode":"overwrite"}}}}
→ 200 {"prompt_id":"e7e9d71f-…","node_errors":{}}
→ created /tmp/comfyui_pwn/arena_owned_abs_00000.png        # outside ALL ComfyUI directories
```

**B. `../` traversal (CWE-22):** prefix `../../../../../../../../tmp/comfyui_pwn/arena_owned_traversal` → `/tmp/comfyui_pwn/arena_owned_traversal_00000.png`. (On Windows, `\` also works as a separator — payload is cross-platform.)

**C. Controlled-content write:** `SaveImageTextDataSetToFolder` with `texts:"<attacker string>"` → `/tmp/comfyui_pwn/owned_content_00000.txt` containing exactly that string.

**D. Silent overwrite:** pre-existing `important_config_00000.txt` ("ORIGINAL - top secret") → after one request: `WIPED BY ATTACKER`. No prompt_id errors, no warnings — execution is silent.

`EmptyImage` (`nodes.py:1979`, pure `torch.full`, no model) feeds the image input.

### 2.3 Impact (realistic framing)

- **Delivery vectors:** (1) unauthenticated HTTP to `/prompt` — default installs have *no auth* ("Anyone with access to the ComfyUI URL is trusted", SECURITY.md); (2) a crafted workflow `.json` the victim imports and runs — the exact in-scope vector named in `SECURITY.md` ("a workflow file … using only built-in nodes, that results in … arbitrary file read/write outside expected directories"). Execution is silent, requires no prompt acknowledgment.
- **Effect:** create files, or truncate+rewrite any existing file whose name matches `<anything>_NNNNN.png/.txt`, anywhere the process can write. Common container/cloud templates (RunPod/Vast.ai/Docker) run ComfyUI as **root**.
- **Consequences:** destroy/poison arbitrary user data, configs, projects, shared-model caches in multi-user SaaS deployments; knock out a service by truncating its matching files; plant attacker content for a second-stage primitive. **Not direct RCE** (§4 constraints).

### 2.4 Remediation (fix included: `fix_suggestion.diff`, syntax-verified)

Contain, inside `save_images_to_folder()` — covers both nodes:

```python
filepath = os.path.join(output_dir, filename)
if not folder_paths.is_within_directory(output_dir, filepath):
    raise ValueError(f"Invalid filename_prefix {prefix!r}: resolves outside of {output_dir}")
```

Defence-in-depth worth suggesting: reject `os.sep`/`..` in `filename_prefix` for these nodes; make the server refuse `is_deprecated=True` nodes unless explicitly enabled.

---

## 3. Corrected note (informational; NOT a separate vuln): browser CSRF

v1 reported a cross-origin CSRF amplifier. It is **weaker than stated** and dropped from findings: `create_origin_only_middleware` (server.py:162-165) returns 403 for any request with `Sec-Fetch-Site: cross-site` — a header browsers send on cross-site requests and scripts cannot override — and the loopback `Host==Origin` rule covers the remainder. My earlier demo worked only because `curl` omits `Sec-Fetch-Site`; that is request forgery against an already-unauthenticated endpoint, not browser CSRF. For deployments exposed via `--listen`, origin policy remains a hardening discussion for a regular GitHub issue; per `SECURITY.md`, anything requiring non-default exposure is out of scope anyway. No CORS headers are emitted (so no cross-origin read), and no finding hinges on this.

---

## 4. Constraints & escalation attempts (all performed; none bypassed)

| # | Constraint / attempt | Result |
|---|---|---|
| 1 | Suffix forced to `_NNNNN.png` / `_NNNNN.txt` (`{prefix}_{idx:05d}`) | **Unavoidable**; `idx` is an enumerate counter |
| 2 | Extension forced to `.png` / `.txt` | **Unavoidable** — so `authorized_keys`-style RCE targets are unreachable |
| 3 | NUL-byte truncation of the suffix | **Blocked** (JSON string parsing / `open()` rejects NUL) |
| 4 | `.replace(".png",".txt")` in caption path replaces **all** occurrences | Confirmed quirk (`sub.png/quirk` → image to `sub.png/…`, caption to `sub.txt/…`) — **no additional escape**; no security delta |
| 5 | Parent directory of the target must exist (`os.makedirs` only creates `output_dir`) | **Confirmed** (FileNotFoundError otherwise); attacker arbitrary-dir creation requires the parent already be present |
| 6 | Windows `\` separators on Linux | Stay literal (single filename, verified); **on Windows they traverse** — the payload is cross-platform via `/` |
| 7 | Symlink placement via HTTP API | **Not possible** — upload/userdata paths create regular files only |
| 8 | PNG content | Re-encoded by PIL (valid PNG); not raw bytes |
| 9 | Looking for paired arbitrary-read primitive in built-in nodes (`LoadImage`, painter, audio fingerprint, 3D loaders, dataset loaders, `/view*`, `/userdata*`, assets API) | **All contained** (annotated/filepath containment or DB-scoped); none found |
| 10 | Adjacent write sites without containment (`SaveGLB`, saver-3D, AVIF metadata, video/latent/audio savers, `nodes_lt`, `websocket_image_save`) | **All contained** — `get_save_image_path()` or uuid filenames |
| 11 | Overwriting existing `*_NNNNN.png/.txt` everywhere (destruction) | Works (constraint only on name pattern) |
| 12 | RCE with built-in nodes only | No path found; `ComfyMathExpression` uses allow-listed `simpleeval` |

---

## 5. Why report it anyway (triager framing)

- In-scope per the project's own exact words (workflow-file vector, built-in nodes, arbitrary write outside expected directories).
- The more severe (controlled-content) node is fully supported, non-deprecated.
- Trivial reliability: one HTTP request, stock install, no models/GPU; runs with process privileges (frequently root in the wild).
- The codebase's own pattern (`secure_subfolder_path`, `get_save_image_path`) shows this is an oversight deserving the same containment; fix is 4 lines and included.

## 6. Areas audited clean (unchanged from v1)

`/view` (+annotations, content-type forcing), `/upload/image|mask`, `/userdata*` (double-decode-safe containment), assets API (off by default; fixed-root tag routing; `filename*` disposition), `/experiment/models/preview` (file + glob-selected preview both realpath-revalidated), `/internal/*` (root-restricted), `get_full_path` (relpath normalization), all other save nodes (`SaveImage`, `CheckpointSave`, `LoraSave`, `SaveText`, audio/latent/video/3D savers), `simpleeval` math node, frontend zip install (regex-validated CLI input, sanitized extractall), static serving (`follow_symlinks=False`), loopback CSRF (blocked by middleware).

## 7. Deliverables & disclosure

- `SECURITY_AUDIT_COMFYUI.md` (this), `poc_arbitrary_file_write.py` (dry-run by default; `--execute` fires), `malicious_workflow_demo.json` (benign target), `fix_suggestion.diff`.
- Report privately: https://github.com/comfyanonymous/ComfyUI/security/advisories/new and/or Huntr (ComfyUI program). Expected class: CWE-22/CWE-73, pre-auth arbitrary file write. Do not publish before coordinated disclosure.

*Audit performed against a local self-hosted instance, for education and responsible disclosure.*
