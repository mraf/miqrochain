
#!/usr/bin/env python3
"""
Fetch official micro-ecc (BSD-2) sources for secp256k1 into vendor/microecc/upstream.
This vendors *exact* upstream files (uECC.c, uECC.h, uECC_vli.c, uECC_vli.h).

Usage:
  python3 scripts/vendor_microecc.py
"""
import os, sys, urllib.request, pathlib

# Mirrors with raw files (GoogleSource mirrors are stable):
FILES = {
  "uECC.c":  "https://pigweed.googlesource.com/third_party/github/kmackay/micro-ecc/+/refs/heads/master/uECC.c?format=TEXT",
  "uECC.h":  "https://fuchsia.googlesource.com/third_party/github.com/kmackay/micro-ecc/+/refs/heads/master/uECC.h?format=TEXT",
  "uECC_vli.c": "https://pigweed.googlesource.com/third_party/github/kmackay/micro-ecc/+/refs/heads/master/uECC_vli.c?format=TEXT",
  "uECC_vli.h": "https://pigweed.googlesource.com/third_party/github/kmackay/micro-ecc/+/refs/heads/master/uECC_vli.h?format=TEXT",
  "LICENSE": "https://fuchsia.googlesource.com/third_party/github.com/kmackay/micro-ecc/+/refs/heads/master/LICENSE?format=TEXT",
  "README.md": "https://fuchsia.googlesource.com/third_party/github.com/kmackay/micro-ecc/+/refs/heads/master/README.md?format=TEXT",
}

def b64decode_text(b):
    import base64
    return base64.b64decode(b).decode("utf-8", errors="replace")

def main():
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    outdir = repo_root / "vendor" / "microecc" / "upstream"
    outdir.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        print(f"Downloading {name} ...")
        with urllib.request.urlopen(url) as r:
            data = r.read()
        # googlesource returns Base64 when ?format=TEXT
        text = b64decode_text(data)
        (outdir / name).write_text(text, encoding="utf-8")
    print("Done. Upstream micro-ecc vendored into:", outdir)
    print("Rebuild with: cmake -S . -B build -DMIQ_USE_UPSTREAM_MICROECC=ON && cmake --build build")

if __name__ == "__main__":
    main()
