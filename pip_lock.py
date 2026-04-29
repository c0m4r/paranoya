#!.venv/bin/python
"""Generate a requirements.lock.txt with hashes from a pinned requirements.freeze.txt file.

Usage:
    python pip_lock.py [freeze_file] [output_file]

Defaults:
    freeze_file  = requirements.freeze.txt
    output_file = requirements.lock.txt
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request


def parse_lock(filepath: str) -> list[tuple[str, str, str]]:
    """Parse a lock file, returning (name, version, original_line) tuples."""
    packages: list[tuple[str, str, str]] = []
    skipped = 0
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                if line:
                    skipped += 1
                continue
            m = re.match(r"^([a-zA-Z0-9._-]+)(?:\[([^\]]+)\])?==(.+)$", line)
            if m:
                name = m.group(1)
                version = m.group(3)
                packages.append((name, version, line))
            else:
                print(f"  [warn] could not parse: {line}", file=sys.stderr)
                skipped += 1
    print(f"  [info] parsed {len(packages)} packages, skipped {skipped} lines")
    return packages


def fetch_hashes(name: str, version: str) -> list[str]:
    """Fetch SHA256 hashes from PyPI JSON API for a given package version."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pip_freeze/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  [error] HTTP {e.code} fetching {name}=={version}", file=sys.stderr)
        return []
    except (urllib.error.URLError, OSError) as e:
        print(f"  [error] network error fetching {name}=={version}: {e}", file=sys.stderr)
        return []

    seen: set[str] = set()
    hashes: list[str] = []
    sdist_count = 0
    wheel_count = 0
    for dist in data.get("urls", []):
        sha256 = dist.get("digests", {}).get("sha256")
        if sha256 and sha256 not in seen:
            seen.add(sha256)
            hashes.append(f"sha256:{sha256}")
            if dist.get("packagetype") == "sdist":
                sdist_count += 1
            else:
                wheel_count += 1
    return hashes


def main() -> None:
    freeze_file = sys.argv[1] if len(sys.argv) > 1 else "requirements.freeze.txt"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "requirements.lock.txt"

    print(f"[info] reading {freeze_file}")
    try:
        packages = parse_lock(freeze_file)
    except FileNotFoundError:
        print(f"[error] {freeze_file} not found", file=sys.stderr)
        sys.exit(1)

    if not packages:
        print("[warn] no packages found, nothing to do")
        sys.exit(0)

    total = len(packages)
    print(f"[info] processing {total} packages...\n")
    lines: list[str] = []
    total_hashes = 0
    total_errors = 0
    start_time = time.monotonic()

    for i, (name, version, original_line) in enumerate(packages, 1):
        pct = i / total * 100
        print(f"  [{i:>3}/{total}] {name}=={version}  ({pct:.0f}%)", end=" ", flush=True)
        t0 = time.monotonic()
        hashes = fetch_hashes(name, version)
        elapsed = time.monotonic() - t0

        if not hashes:
            print("-> 0 hashes [error]")
            total_errors += 1
            lines.append(original_line)
            continue

        print(f"-> {len(hashes)} hashes  ({elapsed:.2f}s)")
        lines.append(f"{original_line} \\")
        for j, h in enumerate(hashes):
            continuation = " \\" if j < len(hashes) - 1 else ""
            lines.append(f"    --hash={h}{continuation}")
        total_hashes += len(hashes)

    elapsed = time.monotonic() - start_time

    with open(output_file, "w") as f:
        f.write("\n".join(lines) + "\n")

    output_size = len("\n".join(lines)) + 1
    print(f"\n[info] done in {elapsed:.1f}s")
    print(f"[info] packages: {total}  hashes: {total_hashes}  errors: {total_errors}")
    print(f"[info] wrote {output_file} ({output_size:,} bytes, {len(lines):,} lines)")


if __name__ == "__main__":
    main()
