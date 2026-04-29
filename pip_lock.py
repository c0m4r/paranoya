#!/usr/bin/env python3
"""
Generate requirements.lock.txt from requirements.freeze.txt with SHA256 hashes.
The output is compatible with: pip install --require-hashes -r requirements.lock.txt
"""

import hashlib
import os
import subprocess
import sys
import tempfile
from collections import defaultdict


def pkg_name_normalize(name: str) -> str:
    """Normalize package name per PEP 503: lowercase, replace _ with -"""
    return name.lower().replace("_", "-")


def main():
    if not os.path.exists("requirements.freeze.txt"):
        print("Error: requirements.freeze.txt not found", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:
        print("Downloading packages...")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--no-deps",
                "--no-cache-dir",
                "-d",
                tmpdir,
                "-r",
                "requirements.freeze.txt",
            ],
            check=True,
        )

        hashes_by_package = defaultdict(list)

        for filename in sorted(os.listdir(tmpdir)):
            filepath = os.path.join(tmpdir, filename)
            if not os.path.isfile(filepath) or filename == "requirements.freeze.txt":
                continue

            # Extract package name: "package-version-..." -> "package"
            # Wheel: package-version-<pyver>-<abi>-<platform>.whl
            # Sdist:  package-version.tar.gz
            base, _, ext = filename.rpartition(".")
            if ext == "whl":
                # Strip everything after version: name-version-py3-none-any.whl
                parts = base.split("-")
                # Find where version starts (first part that begins with digit)
                name_parts = []
                for i, part in enumerate(parts):
                    if part[0].isdigit():
                        name_parts = parts[:i]
                        break
                pkg_name = "-".join(name_parts)
            elif ext in ("gz", "bz2", "zip"):
                # sdist: package-version.tar.gz
                # Strip .tar then parse: name-version
                inner = base.removesuffix(".tar")
                parts = inner.split("-")
                name_parts = []
                for i, part in enumerate(parts):
                    if part[0].isdigit():
                        name_parts = parts[:i]
                        break
                pkg_name = "-".join(name_parts)
            else:
                continue

            pkg_name = pkg_name_normalize(pkg_name)

            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)

            hashes_by_package[pkg_name].append(sha256.hexdigest())

    with open("requirements.freeze.txt") as f:
        lines = [line.strip() for line in f if line.strip()]

    output_lines = []
    for line in lines:
        pkg_name = pkg_name_normalize(line.split("==")[0])
        hashes = hashes_by_package.get(pkg_name, [])
        if not hashes:
            print(f"Warning: no hashes for {line}", file=sys.stderr)
            output_lines.append(f"{line}\n")
            continue

        lines_for_pkg = [f"{line} \\"]
        for i, h in enumerate(hashes):
            suffix = " \\" if i < len(hashes) - 1 else ""
            lines_for_pkg.append(f"    --hash=sha256:{h}{suffix}")
        output_lines.append("\n".join(lines_for_pkg) + "\n\n")

    with open("requirements.lock.txt", "w") as out:
        out.writelines(output_lines)

    print(f"Generated requirements.lock.txt ({len(lines)} packages)")


if __name__ == "__main__":
    main()
