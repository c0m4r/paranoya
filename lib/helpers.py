"""
Loki (daemonized) lib/helpers.py
https://github.com/c0m4r/Loki-daemonized

Loki (daemonized): Simple IOC and YARA Scanner for Linux®
Copyright (c) 2015-2023 Florian Roth
Copyright (c) 2023-2024 c0m4r

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Linux® is the registered trademark of Linus Torvalds
in the U.S. and other countries.
"""

import hashlib
import os
import re
import string
import sys
import time
import traceback


# Helper Functions -------------------------------------------------------------


def loki_generate_hashes(filedata: bytes) -> tuple[str, str, str]:
    """
    generate hashes
    """
    try:
        md5 = hashlib.md5()  # nosec
        sha1 = hashlib.sha1()  # nosec
        sha256 = hashlib.sha256()  # nosec

        md5.update(filedata)  # nosec
        sha1.update(filedata)  # nosec
        sha256.update(filedata)  # nosec

        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()  # nosec
    except Exception:
        traceback.print_exc()
        return "0", "0", "0"


def loki_get_excluded_mountpoints() -> list[str]:
    """
    get excluded mountpoints
    """
    excludes = []
    try:
        with open("/etc/mtab", "r", encoding="utf-8") as mtab:
            for mpoint in mtab:
                options = mpoint.split(" ")
                if not options[0].startswith("/dev/"):
                    if not options[1] == "/":
                        excludes.append(options[1])
    except Exception:
        print("Error while reading /etc/mtab")
    return excludes


def loki_print_progress(i: int) -> None:
    """
    print progress indicator
    """
    if (i % 4) == 0:
        sys.stdout.write("\b/")
    elif (i % 4) == 1:
        sys.stdout.write("\b-")
    elif (i % 4) == 2:
        sys.stdout.write("\b\\")
    elif (i % 4) == 3:
        sys.stdout.write("\b|")
    sys.stdout.flush()


def loki_transform_os(regex: str) -> str:
    """
    transform os specific characters
    """
    regex = regex.replace(r"\\", r"/")
    regex = regex.replace(r"C:", "")
    return regex


def loki_replace_env_vars(path: str) -> str:
    """
    replace os specific env vars
    """
    # Setting new path to old path for default
    new_path = path

    # ENV VARS ----------------------------------------------------------------
    # Now check if an environment env is included in the path string
    res = re.search(r"([@]?%[A-Za-z_]+%)", path)
    if res:
        env_var_full = res.group(1)
        env_var = env_var_full.replace("%", "").replace("@", "")

        # Check environment variables if there is a matching var
        if env_var in os.environ:
            if os.environ[env_var]:
                new_path = path.replace(env_var_full, re.escape(os.environ[env_var]))

    # TYPICAL REPLACEMENTS ----------------------------------------------------
    if path[:11].lower() == "\\systemroot":
        new_path = path.replace("\\SystemRoot", os.environ["SystemRoot"])

    if path[:8].lower() == "system32":
        envsysroot = os.environ["SystemRoot"]
        new_path = path.replace("system32", f"{envsysroot}\\System32")

    return new_path


def loki_get_file_type(
    file_path: str, filetype_sigs, max_filetype_magics, logger
) -> str:
    """
    get file type
    """
    try:
        # Reading bytes from file
        with open(file_path, "rb", os.O_RDONLY) as f:
            # Reading bytes from file
            res_full = f.read(max_filetype_magics)
            # Checking sigs
            for sig in filetype_sigs:
                bytes_to_read = int(len(str(sig)) / 2)
                res = res_full[:bytes_to_read]
                if res == bytes.fromhex(sig):
                    return str(filetype_sigs[sig])
        return "UNKNOWN"
    except Exception:
        if logger.debug:
            traceback.print_exc()
        return "UNKNOWN"


def loki_remove_non_ascii_drop(s) -> str:
    """
    remove non-ascii
    """
    nonascii = "error"
    try:
        # Generate a new string without disturbing characters
        printable = set(string.printable)
        nonascii = str(filter(lambda x: x in printable, s))
    except Exception:
        traceback.print_exc()
    return nonascii


def loki_get_age(file_path: str) -> tuple[float, float, float]:
    """
    get age
    """
    try:
        stats = os.stat(file_path)

        # Created
        ctime = stats.st_ctime
        # Modified
        mtime = stats.st_mtime
        # Accessed
        atime = stats.st_atime

    except Exception:
        # traceback.print_exc()
        return (0, 0, 0)

    # print "%s %s %s" % ( ctime, mtime, atime )
    return (ctime, mtime, atime)


def loki_get_age_string(file_path: str) -> str:
    """
    get age string
    """
    (ctime, mtime, atime) = loki_get_age(file_path)
    timestring = ""
    try:
        timestring = (
            f"CREATED: {time.ctime(ctime)} "
            f"MODIFIED: {time.ctime(mtime)} "
            f"ACCESSED: {time.ctime(atime)}"
        )
    except Exception:
        timestring = (
            "CREATED: not_available MODIFIED: not_available ACCESSED: not_available"
        )
    return timestring
