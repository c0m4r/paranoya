#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-

"""
Loki (daemonized): Simple IOC and YARA Scanner
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
"""

import hashlib
import os
import re
import string
import sys
import time
import traceback

# Helper Functions -------------------------------------------------------------


def generateHashes(filedata):
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        md5.update(filedata)
        sha1.update(filedata)
        sha256.update(filedata)
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    except Exception:
        traceback.print_exc()
        return 0, 0, 0


def getExcludedMountpoints():
    excludes = []
    try:
        mtab = open("/etc/mtab", "r")
        for mpoint in mtab:
            options = mpoint.split(" ")
            if not options[0].startswith("/dev/"):
                if not options[1] == "/":
                    excludes.append(options[1])
    except Exception:
        print("Error while reading /etc/mtab")
    finally:
        mtab.close()
    return excludes


def printProgress(i):
    if (i % 4) == 0:
        sys.stdout.write("\b/")
    elif (i % 4) == 1:
        sys.stdout.write("\b-")
    elif (i % 4) == 2:
        sys.stdout.write("\b\\")
    elif (i % 4) == 3:
        sys.stdout.write("\b|")
    sys.stdout.flush()


def transformOS(regex):
    regex = regex.replace(r"\\", r"/")
    regex = regex.replace(r"C:", "")
    return regex


def replaceEnvVars(path):
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
        new_path = path.replace("system32", "%s\\System32" % os.environ["SystemRoot"])

    return new_path


def get_file_type(filePath, filetype_sigs, max_filetype_magics, logger):
    try:
        # Reading bytes from file
        res_full = open(filePath, "rb", os.O_RDONLY).read(max_filetype_magics)
        # Checking sigs
        for sig in filetype_sigs:
            bytes_to_read = int(len(str(sig)) / 2)
            res = res_full[:bytes_to_read]
            if res == bytes.fromhex(sig):
                return filetype_sigs[sig]
        return "UNKNOWN"
    except Exception:
        if logger.debug:
            traceback.print_exc()
        return "UNKNOWN"


def removeNonAscii(s, stripit=False):
    nonascii = "error"
    try:
        try:
            printable = set(string.printable)
            filtered_string = filter(lambda x: x in printable, s.decode("utf-8"))
            nonascii = "".join(filtered_string)
        except Exception:
            traceback.print_exc()
            nonascii = s.hex()
    except Exception:
        traceback.print_exc()
        pass
    return nonascii


def removeNonAsciiDrop(s):
    nonascii = "error"
    try:
        # Generate a new string without disturbing characters
        printable = set(string.printable)
        nonascii = filter(lambda x: x in printable, s)
    except Exception:
        traceback.print_exc()
        pass
    return nonascii


def getAge(filePath):
    try:
        stats = os.stat(filePath)

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


def getAgeString(filePath):
    (ctime, mtime, atime) = getAge(filePath)
    timestring = ""
    try:
        timestring = "CREATED: %s MODIFIED: %s ACCESSED: %s" % (
            time.ctime(ctime),
            time.ctime(mtime),
            time.ctime(atime),
        )
    except Exception:
        timestring = (
            "CREATED: not_available MODIFIED: not_available ACCESSED: not_available"
        )
    return timestring


def getHostname(os_platform):
    """
    Generate and return a hostname
    :return:
    """
    # Computername
    if os_platform == "linux" or os_platform == "macos":
        return os.uname()[1]
    else:
        return os.environ["COMPUTERNAME"]
