#!/usr/bin/env python
"""
paranoya upgrader
https://github.com/c0m4r/paranoya

paranoya: Simple IOC and YARA Scanner for Linux®
Copyright (c) 2015-2023 Florian Roth
Copyright (c) 2023-2026 c0m4r

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

import argparse
import glob
import hashlib
import os
import platform
import re
import stat
import sys
import tempfile

from io import BytesIO
from os.path import exists
from traceback import print_exc as trace
from urllib.parse import urljoin, urlparse
from signal import signal, SIGPIPE, SIG_DFL, SIGTERM, SIGINT
from types import FrameType
from typing import IO, Optional
from zipfile import ZipFile, ZipInfo

# paranoya modules
from lib.paranoya_venv import venv_check

# venv before loading custom modules
venv_check(__file__)

# Custom modules
try:
    import requests
    from colorama import Fore, Style
except Exception as e:
    print(e)
    sys.exit(0)

signal(SIGPIPE, SIG_DFL)

# System
SYSTEM = platform.system()

# Arch
ARCH = platform.machine()

# Cache dir (relative to the application path)
CACHE_DIR = "cache"

# Downloads are only accepted over HTTPS from GitHub
ALLOWED_HOSTS = ("github.com", "api.github.com", "codeload.github.com")
ALLOWED_HOST_SUFFIXES = (".githubusercontent.com",)
MAX_REDIRECTS = 5

# Archive limits (current archives are < 5 MiB, the largest rule file ~20 MiB)
MAX_DOWNLOAD_SIZE = 128 * 1024 * 1024
MAX_MEMBERS = 50_000
MAX_MEMBER_SIZE = 64 * 1024 * 1024
MAX_TOTAL_SIZE = 1024 * 1024 * 1024
MAX_RATIO = 100


def color_chooser(log_type: str) -> str:
    """
    Color selection
    """
    if log_type == "DEBUG":
        color = Fore.MAGENTA
    elif log_type == "ERROR":
        color = Fore.RED
    elif log_type == "INFO":
        color = Fore.CYAN
    else:
        color = ""

    return color


def log(log_type: str, module: str, message: str) -> None:
    """
    Logger
    """
    log_type_colored = color_chooser(log_type) + log_type + Style.RESET_ALL

    print(f"[ {log_type_colored} ]", f"{module}:", message)


class UnsafeDownloadError(Exception):
    """
    Download or archive failed a safety check
    """


def check_url(url: str) -> None:
    """
    Only allow HTTPS downloads from GitHub
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not (
        host in ALLOWED_HOSTS or host.endswith(ALLOWED_HOST_SUFFIXES)
    ):
        raise UnsafeDownloadError(f"refusing to download from {url}")


def safe_download(url: str) -> bytes:
    """
    Download a file from an allowed host (checked on every redirect),
    with a size limit
    """
    for _ in range(MAX_REDIRECTS + 1):
        check_url(url)
        with requests.get(
            url, timeout=30, stream=True, allow_redirects=False
        ) as response:
            if response.is_redirect:
                url = urljoin(url, response.headers["Location"])
                continue
            response.raise_for_status()
            if int(response.headers.get("Content-Length", 0)) > MAX_DOWNLOAD_SIZE:
                raise UnsafeDownloadError(f"{url} is larger than {MAX_DOWNLOAD_SIZE}")
            data = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                data += chunk
                if len(data) > MAX_DOWNLOAD_SIZE:
                    raise UnsafeDownloadError(
                        f"{url} is larger than {MAX_DOWNLOAD_SIZE}"
                    )
            return bytes(data)
    raise UnsafeDownloadError(f"too many redirects for {url}")


def member_path(info: ZipInfo) -> str:
    """
    Validate a ZIP member name and return it as a relative path
    """
    name = info.filename
    parts = name.rstrip("/").split("/")
    if "\\" in name or any(part in ("", ".", "..") for part in parts):
        raise UnsafeDownloadError(f"unsafe path in archive: {name!r}")
    return "/".join(parts)


def is_regular_file(info: ZipInfo) -> bool:
    """
    Skip directories, symlinks, special files and encrypted members
    """
    mode = info.external_attr >> 16
    return (
        not info.is_dir()
        and (not mode or stat.S_ISREG(mode))
        and not info.flag_bits & 0x1
    )


def check_archive(zip_file: ZipFile, members: list[ZipInfo]) -> None:
    """
    Check the whole archive before extracting anything (paths, zip bombs)
    """
    infos = zip_file.infolist()
    if len(infos) > MAX_MEMBERS:
        raise UnsafeDownloadError(f"too many files in archive: {len(infos)}")
    for info in infos:
        member_path(info)
    total = 0
    for info in members:
        if info.file_size > MAX_MEMBER_SIZE:
            raise UnsafeDownloadError(f"file too large: {info.filename}")
        if (
            info.file_size > 1024 * 1024
            and info.file_size > info.compress_size * MAX_RATIO
        ):
            raise UnsafeDownloadError(f"suspicious compression ratio: {info.filename}")
        total += info.file_size
    if total > MAX_TOTAL_SIZE:
        raise UnsafeDownloadError(f"archive too large when extracted: {total}")


def safe_write(base_dir: str, rel_path: str, source: IO[bytes], mode: int) -> None:
    """
    Atomically write a file inside base_dir, refusing to escape it
    (also through symlinked dirs) and replacing symlinks instead of following them
    """
    base = os.path.realpath(base_dir)
    target = os.path.normpath(os.path.join(base, rel_path))
    parent = os.path.dirname(target)
    if target == base or os.path.commonpath([base, os.path.realpath(parent)]) != base:
        raise UnsafeDownloadError(f"{rel_path} escapes {base}")
    os.makedirs(parent, exist_ok=True)
    if os.path.isfile(target) and not os.path.islink(target):
        mode = stat.S_IMODE(os.stat(target).st_mode)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".upgrader-")
    try:
        with os.fdopen(fd, "wb") as target_file:
            written = 0
            while chunk := source.read(65536):
                written += len(chunk)
                if written > MAX_MEMBER_SIZE:
                    raise UnsafeDownloadError(f"file too large: {rel_path}")
                target_file.write(chunk)
        os.chmod(tmp, (mode & 0o755) | 0o644)
        os.replace(tmp, target)
    except BaseException:
        os.unlink(tmp)
        raise


def extract_members(
    zip_file: ZipFile, plan: list[tuple[ZipInfo, str]], base_dir: str, verbose: bool
) -> None:
    """
    Validate the archive, then extract (member, relative target path) pairs
    """
    check_archive(zip_file, [info for info, _ in plan])
    for info, rel_path in plan:
        if verbose:
            log("INFO", "Upgrader", f"Extracting {rel_path} ...")
        with zip_file.open(info) as source:
            safe_write(base_dir, rel_path, source, (info.external_attr >> 16) or 0o644)


def cache_name(sig_url: str) -> str:
    """
    Cache file name for a signature repository URL
    """
    return "_".join(urlparse(sig_url).path.split("/")[:-2]) + ".cache"


def needs_update(sig_url: str, cache_file: str) -> tuple[bool, str]:
    """
    Check if signatures need an update, returns (changed, latest commit sha)
    """
    try:
        o = urlparse(sig_url)
        path = o.path.split("/")
        branch = path[4].split(".")[0]
        url = (
            o.scheme
            + "://api."
            + o.netloc
            + "/repos"
            + "/".join(path[:-2])
            + "/commits/"
            + branch
        )
        response_info = requests.get(url=url, timeout=30)
        sha = str(response_info.json()["sha"])
        if not re.fullmatch("[0-9a-f]{40}", sha):
            return True, ""
    except Exception:
        return True, ""
    if exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as file:
            old_sha = file.read().rstrip()
        return sha != old_sha, sha
    return True, sha


class ParanoyaUpdater:
    """
    paranoya upgrader
    """

    UPDATE_URL_SIGS: list[str] = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip",
    ]

    UPDATE_URL_SIGS_STANDALONE: dict[str, dict[str, str]] = {
        "elastic": {
            "sig_url": "https://github.com/elastic/protections-artifacts/archive/master.zip",
        },
        "PhishingKit": {
            "sig_url": "https://github.com/t4d/PhishingKit-Yara-Rules/archive/master.zip",
        },
        "malpedia": {
            "sig_url": "https://github.com/malpedia/signator-rules/archive/master.zip",
        },
        "Yara Forge": {
            "sig_url": "https://github.com/YARAHQ/yara-forge"
            "/releases/latest/download/yara-forge-rules-full.zip",
        },
    }

    UPDATE_URL_PARANOYA: str = (
        "https://api.github.com/repos/c0m4r/paranoya/releases/latest"
    )

    def __init__(
        self,
        debug: bool,
        application_path: str,
    ) -> None:
        self.debug = debug
        self.application_path = application_path
        self.failed = False
        self.cache_dir = os.path.join(application_path, CACHE_DIR)
        os.makedirs(self.cache_dir, exist_ok=True)

        # Move cache files left by older versions
        for old_cache in glob.glob(
            os.path.join(glob.escape(application_path), "_*.cache")
        ):
            os.replace(
                old_cache, os.path.join(self.cache_dir, os.path.basename(old_cache))
            )

    def fail(self, sig_url: str, error: Exception) -> None:
        """
        Log a failed signature update and carry on with the next one
        """
        self.failed = True
        if self.debug:
            trace()
        log("ERROR", "Upgrader", f"Cannot update signatures from {sig_url}: {error}")

    def make_sigdirs(self, sig_dir: str) -> None:
        """
        Make signatures dirs
        """
        for out_dir in ["", "iocs", "yara", "misc"]:
            full_out_dir = os.path.join(sig_dir, out_dir)
            if not os.path.exists(full_out_dir):
                os.makedirs(full_out_dir)
                log("DEBUG", "makedir", full_out_dir)

    def get_target_file(self, zip_file_path: str, sig_name: str) -> str:
        """
        Get target file, relative to the signature dir
        """
        if "/iocs/" in zip_file_path and zip_file_path.endswith(".txt"):
            target_file = os.path.join("iocs", sig_name)
        elif "/yara/" in zip_file_path and zip_file_path.endswith(".yar"):
            target_file = os.path.join("yara", sig_name)
        elif "/misc/" in zip_file_path and zip_file_path.endswith(".txt"):
            target_file = os.path.join("misc", sig_name)
        elif zip_file_path.endswith(".yara"):
            target_file = os.path.join("yara", sig_name)
        else:
            target_file = ""
        return target_file

    def get_response(self, sig_url: str) -> bytes:
        """
        Download signature archive
        """
        log("INFO", "Upgrader", f"Downloading {sig_url} ...")
        return safe_download(sig_url)

    def extract_signatures(self, data: bytes, debug: bool, sig_dir: str) -> None:
        """
        Extract signatures from zip
        """
        with ZipFile(BytesIO(data)) as zip_update:
            plan = []
            for info in zip_update.infolist():
                if not is_regular_file(info):
                    continue
                zip_file_path = member_path(info)
                sig_name = os.path.basename(zip_file_path)
                target_file = self.get_target_file(zip_file_path, sig_name)
                if target_file:
                    plan.append((info, target_file))

            new_files = [
                target_file
                for _, target_file in plan
                if not os.path.exists(os.path.join(sig_dir, target_file))
            ]
            extract_members(zip_update, plan, sig_dir, debug)

        for target_file in new_files:
            log(
                "INFO",
                "Upgrader",
                f"New signature file: {os.path.basename(target_file)}",
            )

    def update_signatures_base(self, debug: bool, sig_url: str) -> None:
        """
        Update signature rules
        """
        # Downloading current repository
        data = self.get_response(sig_url)

        sig_dir = os.path.join(self.application_path, "signature-base")
        self.make_sigdirs(sig_dir)

        # Read ZIP file and extract
        self.extract_signatures(data, debug, sig_dir)

    def update_signatures(self, force: bool, debug: bool) -> None:
        """
        Update signatures
        """
        if not os.path.exists(os.path.join(self.application_path, "signature-base")):
            for filename in glob.glob(
                os.path.join(glob.escape(self.cache_dir), "_*.cache")
            ):
                os.remove(filename)

        for sig_url in self.UPDATE_URL_SIGS:
            cache_file = os.path.join(self.cache_dir, cache_name(sig_url))
            changed, sha = needs_update(sig_url, cache_file)
            if not changed and not force:
                log("INFO", "Upgrader", f"{sig_url} is up to date.")
                continue
            try:
                self.update_signatures_base(debug, sig_url)
            except Exception as e:
                self.fail(sig_url, e)
                continue
            # Remember the commit only once it has been extracted successfully
            if sha:
                with open(cache_file, "w", encoding="utf-8") as file:
                    file.write(sha)

    def update_standalone_signatures(self, force: bool) -> None:
        """
        update standalone signatures
        """
        out_dir = os.path.join(self.application_path, "signature-custom", "yara")
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
            force = True

        for key, val in self.UPDATE_URL_SIGS_STANDALONE.items():
            sig_name = key
            sig_url = val["sig_url"]

            sig_url_hash = hashlib.md5(sig_url.encode("utf-8")).hexdigest()  # nosec
            sig_name_strip = re.sub("[^A-Za-z0-9]+", "", sig_name)
            cache_file_name = os.path.join(
                self.cache_dir, f"_{sig_name_strip}_{sig_url_hash}.cache"
            )

            if os.path.exists(cache_file_name) and not force:
                log("INFO", "Upgrader", f"{cache_file_name} exists, skipping {sig_url}")
                continue

            log(
                "INFO",
                "Upgrader",
                f"Extracting {sig_name} from {sig_url} to {out_dir}",
            )

            try:
                with ZipFile(BytesIO(safe_download(sig_url))) as zip_update:
                    plan = [
                        (info, member_path(info))
                        for info in zip_update.infolist()
                        if is_regular_file(info)
                        and info.filename.endswith((".yar", ".yara"))
                    ]
                    extract_members(zip_update, plan, out_dir, self.debug)
            except Exception as e:
                self.fail(sig_url, e)
                continue

            with open(cache_file_name, "w", encoding="utf-8") as cache_file:
                cache_file.close()

    def get_paranoya_zip_file_url(self) -> str:
        """
        Get latest paranoya zipfile download url from github api
        """
        response_info = requests.get(url=self.UPDATE_URL_PARANOYA, timeout=30)
        data = response_info.json()
        if "zipball_url" in data:
            return str(data["zipball_url"])
        if "message" in data:
            log("ERROR", "GITHUB", data)
            sys.exit(1)
        return ""

    def download_paranoya(self) -> bytes:
        """
        Download paranoya
        """
        # Downloading the info for latest release
        try:
            log(
                "INFO",
                "Upgrader",
                f"Checking location of latest release {self.UPDATE_URL_PARANOYA} ...",
            )
            # Get download URL
            zip_url = self.get_paranoya_zip_file_url()
            if not zip_url:
                log(
                    "ERROR",
                    "Upgrader",
                    "Error downloading the paranoya update - check your Internet connection",
                )
                sys.exit(1)
            else:
                log("INFO", "Upgrader", f"Downloading latest release {zip_url} ...")
                return safe_download(zip_url)
        except UnsafeDownloadError as e:
            log("ERROR", "Upgrader", f"Rejected paranoya update: {e}")
            sys.exit(1)
        except Exception:
            if self.debug:
                trace()
            log(
                "ERROR",
                "Upgrader",
                "Error downloading the paranoya update - check your Internet connection",
            )
            sys.exit(1)

    def extract_paranoya(self, data: bytes) -> None:
        """
        Extract paranoya
        """
        # Read ZIP file
        try:
            with ZipFile(BytesIO(data)) as zip_update:
                plan = []
                for info in zip_update.infolist():
                    if not is_regular_file(info):
                        continue
                    zip_file_path = member_path(info)
                    if "/config/" in zip_file_path:
                        continue
                    # Strip the top level dir of the GitHub zipball
                    target_file = "/".join(zip_file_path.split("/")[1:])
                    if target_file:
                        plan.append((info, target_file))

                extract_members(zip_update, plan, self.application_path, True)

        except UnsafeDownloadError as e:
            log("ERROR", "Upgrader", f"Rejected paranoya update: {e}")
            sys.exit(1)
        except Exception:
            if self.debug:
                trace()
            log(
                "ERROR",
                "Upgrader",
                "Error while extracting the signature files from the download package",
            )
            sys.exit(1)

    def update_paranoya(self) -> bool:
        """
        Update paranoya
        """
        try:
            self.extract_paranoya(self.download_paranoya())
        except Exception:
            if self.debug:
                trace()
            return False
        return True


def get_application_path() -> str:
    """
    Get application path
    """
    try:
        if getattr(sys, "frozen", False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        return application_path
    except Exception:
        print("Error while evaluation of application path")
        trace()
        return ""


def sig_handler(signal_name: int, frame: Optional[FrameType]) -> None:
    """
    signal handler
    """
    print("Upgrade process interrupted, exiting.")
    print(signal_name, frame)
    sys.exit(0)


if __name__ == "__main__":
    # Signal handlers
    signal(SIGINT, sig_handler)
    signal(SIGTERM, sig_handler)

    # Parse Arguments
    parser = argparse.ArgumentParser(description="paranoya upgrader")
    parser.add_argument(
        "--sigsonly",
        action="store_true",
        help="Update the signatures only",
        default=False,
    )
    parser.add_argument(
        "--progonly",
        action="store_true",
        help="Update the program files only",
        default=False,
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Debug output"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Force signature update",
    )
    parser.add_argument(
        "--detached", action="store_true", default=False, help=argparse.SUPPRESS
    )

    args = parser.parse_args()

    # Update paranoya
    updater = ParanoyaUpdater(args.debug, get_application_path())

    if not args.sigsonly:
        log("INFO", "Upgrader", "Updating paranoya ...")
        updater.update_paranoya()
    if not args.progonly:
        log("INFO", "Upgrader", "Updating Signatures ...")
        updater.update_signatures(args.force, args.debug)
        updater.update_standalone_signatures(args.force)

    if updater.failed:
        log("ERROR", "Upgrader", "Update finished with errors")
        sys.exit(1)

    log("INFO", "Upgrader", "Update complete")

    if args.detached:
        log("INFO", "Upgrader", "Press any key to return ...")

# EOF
