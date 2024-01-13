#!/usr/bin/env python
"""
Loki (daemonized)
https://github.com/c0m4r/Loki-daemonized

Loki (daemonized): Simple IOC and YARA Scanner for Linux
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

import codecs
import datetime
import ipaddress
import os
import platform
import re
import socket
import stat
import sys
import threading
import traceback
import signal

from bisect import bisect_left
from collections import Counter
from subprocess import Popen, PIPE, run

# LOKI modules
from lib.lokiargs import parser
from lib.lokilogger import LokiLogger, get_syslog_timestamp
from lib.helpers import (
    loki_generate_hashes,
    loki_get_excluded_mountpoints,
    loki_print_progress,
    loki_transform_os,
    loki_replace_env_vars,
    loki_get_file_type,
    loki_remove_non_ascii_drop,
    loki_get_age_string,
)

from lib.constants import (
    EVIL_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    SCRIPT_TYPES,
    HASH_WHITELIST,
)

from lib.lokivenv import venv_check

# venv before loading custom modules
venv_check(__file__)

# Custom modules
try:
    import psutil
    import yara
    import progressbar
except Exception as e:
    print(e)
    sys.exit(0)


def ioc_contains(sorted_list, value):
    """
    returns true if sorted_list contains value
    """
    index = bisect_left(sorted_list, value)
    return index != len(sorted_list) and sorted_list[index] == value


class Loki:
    """
    Loki
    """

    # Signatures
    yara_rules = []
    filename_iocs = []
    hashes_md5 = {}
    hashes_sha1 = {}
    hashes_sha256 = {}
    hashes_scores = {}
    false_hashes = {}
    c2_server = {}

    # Yara rule directories
    yara_rule_directories = []

    # Excludes (list of regex that match within the whole path) (user-defined via excludes.cfg)
    full_excludes = []
    # Platform specific excludes (match the beginning of the full path) (not user-defined)
    start_excludes = []
    # Excludes hash (md5, sha1 and sha256)
    excludes_hash = []

    # File type magics
    filetype_magics = {}
    max_filetype_magics = 0

    bar_iter = 0
    bar_iter_max = 10000

    def __init__(self, intense_mode):
        # Scan Mode
        self.intense_mode = intense_mode

        # Get application path
        self.app_path = get_application_path()

        # Check if signature database is present
        sig_dir = os.path.join(self.app_path, "signature-base")
        if not os.path.exists(sig_dir) or os.listdir(sig_dir) == []:
            logger.log(
                "NOTICE",
                "Init",
                "The 'signature-base' subdirectory doesn't exist or is empty. "
                "Trying to retrieve the signature database automatically.",
            )
            update_loki(sigs_only=True)

        # Excludes
        self.initialize_excludes(
            os.path.join(self.app_path, "config/excludes.cfg".replace("/", os.sep))
        )

        # Static excludes
        if not args.force:
            linux_path_skips_start = set(
                [
                    "/proc",
                    "/dev",
                    "/sys/kernel/debug",
                    "/sys/kernel/slab",
                    "/sys/devices",
                    "/usr/src/linux",
                ]
            )
            if args.alldrives:
                self.start_excludes = linux_path_skips_start
            else:
                self.start_excludes = (
                    linux_path_skips_start
                    | set(["/media", "/volumes"])
                    | set(loki_get_excluded_mountpoints())
                )

        # Set IOC path
        self.ioc_path = os.path.join(
            self.app_path, "signature-base/iocs/".replace("/", os.sep)
        )

        # Yara rule directories
        self.yara_rule_directories.append(
            os.path.join(self.app_path, "signature-base/yara".replace("/", os.sep))
        )
        self.yara_rule_directories.append(
            os.path.join(self.app_path, "signature-base/iocs/yara".replace("/", os.sep))
        )
        self.yara_rule_directories.append(
            os.path.join(self.app_path, "signature-base/3rdparty".replace("/", os.sep))
        )

        # Read IOCs -------------------------------------------------------
        # File Name IOCs (all files in iocs that contain 'filename')
        self.initialize_filename_iocs(self.ioc_path)
        logger.log(
            "INFO",
            "Init",
            f"File Name Characteristics initialized with {len(self.filename_iocs)} regex patterns",
        )

        # C2 based IOCs (all files in iocs that contain 'c2')
        self.initialize_c2_iocs(self.ioc_path)
        logger.log(
            "INFO",
            "Init",
            f"C2 server indicators initialized with {len(self.c2_server.keys())} elements",
        )

        # Hash based IOCs (all files in iocs that contain 'hash')
        self.initialize_hash_iocs(self.ioc_path)
        logger.log(
            "INFO",
            "Init",
            f"Malicious MD5 Hashes initialized with {len(self.hashes_md5.keys())} hashes",
        )
        logger.log(
            "INFO",
            "Init",
            f"Malicious SHA1 Hashes initialized with {len(self.hashes_sha1.keys())} hashes",
        )
        logger.log(
            "INFO",
            "Init",
            f"Malicious SHA256 Hashes initialized with {len(self.hashes_sha256.keys())} hashes",
        )

        # Hash based False Positives (all files in iocs that contain 'hash' and 'falsepositive')
        self.initialize_hash_iocs(self.ioc_path, false_positive=True)
        logger.log(
            "INFO",
            "Init",
            f"False Positive Hashes initialized with {len(self.false_hashes.keys())} hashes",
        )

        # Compile Yara Rules
        self.initialize_yara_rules()

        # Initialize File Type Magic signatures
        self.initialize_filetype_magics(
            os.path.join(
                self.app_path,
                "signature-base/misc/file-type-signatures.txt".replace("/", os.sep),
            )
        )

    def file_list_gen(self, path):
        """
        file list gen
        """
        matches = []
        flg_iter = 0
        logger.log("INFO", "Init", "Processing files to scan, this might take a while.")
        for root, _, filenames in os.walk(path, followlinks=False):
            for filename in filenames:
                matches.append(os.path.join(root, filename))
                flg_iter += 1
                if flg_iter > self.bar_iter_max:
                    logger.log(
                        "INFO",
                        "Init",
                        "File list too large, progress will be unavailable",
                    )
                    return matches
        logger.log("INFO", "Init", "Processing done")
        return matches

    def scan_path(self, path):
        """
        scan path
        """
        if os.path.isfile(path):
            root = ""
            directories = ""
            files = [path]
            loki.scan_path_files(root, directories, files)
            return

        if args.progress and not args.silent and not args.noindicator:
            files_all = self.file_list_gen(path)
            files_all_len = len(files_all)

        # Check if path exists
        if not os.path.exists(path):
            logger.log("ERROR", "FileScan", f"None Existing Scanning Path {path} ...  ")
            return

        # Startup
        logger.log("INFO", "FileScan", f"Scanning Path {path} ...  ")
        # Platform specific excludes
        for skip in self.start_excludes:
            if path.startswith(skip):
                logger.log(
                    "INFO",
                    "FileScan",
                    f"Skipping {skip} directory [fixed excludes] (try using --force or --alldrives)",
                )
                return

        if args.progress and not args.silent and not args.noindicator:
            if files_all_len <= self.bar_iter_max:
                progress_bar = progressbar.ProgressBar(
                    max_value=files_all_len, redirect_stdout=True
                )
            else:
                progress_bar = progressbar.ProgressBar(
                    max_value=progressbar.UnknownLength, redirect_stdout=True
                )
        else:
            progress_bar = None

        for root, directories, files in os.walk(
            path, onerror=walk_error, followlinks=False
        ):
            # Skip paths that start with ..
            new_directories = []
            for dirname in directories:
                skip_it = False

                # Generate a complete path for comparisons
                complete_path = os.path.join(root, dirname).lower() + os.sep

                # Platform specific excludes
                for skip in self.start_excludes:
                    if complete_path.startswith(skip):
                        logger.log(
                            "INFO",
                            "FileScan",
                            f"Skipping {skip} directory [fixed excludes] "
                            "(try using --force or --alldrives)",
                        )
                        skip_it = True

                if not skip_it:
                    new_directories.append(dirname)
            directories[:] = new_directories

            loki.scan_path_files(root, directories, files, progress_bar)

    def perform_intense_check(
        self,
        file_path,
        file_type,
        file_name_cleaned,
        file_path_cleaned,
        extension,
        reasons,
        total_score,
    ):
        """
        Perform intense check
        """
        # Hash Check -------------------------------------------------------
        # Do the check
        file_data = self.get_file_data(file_path)

        # First bytes
        first_bytes_string = "%s / %s" % (
            file_data[:20].hex(),
            loki_remove_non_ascii_drop(file_data[:20]),
        )

        # Hash Eval
        match_type = None
        match_desc = None
        match_hash = None
        md5 = 0
        sha1 = 0
        sha256 = 0

        md5, sha1, sha256 = loki_generate_hashes(file_data)
        md5_num = int(md5, 16)
        sha1_num = int(sha1, 16)
        sha256_num = int(sha256, 16)

        # False Positive Hash
        if (
            md5_num in self.false_hashes.keys()
            or sha1_num in self.false_hashes.keys()
            or sha256_num in self.false_hashes.keys()
        ):
            return False, None, None, None, None, None

        # Skip exclude hash
        if (
            md5 in self.excludes_hash
            or sha1 in self.excludes_hash
            or sha256 in self.excludes_hash
        ):
            logger.log(
                "DEBUG",
                "FileScan",
                f"Skipping element {file_path} excluded by hash",
            )
            return False, None, None, None, None, None

        # Malware Hash
        match_score = 100
        match_level = "Malware"
        if ioc_contains(self.hashes_md5_list, md5_num):
            match_type = "MD5"
            match_desc = self.hashes_md5[md5_num]
            match_hash = md5
            match_score = self.hashes_scores[md5_num]
        if ioc_contains(self.hashes_sha1_list, sha1_num):
            match_type = "SHA1"
            match_desc = self.hashes_sha1[sha1_num]
            match_hash = sha1
            match_score = self.hashes_scores[sha1_num]
        if ioc_contains(self.hashes_sha256_list, sha256_num):
            match_type = "SHA256"
            match_desc = self.hashes_sha256[sha256_num]
            match_hash = sha256
            match_score = self.hashes_scores[sha256_num]

        # If score is low change the description
        if match_score < 80:
            match_level = "Suspicious"

        # Hash string
        hash_string = f"MD5: {md5} SHA1: {sha1} SHA256: {sha256}"

        if match_type:
            reasons.append(
                "%s Hash TYPE: %s HASH: %s SUBSCORE: %d DESC: %s"
                % (
                    match_level,
                    match_type,
                    match_hash,
                    match_score,
                    match_desc,
                )
            )
            total_score += match_score

        # Script Anomalies Check
        if args.scriptanalysis:
            if extension in SCRIPT_EXTENSIONS or type in SCRIPT_TYPES:
                logger.log(
                    "DEBUG",
                    "FileScan",
                    f"Performing character analysis on file {file_path} ... ",
                )
                message, score = self.script_stats_analysis(file_data)
                if message:
                    reasons.append("%s SCORE: %s" % (message, score))
                    total_score += score

        # Yara Check -------------------------------------------------------

        # Memory Dump Scan
        if file_type == "MDMP":
            logger.log(
                "INFO",
                "FileScan",
                "Scanning memory dump file %s" % file_name_cleaned.decode("utf-8"),
            )

        # Scan the read data
        try:
            for (
                score,
                rule,
                description,
                reference,
                matched_strings,
                author,
            ) in self.scan_data(
                file_data=file_data,
                file_type=file_type,
                file_name=file_name_cleaned,
                file_path=file_path_cleaned,
                extension=extension,
                md5=md5,  # legacy rule support
            ):
                # Message
                message = (
                    "Yara Rule MATCH: %s SUBSCORE: %s "
                    "DESCRIPTION: %s REF: %s AUTHOR: %s"
                    % (rule, score, description, reference, author)
                )
                # Matches
                if len(matched_strings) > 0:
                    message += " MATCHES: %s" % ", ".join(matched_strings)

                total_score += score
                reasons.append(message)

            return (
                True,
                file_data,
                total_score,
                first_bytes_string,
                hash_string,
                reasons,
            )

        except Exception:
            if logger.debug:
                traceback.print_exc()
            logger.log(
                "ERROR",
                "FileScan",
                f"Cannot YARA scan file: {file_path_cleaned}",
            )

    def scan_path_files(self, root, directories, files, progress_bar=None):
        """
        scan path files
        """
        # Counter
        c = 0

        # Loop through files
        for filename in files:
            try:
                if args.progress and not args.silent and not args.noindicator:
                    self.bar_iter += 1
                    progress_bar.update(self.bar_iter)
                # Findings
                reasons = []
                # Total Score
                total_score = 0

                # Get the file and path
                file_path = os.path.join(root, filename)
                fpath = os.path.split(file_path)[0]
                # Clean the values for YARA matching
                # > due to errors when Unicode characters are passed to the match function as
                #   external variables
                file_path_cleaned = fpath.encode("ascii", errors="replace")
                file_name_cleaned = filename.encode("ascii", errors="replace")

                # Get Extension
                extension = os.path.splitext(file_path)[1].lower()

                # Skip marker
                skip_it = False

                # User defined excludes
                for skip in self.full_excludes:
                    if skip.search(file_path):
                        logger.log("DEBUG", "FileScan", f"Skipping element {file_path}")
                        skip_it = True

                # File mode
                try:
                    mode = os.stat(file_path).st_mode
                    if (
                        stat.S_ISCHR(mode)
                        or stat.S_ISBLK(mode)
                        or stat.S_ISFIFO(mode)
                        or stat.S_ISLNK(mode)
                        or stat.S_ISSOCK(mode)
                    ):
                        continue
                except Exception:
                    logger.log(
                        "DEBUG",
                        "FileScan",
                        f"Skipping element {file_path} does not exist or is a broken symlink",
                    )
                    continue

                # Skip
                if skip_it:
                    continue

                # Counter
                c += 1

                if not args.noindicator:
                    loki_print_progress(c)

                # Skip program directory
                if self.app_path.lower() in file_path.lower():
                    logger.log(
                        "DEBUG",
                        "FileScan",
                        f"Skipping file in program directory FILE: {file_path_cleaned}",
                    )
                    continue

                file_size = os.stat(file_path).st_size
                # print file_size

                # File Name Checks -------------------------------------------------
                for fioc in self.filename_iocs:
                    match = fioc["regex"].search(file_path)
                    if match:
                        # Check for False Positive
                        if fioc["regex_fp"]:
                            match_fp = fioc["regex_fp"].search(file_path)
                            if match_fp:
                                continue
                        # Create Reason
                        reasons.append(
                            "File Name IOC matched PATTERN: %s SUBSCORE: %s DESC: %s"
                            % (
                                fioc["regex"].pattern,
                                fioc["score"],
                                fioc["description"],
                            )
                        )
                        total_score += int(fioc["score"])

                # Access check (also used for magic header detection)
                first_bytes_string = b"-"
                hash_string = ""

                # Evaluate Type
                file_type = loki_get_file_type(
                    file_path, self.filetype_magics, self.max_filetype_magics, logger
                )

                # Fast Scan Mode - non intense
                do_intense_check = True
                if (
                    not self.intense_mode
                    and file_type == "UNKNOWN"
                    and extension not in EVIL_EXTENSIONS
                ):
                    if args.printall:
                        logger.log(
                            "INFO",
                            "FileScan",
                            f"Skipping file due to fast scan mode: {file_name_cleaned}",
                        )
                    do_intense_check = False

                # Set file_data to an empty value
                file_data = ""

                print_filesize_info = False

                # Evaluations -------------------------------------------------------
                # Evaluate size
                file_size_limit = int(args.s) * 1024
                if file_size > file_size_limit:
                    # Print files
                    do_intense_check = False
                    print_filesize_info = True

                # Some file types will force intense check
                if file_type == "MDMP":
                    do_intense_check = True
                    print_filesize_info = False

                # Intense Check switch
                if do_intense_check and args.printall:
                    logger.log(
                        "INFO",
                        "FileScan",
                        f"Scanning {file_name_cleaned} TYPE: {file_type} SIZE: {file_size}",
                    )
                elif args.printall:
                    logger.log(
                        "INFO",
                        "FileScan",
                        f"Checking {file_name_cleaned} TYPE: {file_type} SIZE: {file_size}",
                    )

                if print_filesize_info and args.printall:
                    logger.log(
                        "INFO",
                        "FileScan",
                        "Skipping file due to file size: %s TYPE: %s SIZE: %s "
                        "CURRENT SIZE LIMIT(kilobytes): %d"
                        % (file_name_cleaned, file_type, file_size, file_size_limit),
                    )

                if do_intense_check:
                    (
                        proceed,
                        file_data,
                        total_score,
                        first_bytes_string,
                        hash_string,
                        reasons,
                    ) = self.perform_intense_check(
                        file_path,
                        file_type,
                        file_name_cleaned,
                        file_path_cleaned,
                        extension,
                        reasons,
                        total_score,
                    )

                    if not proceed:
                        continue

                # Info Line -----------------------------------------------------------------------
                file_info = (
                    "FILE: %s SCORE: %s TYPE: %s SIZE: %s FIRST_BYTES: %s %s %s "
                    % (
                        file_path,
                        total_score,
                        file_type,
                        file_size,
                        first_bytes_string,
                        hash_string,
                        loki_get_age_string(file_path),
                    )
                )

                # Now print the total result
                if total_score >= args.a:
                    message_type = "ALERT"
                    threading.current_thread().message = "ALERT"
                elif total_score >= args.w:
                    message_type = "WARNING"
                    threading.current_thread().message = "WARNING"
                elif total_score >= args.n:
                    message_type = "NOTICE"
                    threading.current_thread().message = "NOTICE"

                if total_score < args.n:
                    continue

                # Reasons to message body
                message_body = file_info
                for i, r in enumerate(reasons):
                    if i < 2 or args.allreasons:
                        message_body += "REASON_{0}: {1}".format(i + 1, r)

                logger.log(message_type, "FileScan", message_body)

            except Exception:
                if logger.debug:
                    traceback.print_exc()
                    sys.exit(1)

    def yara_externals(
        self,
        dummy,
        file_name=b"-",
        file_path=b"-",
        extension=b"-",
        file_type="-",
        md5="-",
    ):
        """
        yara externals
        """
        if dummy is True:
            return {
                "filename": "dummy",
                "filepath": "dummy",
                "extension": "dummy",
                "filetype": "dummy",
                "md5": "dummy",
                "owner": "dummy",
            }
        else:
            return {
                "filename": file_name,
                "filepath": file_path,
                "extension": extension,
                "filetype": file_type,
                "md5": md5,
                "owner": "dummy",
            }

    def scan_data(
        self,
        file_data,
        file_type="-",
        file_name=b"-",
        file_path=b"-",
        extension=b"-",
        md5="-",
    ):
        """
        scan data
        """
        # Scan with yara
        try:
            for rules in self.yara_rules:
                # Yara Rule Match
                externals = self.yara_externals(
                    False,
                    file_name.decode("utf-8"),
                    file_path.decode("utf-8"),
                    extension,
                    file_type,
                    md5,
                )
                matches = rules.match(
                    data=file_data,
                    externals=externals,
                )

                # If matched
                if matches:
                    for match in matches:
                        score = 70
                        description = "not set"
                        reference = "-"
                        author = "-"

                        # Built-in rules have meta fields (cannot be expected from custom rules)
                        if hasattr(match, "meta"):
                            if "description" in match.meta:
                                description = match.meta["description"]
                            if "cluster" in match.meta:
                                description = "IceWater Cluster {0}".format(
                                    match.meta["cluster"]
                                )

                            if "reference" in match.meta:
                                reference = match.meta["reference"]
                            if "viz_url" in match.meta:
                                reference = match.meta["viz_url"]
                            if "author" in match.meta:
                                author = match.meta["author"]

                            # If a score is given
                            if "score" in match.meta:
                                score = int(match.meta["score"])

                        # Matching strings
                        matched_strings = []
                        if hasattr(match, "strings"):
                            # Get matching strings
                            matched_strings = self.get_string_matches(match.strings)

                        yield score, match.rule, description, reference, matched_strings, author

        except Exception:
            if logger.debug:
                traceback.print_exc()

    def get_string_matches(self, strings):
        """
        get string matches
        """
        try:
            matching_strings = []
            for string in strings:
                # Limit string
                string_value = str(string.instances[0]).replace("'", "\\")
                if len(string_value) > 140:
                    string_value = string_value[:140] + " ... (truncated)"
                matching_strings.append(
                    "{0}: '{1}'".format(string.identifier, string_value)
                )
            return matching_strings
        except Exception:
            traceback.print_exc()

    def scan_processes_linux(self):
        """
        scan processes linux
        """
        processes = psutil.pids()

        for process in processes:
            # Gather Process Information -------------------------------------
            pid = process
            try:
                name = psutil.Process(process).name()
            except psutil.NoSuchProcess:
                logger.log(
                    "DEBUG",
                    "ProcessScan",
                    f"Skipping Process PID: {str(pid)} as it just exited and no longer exists",
                )
                continue
            owner = psutil.Process(process).username()
            status = psutil.Process(process).status()
            try:
                cmd = " ".join(psutil.Process(process).cmdline())
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                logger.log(
                    "WARNING",
                    "ProcessScan",
                    f"Process PID: {str(pid)} NAME: {name} STATUS: {status}",
                )
                continue
            path = psutil.Process(process).cwd()
            bin = psutil.Process(process).exe()
            tty = psutil.Process(process).terminal()

            process_info = (
                "PID: %s NAME: %s OWNER: %s STATUS: %s BIN: %s CMD: %s PATH: %s TTY: %s"
                % (str(pid), name, owner, status, bin, cmd.strip(), path, tty)
            )

            # Print info -------------------------------------------------------
            logger.log("INFO", "ProcessScan", f"Process {process_info}")

            # Process Masquerading Detection -----------------------------------

            if re.search(r"\[", cmd):
                maps = "/proc/%s/maps" % str(pid)
                maps = run(["/bin/cat", maps], encoding="utf-8", stdout=PIPE)
                if maps.stdout.strip():
                    logger.log(
                        "WARNING",
                        "ProcessScan",
                        "Potential Process Masquerading PID: %s CMD: %s Check /proc/%s/maps"
                        % (str(pid), cmd, str(pid)),
                    )

            # File Name Checks -------------------------------------------------
            for fioc in self.filename_iocs:
                match = fioc["regex"].search(cmd)
                if match:
                    if int(fioc["score"]) > 70:
                        logger.log(
                            "ALERT",
                            "ProcessScan",
                            "File Name IOC matched PATTERN: %s DESC: %s MATCH: %s"
                            % (fioc["regex"].pattern, fioc["description"], cmd),
                        )
                    elif int(fioc["score"]) > 40:
                        logger.log(
                            "WARNING",
                            "ProcessScan",
                            "File Name Suspicious IOC matched PATTERN: %s DESC: %s MATCH: %s"
                            % (fioc["regex"].pattern, fioc["description"], cmd),
                        )

            # Process connections ----------------------------------------------
            if not args.nolisten:
                connections = psutil.Process(pid).connections()
                conn_count = 0
                conn_limit = 20
                for pconn in connections:
                    conn_count += 1
                    if conn_count > conn_limit:
                        logger.log(
                            "NOTICE",
                            "ProcessScan",
                            "Process PID: %s NAME: %s More connections detected. Showing only %s"
                            % (str(pid), name, conn_limit),
                        )
                        break
                    ip = pconn.laddr.ip
                    status = pconn.status
                    ext = pconn.raddr
                    if ext:
                        ext_ip = pconn.raddr.ip
                        ext_port = pconn.raddr.port
                        logger.log(
                            "NOTICE",
                            "ProcessScan",
                            "Process PID: %s NAME: %s CONNECTION: %s <=> %s %s (%s)"
                            % (str(pid), name, ip, ext_ip, ext_port, status),
                        )
                    else:
                        logger.log(
                            "NOTICE",
                            "ProcessScan",
                            "Process PID: %s NAME: %s CONNECTION: %s (%s)"
                            % (str(pid), name, ip, status),
                        )

    def check_process_connections(self, process):
        """
        check process connections
        """
        try:
            # Limits
            max_connections = 20

            # Counter
            connection_count = 0

            # Pid from process
            pid = process.ProcessId
            name = process.Name

            # Get psutil info about the process
            try:
                p = psutil.Process(pid)
            except Exception:
                if logger.debug:
                    traceback.print_exc()
                return

            # print "Checking connections of %s" % process.Name
            for x in p.connections():
                # Evaluate a usable command line to check
                try:
                    command = process.CommandLine
                except Exception:
                    command = p.cmdline()

                if x.status == "LISTEN":
                    connection_count += 1
                    logger.log(
                        "NOTICE",
                        "ProcessScan",
                        "Listening process PID: %s NAME: %s COMMAND: %s IP: %s PORT: %s"
                        % (str(pid), name, command, str(x.laddr[0]), str(x.laddr[1])),
                    )
                    if str(x.laddr[1]) == "0":
                        logger.log(
                            "WARNING",
                            "ProcessScan",
                            "Listening on Port 0 PID: %s NAME: %s COMMAND: %s  IP: %s PORT: %s"
                            % (
                                str(pid),
                                name,
                                command,
                                str(x.laddr[0]),
                                str(x.laddr[1]),
                            ),
                        )

                if x.status == "ESTABLISHED":
                    # Check keyword in remote address
                    is_match, description = self.check_c2(str(x.raddr[0]))
                    if is_match:
                        logger.log(
                            "ALERT",
                            "ProcessScan",
                            "Malware Domain/IP match in remote address PID: "
                            "%s NAME: %s COMMAND: %s IP: %s PORT: %s DESC: %s"
                            % (
                                str(pid),
                                name,
                                command,
                                str(x.raddr[0]),
                                str(x.raddr[1]),
                                description,
                            ),
                        )

                    # Full list
                    connection_count += 1
                    logger.log(
                        "NOTICE",
                        "ProcessScan",
                        "Established connection PID: %s NAME: %s COMMAND: %s "
                        "LIP: %s LPORT: %s RIP: %s RPORT: %s"
                        % (
                            str(pid),
                            name,
                            command,
                            str(x.laddr[0]),
                            str(x.laddr[1]),
                            str(x.raddr[0]),
                            str(x.raddr[1]),
                        ),
                    )

                # Maximum connection output
                if connection_count > max_connections:
                    logger.log(
                        "NOTICE",
                        "ProcessScan",
                        "Connection output threshold reached. Output truncated.",
                    )
                    return

        except Exception:
            if args.debug:
                traceback.print_exc()
                sys.exit(1)
            logger.log(
                "INFO",
                "ProcessScan",
                f"Process {str(pid)} does not exist anymore or cannot be accessed",
            )

    def check_c2(self, remote_system):
        """
        check c2
        """
        # IP - exact match
        if ipaddress.ip_address(remote_system):
            for c2 in self.c2_server:
                # if C2 definition is CIDR network
                if ipaddress.ip_network(c2):
                    if ipaddress.ip_address(remote_system) in ipaddress.ip_network(c2):
                        return True, self.c2_server[c2]
                # if C2 is ip or else
                if c2 == remote_system:
                    return True, self.c2_server[c2]
        # Domain - remote system contains c2
        # e.g. evildomain.com and dga1.evildomain.com
        else:
            for c2 in self.c2_server:
                if c2 in remote_system:
                    return True, self.c2_server[c2]

        return False, ""

    def initialize_c2_iocs(self, ioc_directory):
        """
        initialize c2 iocs
        """
        try:
            for ioc_filename in os.listdir(ioc_directory):
                try:
                    if "c2" in ioc_filename:
                        with codecs.open(
                            os.path.join(ioc_directory, ioc_filename),
                            "r",
                            encoding="utf-8",
                        ) as file:
                            lines = file.readlines()

                            # Last Comment Line
                            last_comment = ""

                            for line in lines:
                                try:
                                    # Comments and empty lines
                                    if re.search(r"^#", line) or re.search(
                                        r"^[\s]*$", line
                                    ):
                                        last_comment = (
                                            line.lstrip("#").lstrip(" ").rstrip("\n")
                                        )
                                        continue

                                    # Split the IOC line
                                    if ";" in line:
                                        line = line.rstrip(" ").rstrip("\n\r")
                                        row = line.split(";")
                                        c2 = row[0]

                                        # Elements without description
                                    else:
                                        c2 = line

                                    # Check length
                                    if len(c2) < 4:
                                        logger.log(
                                            "NOTICE",
                                            "Init",
                                            "C2 server definition is "
                                            "suspiciously short - will not add %s" % c2,
                                        )
                                        continue

                                    # Add to the LOKI iocs
                                    self.c2_server[c2.lower()] = last_comment

                                except Exception:
                                    logger.log(
                                        "ERROR", "Init", f"Cannot read line: {line}"
                                    )
                                    if logger.debug:
                                        sys.exit(1)
                except OSError:
                    logger.log("ERROR", "Init", "No such file or directory")
        except Exception:
            traceback.print_exc()
            logger.log("ERROR", "Init", f"Error reading Hash file: {ioc_filename}")

    def initialize_filename_iocs(self, ioc_directory):
        """
        initialize_filename_iocs
        """
        try:
            for ioc_filename in os.listdir(ioc_directory):
                if "filename" in ioc_filename:
                    with codecs.open(
                        os.path.join(ioc_directory, ioc_filename), "r", encoding="utf-8"
                    ) as file:
                        lines = file.readlines()

                        # Last Comment Line
                        last_comment = ""
                        # Initialize score variable
                        score = 0
                        # Initialize empty description
                        desc = ""

                        for line in lines:
                            try:
                                # Empty
                                if re.search(r"^[\s]*$", line):
                                    continue

                                # Comments
                                if re.search(r"^#", line):
                                    last_comment = (
                                        line.lstrip("#").lstrip(" ").rstrip("\n")
                                    )
                                    continue

                                # Elements with description
                                if ";" in line:
                                    line = line.rstrip(" ").rstrip("\n\r")
                                    row = line.split(";")
                                    regex = row[0]
                                    score = row[1]
                                    if len(row) > 2:
                                        regex_fp = row[2]
                                    desc = last_comment

                                # Elements without description
                                else:
                                    regex = line

                                # Replace environment variables
                                regex = loki_replace_env_vars(regex)

                                # OS specific transforms
                                regex = loki_transform_os(regex)

                                # If false positive definition exists
                                regex_fp_comp = None
                                if "regex_fp" in locals():
                                    # Replacements
                                    regex_fp = loki_replace_env_vars(regex_fp)
                                    regex_fp = loki_transform_os(regex_fp)
                                    # String regex as key - value is compiled regex
                                    # of false positive values
                                    regex_fp_comp = re.compile(regex_fp)

                                # Create dictionary with IOC data
                                fioc = {
                                    "regex": re.compile(regex),
                                    "score": score,
                                    "description": desc,
                                    "regex_fp": regex_fp_comp,
                                }
                                self.filename_iocs.append(fioc)

                            except Exception:
                                logger.log(
                                    "ERROR", "Init", f"Error reading line: {line}"
                                )
                                if logger.debug:
                                    traceback.print_exc()
                                    sys.exit(1)

        except Exception:
            if "ioc_filename" in locals():
                logger.log("ERROR", "Init", f"Error reading IOC file: {ioc_filename}")
            else:
                logger.log(
                    "ERROR",
                    "Init",
                    f"Error reading files from IOC folder: {ioc_directory}",
                )
                logger.log(
                    "ERROR",
                    "Init",
                    "Please make sure that you cloned the repo or downloaded the sub repository: "
                    "See https://github.com/Neo23x0/Loki/issues/51",
                )
            sys.exit(1)

    def initialize_yara_rules(self):
        """
        initialize yara rules
        """
        yara_rules = ""
        rule_count = 0

        try:
            for yara_rule_directory in self.yara_rule_directories:
                if not os.path.exists(yara_rule_directory):
                    continue
                logger.log(
                    "INFO",
                    "Init",
                    "Processing YARA rules folder {0}".format(yara_rule_directory),
                )
                for root, directories, files in os.walk(
                    yara_rule_directory, onerror=walk_error, followlinks=False
                ):
                    for file in files:
                        try:
                            # Full Path
                            yara_rule_file = os.path.join(root, file)

                            if file in args.disable_yara_files.split(","):
                                logger.log(
                                    "NOTICE", "Init", "Disabled yara file: " + file
                                )
                                continue

                            # Skip hidden, backup or system related files
                            if (
                                file.startswith(".")
                                or file.startswith("~")
                                or file.startswith("_")
                            ):
                                continue

                            # Extension
                            extension = os.path.splitext(file)[1].lower()

                            # Skip all files that don't have *.yar or *.yara extensions
                            if extension != ".yar" and extension != ".yara":
                                continue

                            with open(yara_rule_file, "r", encoding="utf-8") as yfile:
                                yara_rule_data = yfile.read()

                            # Test Compile
                            try:
                                externals = self.yara_externals(True)
                                compiled_rules = yara.compile(
                                    source=yara_rule_data,
                                    externals=externals,
                                )
                                logger.log(
                                    "DEBUG", "Init", f"Initializing Yara rule {file}"
                                )
                                rule_count += 1
                            except Exception:
                                logger.log(
                                    "ERROR",
                                    "Init",
                                    "Error while initializing Yara rule %s ERROR: %s"
                                    % (file, sys.exc_info()[1]),
                                )
                                traceback.print_exc()
                                if logger.debug:
                                    sys.exit(1)
                                continue

                            # Add the rule
                            yara_rules += yara_rule_data

                        except Exception:
                            logger.log(
                                "ERROR",
                                "Init",
                                "Error reading signature file %s ERROR: %s"
                                % (yara_rule_file, sys.exc_info()[1]),
                            )
                            if logger.debug:
                                traceback.print_exc()

            # Compile
            try:
                logger.log(
                    "INFO",
                    "Init",
                    "Initializing all YARA rules at once (composed string of all rule files)",
                )
                externals = self.yara_externals(True)
                compiled_rules = yara.compile(
                    source=yara_rules,
                    externals=externals,
                )
                logger.log("INFO", "Init", f"Initialized {rule_count} Yara rules")
            except Exception:
                traceback.print_exc()
                logger.log(
                    "ERROR",
                    "Init",
                    "Error during YARA rule compilation ERROR: %s "
                    "- please fix the issue in the rule set" % sys.exc_info()[1],
                )
                sys.exit(1)

            # Add as Lokis YARA rules
            self.yara_rules.append(compiled_rules)

        except Exception:
            logger.log("ERROR", "Init", "Error reading signature folder /signatures/")
            if logger.debug:
                traceback.print_exc()
                sys.exit(1)

    def initialize_hash_iocs(self, ioc_directory, false_positive=False):
        """
        initialize hash iocs
        """
        try:
            for ioc_filename in os.listdir(ioc_directory):
                if "hash" in ioc_filename:
                    if false_positive and "falsepositive" not in ioc_filename:
                        continue
                    with codecs.open(
                        os.path.join(ioc_directory, ioc_filename), "r", encoding="utf-8"
                    ) as file:
                        lines = file.readlines()

                        for line in lines:
                            try:
                                if re.search(r"^#", line) or re.search(
                                    r"^[\s]*$", line
                                ):
                                    continue
                                row = line.split(";")
                                # Handle 2 and 3 column IOCs
                                if len(row) == 3 and row[1].isdigit():
                                    hash = row[0].lower()
                                    score = int(row[1])
                                    comment = row[2].rstrip(" ").rstrip("\n")
                                else:
                                    hash = row[0].lower()
                                    comment = row[1].rstrip(" ").rstrip("\n")
                                    score = 100
                                # Empty File Hash
                                if hash in HASH_WHITELIST:
                                    continue
                                # Else - check which type it is
                                self.hashes_scores[int(hash, 16)] = score
                                if len(hash) == 32:
                                    self.hashes_md5[int(hash, 16)] = comment
                                if len(hash) == 40:
                                    self.hashes_sha1[int(hash, 16)] = comment
                                if len(hash) == 64:
                                    self.hashes_sha256[int(hash, 16)] = comment
                                if false_positive:
                                    self.false_hashes[int(hash, 16)] = comment
                            except Exception:
                                if logger.debug:
                                    traceback.print_exc()
                                logger.log("ERROR", "Init", f"Cannot read line: {line}")

                    # Debug
                    if logger.debug:
                        logger.log(
                            "DEBUG",
                            "Init",
                            "Initialized %s hash IOCs from file %s"
                            % (
                                str(
                                    len(self.hashes_md5)
                                    + len(self.hashes_sha1)
                                    + len(self.hashes_sha256)
                                ),
                                ioc_filename,
                            ),
                        )

            # create sorted lists with just the integer values of the hashes for quick binary search
            self.hashes_md5_list = list(self.hashes_md5.keys())
            self.hashes_md5_list.sort()
            self.hashes_sha1_list = list(self.hashes_sha1.keys())
            self.hashes_sha1_list.sort()
            self.hashes_sha256_list = list(self.hashes_sha256.keys())
            self.hashes_sha256_list.sort()

        except Exception:
            if logger.debug:
                traceback.print_exc()
                sys.exit(1)
            logger.log("ERROR", "Init", f"Error reading Hash file: {ioc_filename}")

    def initialize_filetype_magics(self, filetype_magics_file):
        """
        initialize filetype magics
        """
        try:
            with open(filetype_magics_file, "r", encoding="utf-8") as config:
                lines = config.readlines()

            for line in lines:
                try:
                    if (
                        re.search(r"^#", line)
                        or re.search(r"^[\s]*$", line)
                        or ";" not in line
                    ):
                        continue

                    (sig_raw, description) = line.rstrip("\n").split(";")
                    sig = re.sub(r" ", "", sig_raw)

                    if len(sig) > self.max_filetype_magics:
                        self.max_filetype_magics = len(sig)

                    self.filetype_magics[sig] = description

                except Exception:
                    logger.log("ERROR", "Init", f"Cannot read line: {line}")

        except Exception:
            if logger.debug:
                traceback.print_exc()
                sys.exit(1)
            logger.log(
                "ERROR", "Init", f"Error reading Hash file: {filetype_magics_file}"
            )

    def initialize_excludes(self, excludes_file):
        """
        initialize_excludes
        """
        try:
            excludes = []
            excludes_hash = []
            with open(excludes_file, "r", encoding="utf-8") as config:
                lines = config.read().splitlines()

            for line in lines:
                if re.search(r"^[\s]*#", line):
                    continue
                try:
                    # If the line contains md5sum
                    if re.search(r"^md5sum:", line):
                        excludes_hash.append(re.sub(r"(md5sum:|(\s\#|\#).*)", "", line))
                    # If the line contains sha1sum
                    elif re.search(r"^sha1sum:", line):
                        excludes_hash.append(
                            re.sub(r"(sha1sum:|(\s\#|\#).*)", "", line)
                        )
                    elif re.search(r"^sha256sum:", line):
                        excludes_hash.append(
                            re.sub(r"(sha256sum:|(\s\#|\#).*)", "", line)
                        )
                    # If the line contains something
                    elif re.search(r"\w", line):
                        regex = re.compile(line, re.IGNORECASE)
                        excludes.append(regex)
                except Exception:
                    logger.log("ERROR", "Init", f"Cannot compile regex: {line}")

            self.full_excludes = excludes
            self.excludes_hash = excludes_hash

        except Exception:
            if logger.debug:
                traceback.print_exc()
            logger.log(
                "NOTICE", "Init", f"Error reading excludes file: {excludes_file}"
            )

    def get_file_data(self, file_path):
        """
        get file data
        """
        file_data = b""
        try:
            # Read file complete
            with open(file_path, "rb") as f:
                file_data = f.read()
        except Exception:
            if logger.debug:
                traceback.print_exc()
            logger.log(
                "DEBUG", "FileScan", f"Cannot open file {file_path} (access denied)"
            )
        finally:
            return file_data

    def script_stats_analysis(self, data):
        """
        Doing a statistical analysis for scripts like PHP, JavaScript or PowerShell to
        detect obfuscated code
        :param data:
        :return: message, score
        """
        anomal_chars = [r"^", r"{", r"}", r'"', r",", r"<", r">", ";"]
        anomal_char_stats = {}
        char_stats = {"upper": 0, "lower": 0, "numbers": 0, "symbols": 0, "spaces": 0}
        anomalies = []
        c = Counter(data)
        anomaly_score = 0

        # Check the characters
        for char in c.most_common():
            if char[0] in anomal_chars:
                anomal_char_stats[char[0]] = char[1]
            if char[0].isupper():
                char_stats["upper"] += char[1]
            elif char[0].islower():
                char_stats["lower"] += char[1]
            elif char[0].isdigit():
                char_stats["numbers"] += char[1]
            elif char[0].isspace():
                char_stats["spaces"] += char[1]
            else:
                char_stats["symbols"] += char[1]
        # Totals
        char_stats["total"] = len(data)
        char_stats["alpha"] = char_stats["upper"] + char_stats["lower"]

        # Detect Anomalies
        if char_stats["alpha"] > 40 and char_stats["upper"] > (
            char_stats["lower"] * 0.9
        ):
            anomalies.append("upper to lower ratio")
            anomaly_score += 20
        if char_stats["symbols"] > char_stats["alpha"]:
            anomalies.append("more symbols than alphanum chars")
            anomaly_score += 40
        for ac, count in anomal_char_stats.iteritems():
            if (count / char_stats["alpha"]) > 0.05:
                anomalies.append(f"symbol count of '{ac}' very high")
                anomaly_score += 40

        # Generate message
        message = "Anomaly detected ANOMALIES: '{0}'".format("', '".join(anomalies))
        if anomaly_score > 40:
            return message, anomaly_score

        return "", 0


def get_application_path():
    """
    get application path
    """
    try:
        if getattr(sys, "frozen", False):
            application_path = os.path.dirname(os.path.realpath(sys.executable))
        else:
            application_path = os.path.dirname(os.path.realpath(__file__))
        return application_path
    except Exception:
        print("Error while evaluation of application path")
        traceback.print_exc()
        if args.debug:
            sys.exit(1)


def update_loki(sigs_only: bool) -> None:
    """
    update loki
    """
    logger.log("INFO", "Update", "Starting separate updater process ...")
    p_args = []

    # Updater
    if os.path.exists(os.path.join(get_application_path(), "upgrader.py")):
        p_args.append(args.python)
        p_args.append("upgrader.py")
    elif os.path.exists(os.path.join(get_application_path(), "upgrader")):
        p_args.append("./upgrader")
    else:
        logger.log(
            "ERROR",
            "Update",
            "Cannot find upgrader in the current working directory.",
        )

    if sigs_only:
        p_args.append("--sigsonly")
        p = Popen(p_args, shell=False)
        p.communicate()
    else:
        p_args.append("--detached")
        Popen(p_args, shell=False)


def walk_error(err):
    """
    walk error
    """
    if "Error 3" in str(err):
        print("Directory walk error")


def save_pidfile():
    """
    save pidfile
    """
    if args.d is True:
        if os.path.exists(args.pidfile):
            fpid = open(args.pidfile, "r", encoding="utf-8")
            loki_pid = int(fpid.read())
            fpid.close()
            if psutil.pid_exists(loki_pid):
                print("LOKI daemon already running. Returning to Asgard.")
                sys.exit(0)
        with open(args.pidfile, "w", encoding="utf-8") as fpid:
            fpid.write(str(os.getpid()))
            fpid.close()


def remove_pidfile():
    """
    remove pidfile
    """
    if args.d and os.path.exists(args.pidfile):
        os.remove(args.pidfile)


def sigint_handler(signal_name, frame):
    """
    SIGINT handler
    """
    try:
        logger.log(
            "INFO",
            "Init",
            "LOKI's work has been interrupted by a human. Returning to Asgard.",
        )
    except Exception:
        print("LOKI's work has been interrupted by a human. Returning to Asgard.")
    remove_pidfile()
    sys.exit(0)


def sigterm_handler(signal_name, frame):
    """
    SIGTERM handler
    """
    remove_pidfile()
    print("LOKI's work has been interrupted by a SIGTERM. Returning to Asgard.")
    sys.exit(0)


def main():
    """
    main
    """
    args = parser.parse_args()

    if args.nolog and (args.logfile or args.logfolder):
        print("The --logfolder and -l directives are not compatible with --nolog")
        sys.exit(1)

    filename = "loki_%s_%s.log" % (
        os.uname().nodename,
        datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
    )
    if args.logfolder and args.logfile:
        print(
            "Must specify either log folder with --logfolder, which uses the default filename, "
            "or log file with -l. Log file can be an absolute path"
        )
        sys.exit(1)
    elif args.logfolder:
        args.logfolder = os.path.abspath(args.logfolder)
        args.logfile = os.path.join(args.logfolder, filename)
    elif not args.logfile:
        args.logfile = filename

    args.excludeprocess = [x.lower() for x in args.excludeprocess]

    return args


# MAIN ################################################################
if __name__ == "__main__":
    # Signal handler for CTRL+C
    signal.signal(signal.SIGINT, sigint_handler)

    # Signal handler for SIGTERM
    signal.signal(signal.SIGTERM, sigterm_handler)

    # Argument parsing
    args = main()

    # Remove old log file
    if os.path.exists(args.logfile):
        os.remove(args.logfile)

    # Logger
    logger = LokiLogger(
        args.nolog,
        args.logfile,
        args.csv,
        args.silent,
        args.debug,
    )

    # Show version
    if args.version:
        sys.exit(0)

    # Update
    if args.update:
        update_loki(sigs_only=False)
        sys.exit(0)

    # Platform info
    try:
        for key, val in platform.freedesktop_os_release().items():
            if key == "PRETTY_NAME":
                platform_pretty_name = val
    except Exception:
        platform_pretty_name = platform.system()
    platform_machine = platform.machine()
    platform_full = platform_pretty_name + " (" + platform_machine + ")"

    logger.log(
        "NOTICE",
        "Init",
        "Starting Loki Scan VERSION: {3} SYSTEM: {0} TIME: {1} PLATFORM: {2}".format(
            os.uname().nodename,
            get_syslog_timestamp(),
            platform_full,
            logger.version,
        ),
    )

    # Loki
    loki = Loki(args.intense)

    if os.geteuid() == 0:
        logger.log("INFO", "Init", "Current user is root - very good")
    else:
        logger.log(
            "NOTICE",
            "Init",
            "Program should be run as 'root' to ensure all access rights "
            "to process memory and file objects.",
        )

    # Scan Processes --------------------------------------------------
    if not args.noprocscan and os.geteuid() == 0:
        loki.scan_processes_linux()
    else:
        logger.log(
            "NOTICE",
            "Init",
            "Skipping process memory check. User has no admin rights.",
        )

    # Scan Path -------------------------------------------------------
    if not args.nofilescan:
        # Set default
        defaultPath = args.p

        # Daemon mode
        if args.d is True:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.bind((args.listen_host, args.listen_port))
            except Exception as strerror:
                logger.log("ERROR", "Init", "{0}".format(strerror))
                server.close()
                sys.exit(1)
            save_pidfile()
            server.listen(5)

            def handle_client(client_socket, address):
                """
                handle client
                """
                size = 2048
                while True:
                    try:
                        clientid = threading.current_thread().name
                        threading.current_thread().message = ""
                        data = client_socket.recv(size)
                        scan_path = data.decode().split(" ")[0]
                        if args.auth:
                            server_authkey = args.auth
                            try:
                                client_authkey = data.decode().split(" ")[1]
                            except Exception:
                                logger.log(
                                    "NOTICE",
                                    "Auth",
                                    "Client "
                                    + str(address[0])
                                    + ":"
                                    + str(address[1])
                                    + " no valid authorization",
                                )
                                client_socket.send("authorization required".encode())
                                client_socket.close()
                                return False

                            if client_authkey.strip() == server_authkey:
                                logger.log(
                                    "NOTICE",
                                    "Auth",
                                    "Client "
                                    + str(address[0])
                                    + ":"
                                    + str(address[1])
                                    + " accepted",
                                )
                            else:
                                logger.log(
                                    "NOTICE",
                                    "Auth",
                                    "Client "
                                    + str(address[0])
                                    + ":"
                                    + str(address[1])
                                    + " unauthorized",
                                )
                                client_socket.send("unauthorized".encode())
                                client_socket.close()
                                return False
                        logger.log(
                            "INFO",
                            "Init",
                            "Received: "
                            + data.decode().strip()
                            + " from: "
                            + str(address[0])
                            + ":"
                            + str(address[1]),
                        )
                        loki.scan_path(scan_path.strip())

                        # Result
                        if threading.current_thread().message == "ALERT":
                            logger.log(
                                "RESULT",
                                "Results",
                                "Indicators detected! (Client: " + clientid + ")",
                            )
                            client_socket.send("RESULT: Indicators detected!".encode())
                        elif threading.current_thread().message == "WARNING":
                            logger.log(
                                "RESULT",
                                "Results",
                                "Suspicious objects detected! (Client: "
                                + clientid
                                + ")",
                            )
                            client_socket.send(
                                "RESULT: Suspicious objects detected!".encode()
                            )
                        else:
                            logger.log(
                                "RESULT",
                                "Results",
                                "SYSTEM SEEMS TO BE CLEAN. (Client: " + clientid + ")",
                            )
                            client_socket.send(
                                "RESULT: SYSTEM SEEMS TO BE CLEAN.".encode()
                            )

                        logger.log(
                            "NOTICE",
                            "Results",
                            "Finished LOKI Scan CLIENT: %s SYSTEM: %s TIME: %s"
                            % (
                                clientid,
                                os.uname().nodename,
                                get_syslog_timestamp(),
                            ),
                        )
                        client_socket.close()
                        return False
                    except socket.error:
                        client_socket.close()
                        return False

            logger.log(
                "NOTICE",
                "Init",
                "Listening on " + args.listen_host + ":" + str(args.listen_port),
            )
            while True:
                client, addr = server.accept()
                threading.Thread(
                    target=handle_client,
                    args=(client, addr),
                    name=str(addr[0]) + ":" + str(addr[1]),
                ).start()

        # Oneshot mode
        else:
            loki.scan_path(defaultPath)

    logger.print_results()
