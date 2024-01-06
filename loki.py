# -*- coding: utf-8 -*-

"""
Loki - Simple IOC Scanner Copyright (c) 2015 Florian Roth
Loki (daemonized) - Simple IOC and YARA Scanner fork (c) 2023 c0m4r

https://github.com/c0m4r/Loki-daemonized

Licensed under GPL 3.0
"""

import argparse
import datetime
import os
import platform
import psutil
import re
import socket
import stat
import sys
import threading
import traceback

import signal as signal_module

from bisect import bisect_left
from collections import Counter
from subprocess import Popen, PIPE, run

# yara-python module
import yara

# LOKI modules
from lib.lokilogger import codecs, logging, LokiLogger, getSyslogTimestamp
from lib.helpers import (
    is_ip,
    is_cidr,
    ip_in_net,
    generateHashes,
    getExcludedMountpoints,
    printProgress,
    transformOS,
    replaceEnvVars,
    get_file_type,
    removeNonAsciiDrop,
    getAgeString,
    getHostname,
)

# Platform
os_platform = "linux"

# Predefined Evil Extensions
EVIL_EXTENSIONS = [
    ".vbs",
    ".ps",
    ".ps1",
    ".rar",
    ".tmp",
    ".bas",
    ".bat",
    ".chm",
    ".cmd",
    ".com",
    ".cpl",
    ".sh",
    ".crt",
    ".dll",
    ".exe",
    ".hta",
    ".js",
    ".lnk",
    ".msc",
    ".ocx",
    ".pcd",
    ".pif",
    ".pot",
    ".pdf",
    ".reg",
    ".scr",
    ".sct",
    ".sys",
    ".url",
    ".vb",
    ".vbe",
    ".wsc",
    ".wsf",
    ".wsh",
    ".ct",
    ".t",
    ".input",
    ".war",
    ".jsp",
    ".jspx",
    ".php",
    ".asp",
    ".aspx",
    ".doc",
    ".docx",
    ".pdf",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".tmp",
    ".log",
    ".dump",
    ".pwd",
    ".w",
    ".txt",
    ".conf",
    ".cfg",
    ".conf",
    ".config",
    ".psd1",
    ".psm1",
    ".ps1xml",
    ".clixml",
    ".psc1",
    ".pssc",
    ".pl",
    ".www",
    ".rdp",
    ".jar",
    ".docm",
    ".sys",
]

SCRIPT_EXTENSIONS = [
    ".asp",
    ".vbs",
    ".ps1",
    ".bas",
    ".bat",
    ".js",
    ".vb",
    ".vbe",
    ".wsc",
    ".wsf",
    ".wsh",
    ".jsp",
    ".jspx",
    ".php",
    ".asp",
    ".aspx",
    ".psd1",
    ".psm1",
    ".ps1xml",
    ".clixml",
    ".psc1",
    ".pssc",
    ".pl",
    ".sh",
]

SCRIPT_TYPES = ["VBS", "PHP", "JSP", "ASP", "BATCH"]


def ioc_contains(sorted_list, value):
    # returns true if sorted_list contains value
    index = bisect_left(sorted_list, value)
    return index != len(sorted_list) and sorted_list[index] == value


class Loki(object):
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
    fullExcludes = []
    # Platform specific excludes (match the beginning of the full path) (not user-defined)
    startExcludes = []
    # Excludes hash (md5, sha1 and sha256)
    excludes_hash = []

    # File type magics
    filetype_magics = {}
    max_filetype_magics = 0

    # Predefined paths to skip
    LINUX_PATH_SKIPS_START = set(
        [
            "/proc",
            "/dev",
            "/sys/kernel/debug",
            "/sys/kernel/slab",
            "/sys/devices",
            "/usr/src/linux",
        ]
    )
    MOUNTED_DEVICES = set(["/media", "/volumes"])
    LINUX_PATH_SKIPS_END = set(["/initctl"])

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
            updateLoki(sigsOnly=True)

        # Excludes
        self.initialize_excludes(
            os.path.join(self.app_path, "config/excludes.cfg".replace("/", os.sep))
        )

        # Static excludes
        if not args.force:
            if args.alldrives:
                self.startExcludes = self.LINUX_PATH_SKIPS_START
            else:
                self.startExcludes = (
                    self.LINUX_PATH_SKIPS_START
                    | self.MOUNTED_DEVICES
                    | set(getExcludedMountpoints())
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
            "File Name Characteristics initialized with %s regex patterns"
            % len(self.filename_iocs),
        )

        # C2 based IOCs (all files in iocs that contain 'c2')
        self.initialize_c2_iocs(self.ioc_path)
        logger.log(
            "INFO",
            "Init",
            "C2 server indicators initialized with %s elements"
            % len(self.c2_server.keys()),
        )

        # Hash based IOCs (all files in iocs that contain 'hash')
        self.initialize_hash_iocs(self.ioc_path)
        logger.log(
            "INFO",
            "Init",
            "Malicious MD5 Hashes initialized with %s hashes"
            % len(self.hashes_md5.keys()),
        )
        logger.log(
            "INFO",
            "Init",
            "Malicious SHA1 Hashes initialized with %s hashes"
            % len(self.hashes_sha1.keys()),
        )
        logger.log(
            "INFO",
            "Init",
            "Malicious SHA256 Hashes initialized with %s hashes"
            % len(self.hashes_sha256.keys()),
        )

        # Hash based False Positives (all files in iocs that contain 'hash' and 'falsepositive')
        self.initialize_hash_iocs(self.ioc_path, false_positive=True)
        logger.log(
            "INFO",
            "Init",
            "False Positive Hashes initialized with %s hashes"
            % len(self.false_hashes.keys()),
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

    def scan_path(self, path):
        if os.path.isfile(path):
            root = ""
            directories = ""
            files = [path]
            loki.scan_path_files(root, directories, files)
            return

        # Check if path exists
        if not os.path.exists(path):
            logger.log(
                "ERROR", "FileScan", "None Existing Scanning Path %s ...  " % path
            )
            return

        # Startup
        logger.log("INFO", "FileScan", "Scanning Path %s ...  " % path)
        # Platform specific excludes
        for skip in self.startExcludes:
            if path.startswith(skip):
                logger.log(
                    "INFO",
                    "FileScan",
                    "Skipping %s directory [fixed excludes] (try using --force or --alldrives)"
                    % skip,
                )
                return

        for root, directories, files in os.walk(
            path, onerror=walk_error, followlinks=False
        ):
            # Skip paths that start with ..
            newDirectories = []
            for dir in directories:
                skipIt = False

                # Generate a complete path for comparisons
                completePath = os.path.join(root, dir).lower() + os.sep

                # Platform specific excludes
                for skip in self.startExcludes:
                    if completePath.startswith(skip):
                        logger.log(
                            "INFO",
                            "FileScan",
                            "Skipping %s directory [fixed excludes] (try using --force or --alldrives)"
                            % skip,
                        )
                        skipIt = True

                if not skipIt:
                    newDirectories.append(dir)
            directories[:] = newDirectories

            loki.scan_path_files(root, directories, files)

    def scan_path_files(self, root, directories, files):
        # Counter
        c = 0

        # Loop through files
        for filename in files:
            try:
                # Findings
                reasons = []
                # Total Score
                total_score = 0

                # Get the file and path
                filePath = os.path.join(root, filename)
                fpath = os.path.split(filePath)[0]
                # Clean the values for YARA matching
                # > due to errors when Unicode characters are passed to the match function as
                #   external variables
                filePathCleaned = fpath.encode("ascii", errors="replace")
                fileNameCleaned = filename.encode("ascii", errors="replace")

                # Get Extension
                extension = os.path.splitext(filePath)[1].lower()

                # Skip marker
                skipIt = False

                # User defined excludes
                for skip in self.fullExcludes:
                    if skip.search(filePath):
                        logger.log(
                            "DEBUG", "FileScan", "Skipping element %s" % filePath
                        )
                        skipIt = True

                # Linux directory skip
                if os_platform == "linux":
                    # Skip paths that end with ..
                    for skip in self.LINUX_PATH_SKIPS_END:
                        if filePath.endswith(skip):
                            if self.LINUX_PATH_SKIPS_END[skip] == 0:
                                logger.log(
                                    "INFO", "FileScan", "Skipping %s element" % skip
                                )
                                self.LINUX_PATH_SKIPS_END[skip] = 1
                                skipIt = True

                    # File mode
                    try:
                        mode = os.stat(filePath).st_mode
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
                            "Skipping element %s does not exist or is a broken symlink"
                            % (filePath),
                        )
                        continue

                # Skip
                if skipIt:
                    continue

                # Counter
                c += 1

                if not args.noindicator:
                    printProgress(c)

                # Skip program directory
                if self.app_path.lower() in filePath.lower():
                    logger.log(
                        "DEBUG",
                        "FileScan",
                        "Skipping file in program directory FILE: %s" % filePathCleaned,
                    )
                    continue

                fileSize = os.stat(filePath).st_size
                # print file_size

                # File Name Checks -------------------------------------------------
                for fioc in self.filename_iocs:
                    match = fioc["regex"].search(filePath)
                    if match:
                        # Check for False Positive
                        if fioc["regex_fp"]:
                            match_fp = fioc["regex_fp"].search(filePath)
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
                firstBytesString = b"-"
                hashString = ""

                # Evaluate Type
                fileType = get_file_type(
                    filePath, self.filetype_magics, self.max_filetype_magics, logger
                )

                # Fast Scan Mode - non intense
                do_intense_check = True
                if (
                    not self.intense_mode
                    and fileType == "UNKNOWN"
                    and extension not in EVIL_EXTENSIONS
                ):
                    if args.printall:
                        logger.log(
                            "INFO",
                            "FileScan",
                            "Skipping file due to fast scan mode: %s" % fileNameCleaned,
                        )
                    do_intense_check = False

                # Set fileData to an empty value
                fileData = ""

                print_filesize_info = False

                # Evaluations -------------------------------------------------------
                # Evaluate size
                fileSizeLimit = int(args.s) * 1024
                if fileSize > fileSizeLimit:
                    # Print files
                    do_intense_check = False
                    print_filesize_info = True

                # Some file types will force intense check
                if fileType == "MDMP":
                    do_intense_check = True
                    print_filesize_info = False

                # Intense Check switch
                if do_intense_check:
                    if args.printall:
                        logger.log(
                            "INFO",
                            "FileScan",
                            "Scanning %s TYPE: %s SIZE: %s"
                            % (fileNameCleaned, fileType, fileSize),
                        )
                else:
                    if args.printall:
                        logger.log(
                            "INFO",
                            "FileScan",
                            "Checking %s TYPE: %s SIZE: %s"
                            % (fileNameCleaned, fileType, fileSize),
                        )

                if print_filesize_info and args.printall:
                    logger.log(
                        "INFO",
                        "FileScan",
                        "Skipping file due to file size: %s TYPE: %s SIZE: %s CURRENT SIZE LIMIT(kilobytes): %d"
                        % (fileNameCleaned, fileType, fileSize, fileSizeLimit),
                    )

                # Hash Check -------------------------------------------------------
                # Do the check
                if do_intense_check:
                    fileData = self.get_file_data(filePath)

                    # First bytes
                    firstBytesString = "%s / %s" % (
                        fileData[:20].hex(),
                        removeNonAsciiDrop(fileData[:20]),
                    )

                    # Hash Eval
                    matchType = None
                    matchDesc = None
                    matchHash = None
                    md5 = 0
                    sha1 = 0
                    sha256 = 0

                    md5, sha1, sha256 = generateHashes(fileData)
                    md5_num = int(md5, 16)
                    sha1_num = int(sha1, 16)
                    sha256_num = int(sha256, 16)

                    # False Positive Hash
                    if (
                        md5_num in self.false_hashes.keys()
                        or sha1_num in self.false_hashes.keys()
                        or sha256_num in self.false_hashes.keys()
                    ):
                        continue

                    # Skip exclude hash
                    if (
                        md5 in self.excludes_hash
                        or sha1 in self.excludes_hash
                        or sha256 in self.excludes_hash
                    ):
                        logger.log(
                            "DEBUG",
                            "FileScan",
                            "Skipping element %s excluded by hash" % (filePath),
                        )
                        continue

                    # Malware Hash
                    matchScore = 100
                    matchLevel = "Malware"
                    if ioc_contains(self.hashes_md5_list, md5_num):
                        matchType = "MD5"
                        matchDesc = self.hashes_md5[md5_num]
                        matchHash = md5
                        matchScore = self.hashes_scores[md5_num]
                    if ioc_contains(self.hashes_sha1_list, sha1_num):
                        matchType = "SHA1"
                        matchDesc = self.hashes_sha1[sha1_num]
                        matchHash = sha1
                        matchScore = self.hashes_scores[sha1_num]
                    if ioc_contains(self.hashes_sha256_list, sha256_num):
                        matchType = "SHA256"
                        matchDesc = self.hashes_sha256[sha256_num]
                        matchHash = sha256
                        matchScore = self.hashes_scores[sha256_num]

                    # If score is low change the description
                    if matchScore < 80:
                        matchLevel = "Suspicious"

                    # Hash string
                    hashString = "MD5: %s SHA1: %s SHA256: %s" % (md5, sha1, sha256)

                    if matchType:
                        reasons.append(
                            "%s Hash TYPE: %s HASH: %s SUBSCORE: %d DESC: %s"
                            % (matchLevel, matchType, matchHash, matchScore, matchDesc)
                        )
                        total_score += matchScore

                    # Script Anomalies Check
                    if args.scriptanalysis:
                        if extension in SCRIPT_EXTENSIONS or type in SCRIPT_TYPES:
                            logger.log(
                                "DEBUG",
                                "FileScan",
                                "Performing character analysis on file %s ... "
                                % filePath,
                            )
                            message, score = self.script_stats_analysis(fileData)
                            if message:
                                reasons.append("%s SCORE: %s" % (message, score))
                                total_score += score

                    # Yara Check -------------------------------------------------------

                    # Memory Dump Scan
                    if fileType == "MDMP":
                        logger.log(
                            "INFO",
                            "FileScan",
                            "Scanning memory dump file %s"
                            % fileNameCleaned.decode("utf-8"),
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
                            fileData=fileData,
                            fileType=fileType,
                            fileName=fileNameCleaned,
                            filePath=filePathCleaned,
                            extension=extension,
                            md5=md5,  # legacy rule support
                        ):
                            # Message
                            message = (
                                "Yara Rule MATCH: %s SUBSCORE: %s DESCRIPTION: %s REF: %s AUTHOR: %s"
                                % (rule, score, description, reference, author)
                            )
                            # Matches
                            if len(matched_strings) > 0:
                                message += " MATCHES: %s" % ", ".join(matched_strings)

                            total_score += score
                            reasons.append(message)

                    except Exception:
                        if logger.debug:
                            traceback.print_exc()
                        logger.log(
                            "ERROR",
                            "FileScan",
                            "Cannot YARA scan file: %s" % filePathCleaned,
                        )

                # Info Line -----------------------------------------------------------------------
                fileInfo = (
                    "FILE: %s SCORE: %s TYPE: %s SIZE: %s FIRST_BYTES: %s %s %s "
                    % (
                        filePath,
                        total_score,
                        fileType,
                        fileSize,
                        firstBytesString,
                        hashString,
                        getAgeString(filePath),
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
                message_body = fileInfo
                for i, r in enumerate(reasons):
                    if i < 2 or args.allreasons:
                        message_body += "REASON_{0}: {1}".format(i + 1, r)

                logger.log(message_type, "FileScan", message_body)

            except Exception:
                if logger.debug:
                    traceback.print_exc()
                    sys.exit(1)

    def scan_data(
        self,
        fileData,
        fileType="-",
        fileName=b"-",
        filePath=b"-",
        extension=b"-",
        md5="-",
    ):
        # Scan with yara
        try:
            for rules in self.yara_rules:
                # Yara Rule Match
                matches = rules.match(
                    data=fileData,
                    externals={
                        "filename": fileName.decode("utf-8"),
                        "filepath": filePath.decode("utf-8"),
                        "extension": extension,
                        "filetype": fileType,
                        "md5": md5,
                        "owner": "dummy",
                    },
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
                    "Skipping Process PID: %s as it just exited and no longer exists"
                    % (str(pid)),
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
                    "Process PID: %s NAME: %s STATUS: %s" % (str(pid), name, status),
                )
                continue
            path = psutil.Process(process).cwd()
            bin = psutil.Process(process).exe()
            tty = psutil.Process(process).terminal()

            process_info = (
                "PID: %s NAME: %s OWNER: %s STATUS: %s BIN: %s CMD: %s PATH: %s TTY: %s"
                % (str(pid), name, owner, status, bin, cmd, path, tty)
            )

            # Print info -------------------------------------------------------
            logger.log("INFO", "ProcessScan", "Process %s" % process_info)

            # Process Masquerading Detection -----------------------------------

            if re.search(r"\[", cmd):
                maps = "/proc/%s/maps" % str(pid)
                maps = run(["cat", maps], encoding="utf-8", stdout=PIPE)
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
        try:
            # Limits
            MAXIMUM_CONNECTIONS = 20

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
                            "Malware Domain/IP match in remote address PID: %s NAME: %s COMMAND: %s IP: %s PORT: %s DESC: %s"
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
                        "Established connection PID: %s NAME: %s COMMAND: %s LIP: %s LPORT: %s RIP: %s RPORT: %s"
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
                if connection_count > MAXIMUM_CONNECTIONS:
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
                "Process %s does not exist anymore or cannot be accessed" % str(pid),
            )

    def check_c2(self, remote_system):
        # IP - exact match
        if is_ip(remote_system):
            for c2 in self.c2_server:
                # if C2 definition is CIDR network
                if is_cidr(c2):
                    if ip_in_net(remote_system, c2):
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
                                            "C2 server definition is suspiciously short - will not add %s"
                                            % c2,
                                        )
                                        continue

                                    # Add to the LOKI iocs
                                    self.c2_server[c2.lower()] = last_comment

                                except Exception:
                                    logger.log(
                                        "ERROR", "Init", "Cannot read line: %s" % line
                                    )
                                    if logger.debug:
                                        sys.exit(1)
                except OSError:
                    logger.log("ERROR", "Init", "No such file or directory")
        except Exception:
            traceback.print_exc()
            logger.log("ERROR", "Init", "Error reading Hash file: %s" % ioc_filename)

    def initialize_filename_iocs(self, ioc_directory):
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
                                regex = replaceEnvVars(regex)

                                # OS specific transforms
                                regex = transformOS(regex)

                                # If false positive definition exists
                                regex_fp_comp = None
                                if "regex_fp" in locals():
                                    # Replacements
                                    regex_fp = replaceEnvVars(regex_fp)
                                    regex_fp = transformOS(regex_fp)
                                    # String regex as key - value is compiled regex of false positive values
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
                                    "ERROR", "Init", "Error reading line: %s" % line
                                )
                                if logger.debug:
                                    traceback.print_exc()
                                    sys.exit(1)

        except Exception:
            if "ioc_filename" in locals():
                logger.log("ERROR", "Init", "Error reading IOC file: %s" % ioc_filename)
            else:
                logger.log(
                    "ERROR",
                    "Init",
                    "Error reading files from IOC folder: %s" % ioc_directory,
                )
                logger.log(
                    "ERROR",
                    "Init",
                    "Please make sure that you cloned the repo or downloaded the sub repository: "
                    "See https://github.com/Neo23x0/Loki/issues/51",
                )
            sys.exit(1)

    def initialize_yara_rules(self):
        yaraRules = ""
        dummy = ""
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
                            yaraRuleFile = os.path.join(root, file)

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

                            with open(yaraRuleFile, "r") as yfile:
                                yara_rule_data = yfile.read()

                            # Test Compile
                            try:
                                compiledRules = yara.compile(
                                    source=yara_rule_data,
                                    externals={
                                        "filename": dummy,
                                        "filepath": dummy,
                                        "extension": dummy,
                                        "filetype": dummy,
                                        "md5": dummy,
                                        "owner": dummy,
                                    },
                                )
                                logger.log(
                                    "DEBUG", "Init", "Initializing Yara rule %s" % file
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
                            yaraRules += yara_rule_data

                        except Exception:
                            logger.log(
                                "ERROR",
                                "Init",
                                "Error reading signature file %s ERROR: %s"
                                % (yaraRuleFile, sys.exc_info()[1]),
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
                compiledRules = yara.compile(
                    source=yaraRules,
                    externals={
                        "filename": dummy,
                        "filepath": dummy,
                        "extension": dummy,
                        "filetype": dummy,
                        "md5": dummy,
                        "owner": dummy,
                    },
                )
                logger.log("INFO", "Init", "Initialized %d Yara rules" % rule_count)
            except Exception:
                traceback.print_exc()
                logger.log(
                    "ERROR",
                    "Init",
                    "Error during YARA rule compilation ERROR: %s - please fix the issue in the rule set"
                    % sys.exc_info()[1],
                )
                sys.exit(1)

            # Add as Lokis YARA rules
            self.yara_rules.append(compiledRules)

        except Exception:
            logger.log("ERROR", "Init", "Error reading signature folder /signatures/")
            if logger.debug:
                traceback.print_exc()
                sys.exit(1)

    def initialize_hash_iocs(self, ioc_directory, false_positive=False):
        HASH_WHITELIST = [  # Empty file
            int("d41d8cd98f00b204e9800998ecf8427e", 16),
            int("da39a3ee5e6b4b0d3255bfef95601890afd80709", 16),
            int("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 16),
            # One byte line break file (Unix) 0x0a
            int("68b329da9893e34099c7d8ad5cb9c940", 16),
            int("adc83b19e793491b1c6ea0fd8b46cd9f32e592fc", 16),
            int("01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b", 16),
            # One byte line break file (Windows) 0x0d0a
            int("81051bcc2cf1bedf378224b0a93e2877", 16),
            int("ba8ab5a0280b953aa97435ff8946cbcbb2755a27", 16),
            int("7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6", 16),
        ]
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
                                logger.log(
                                    "ERROR", "Init", "Cannot read line: %s" % line
                                )

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
            logger.log("ERROR", "Init", "Error reading Hash file: %s" % ioc_filename)

    def initialize_filetype_magics(self, filetype_magics_file):
        try:
            with open(filetype_magics_file, "r") as config:
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
                    logger.log("ERROR", "Init", "Cannot read line: %s" % line)

        except Exception:
            if logger.debug:
                traceback.print_exc()
                sys.exit(1)
            logger.log(
                "ERROR", "Init", "Error reading Hash file: %s" % filetype_magics_file
            )

    def initialize_excludes(self, excludes_file):
        try:
            excludes = []
            excludes_hash = []
            with open(excludes_file, "r") as config:
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
                    logger.log("ERROR", "Init", "Cannot compile regex: %s" % line)

            self.fullExcludes = excludes
            self.excludes_hash = excludes_hash

        except Exception:
            if logger.debug:
                traceback.print_exc()
            logger.log(
                "NOTICE", "Init", "Error reading excludes file: %s" % excludes_file
            )

    def get_file_data(self, filePath):
        fileData = b""
        try:
            # Read file complete
            with open(filePath, "rb") as f:
                fileData = f.read()
        except Exception:
            if logger.debug:
                traceback.print_exc()
            logger.log(
                "DEBUG", "FileScan", "Cannot open file %s (access denied)" % filePath
            )
        finally:
            return fileData

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
                anomalies.append("symbol count of '%s' very high" % ac)
                anomaly_score += 40

        # Generate message
        message = "Anomaly detected ANOMALIES: '{0}'".format("', '".join(anomalies))
        if anomaly_score > 40:
            return message, anomaly_score

        return "", 0


def get_application_path():
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


def processExists(pid):
    """
    Checks if a given process is running
    :param pid:
    :return:
    """
    return psutil.pid_exists(pid)


def updateLoki(sigsOnly):
    logger.log("INFO", "Update", "Starting separate updater process ...")
    pArgs = []

    # Updater
    if os.path.exists(os.path.join(get_application_path(), "loki-upgrader.py")):
        pArgs.append(args.python)
        pArgs.append("loki-upgrader.py")
    elif os.path.exists(os.path.join(get_application_path(), "loki-upgrader")):
        pArgs.append("./loki-upgrader")
    else:
        logger.log(
            "ERROR",
            "Update",
            "Cannot find loki-upgrader in the current working directory.",
        )

    if sigsOnly:
        pArgs.append("--sigsonly")
        p = Popen(pArgs, shell=False)
        p.communicate()
    else:
        pArgs.append("--detached")
        Popen(pArgs, shell=False)


def walk_error(err):
    if "Error 3" in str(err):
        logging.error(str(err))
        print("Directory walk error")


def save_pidfile():
    # Save pidfile
    if args.d is True:
        if os.path.exists(args.pidfile):
            fpid = open(args.pidfile, "r")
            loki_pid = int(fpid.read())
            fpid.close()
            if psutil.pid_exists(loki_pid):
                print("LOKI daemon already running. Returning to Asgard.")
                sys.exit(0)
        with open(args.pidfile, "w", encoding="utf-8") as fpid:
            fpid.write(str(os.getpid()))
            fpid.close()


def remove_pidfile():
    if args.d and os.path.exists(args.pidfile):
        os.remove(args.pidfile)


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
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


# SIGTERM Handler -------------------------------------------------------------
def signal_handler_term(signal_name, frame):
    remove_pidfile()
    print("LOKI's work has been interrupted by a SIGTERM. Returning to Asgard.")
    sys.exit(0)


def main():
    """
    Argument parsing function
    :return:
    """

    # Parse Arguments
    parser = argparse.ArgumentParser(description="Loki - Simple IOC Scanner")
    parser.add_argument("-p", help="Path to scan", metavar="path", default="/")
    parser.add_argument(
        "-s",
        help="Maximum file size to check in KB (default 5000 KB)",
        metavar="kilobyte",
        default=5000,
    )
    parser.add_argument("-l", help="Log file", metavar="log-file", default="")
    parser.add_argument(
        "-r", help="Remote syslog system", metavar="remote-loghost", default=""
    )
    parser.add_argument(
        "-t", help="Remote syslog port", metavar="remote-syslog-port", default=514
    )
    parser.add_argument("-a", help="Alert score", metavar="alert-level", default=100)
    parser.add_argument("-w", help="Warning score", metavar="warning-level", default=60)
    parser.add_argument("-n", help="Notice score", metavar="notice-level", default=40)
    parser.add_argument(
        "-d", help="Run as a daemon", action="store_true", default=False
    )
    parser.add_argument(
        "--pidfile", help="Pid file path (default: loki.pid)", default="loki.pid"
    )
    parser.add_argument(
        "--listen-host",
        help="Listen host for daemon mode (default: localhost)",
        default="localhost",
    )
    parser.add_argument(
        "--listen-port",
        help="Listen port for daemon mode (default: 1337)",
        type=int,
        default=1337,
    )
    parser.add_argument("--auth", help="Auth key, only in daemon mode", default="")
    parser.add_argument(
        "--disable-yara-files",
        help="Comma separated list of yara files to disable",
        default="",
    )
    parser.add_argument(
        "--alldrives",
        action="store_true",
        help="Scan all drives (including network drives and removable media)",
        default=False,
    )
    parser.add_argument(
        "--printall",
        action="store_true",
        help="Print all files that are scanned",
        default=False,
    )
    parser.add_argument(
        "--allreasons",
        action="store_true",
        help="Print all reasons that caused the score",
        default=False,
    )
    parser.add_argument(
        "--noprocscan", action="store_true", help="Skip the process scan", default=False
    )
    parser.add_argument(
        "--nofilescan", action="store_true", help="Skip the file scan", default=False
    )
    parser.add_argument(
        "--scriptanalysis",
        action="store_true",
        help="Statistical analysis for scripts to detect obfuscated code (beta)",
        default=False,
    )
    parser.add_argument(
        "--rootkit", action="store_true", help="Skip the rootkit check", default=False
    )
    parser.add_argument(
        "--noindicator",
        action="store_true",
        help="Do not show a progress indicator",
        default=False,
    )
    parser.add_argument(
        "--dontwait", action="store_true", help="Do not wait on exit", default=False
    )
    parser.add_argument(
        "--intense",
        action="store_true",
        help="Intense scan mode (also scan unknown file types and all extensions)",
        default=False,
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Write CSV log format to STDOUT (machine processing)",
        default=False,
    )
    parser.add_argument(
        "--onlyrelevant",
        action="store_true",
        help="Only print warnings or alerts",
        default=False,
    )
    parser.add_argument(
        "--nolog",
        action="store_true",
        help="Don't write a local log file",
        default=False,
    )
    parser.add_argument(
        "--update",
        action="store_true",
        default=False,
        help='Update the signatures from the "signature-base" sub repository',
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Debug output"
    )
    parser.add_argument(
        "--maxworkingset",
        type=int,
        default=200,
        help="Maximum working set size of processes to scan (in MB, default 100 MB)",
    )
    parser.add_argument(
        "--syslogtcp",
        action="store_true",
        default=False,
        help="Use TCP instead of UDP for syslog logging",
    )
    parser.add_argument(
        "--logfolder",
        help="Folder to use for logging when log file is not specified",
        metavar="log-folder",
        default="",
    )
    parser.add_argument(
        "--python",
        action="store",
        help="Override default python path",
        default="python",
    )
    parser.add_argument(
        "--nolisten",
        action="store_true",
        help="Dot not show listening connections",
        default=False,
    )
    parser.add_argument(
        "--excludeprocess",
        action="append",
        help="Specify an executable name to exclude from scans, can be used multiple times",
        default=[],
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force the scan on a certain folder (even if excluded with hard exclude in LOKI's code",
        default=False,
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Shows welcome text and version of loki, then exit",
        default=False,
    )

    args = parser.parse_args()

    if args.syslogtcp and not args.r:
        print(
            "Syslog logging set to TCP with --syslogtcp, but syslog logging not enabled with -r"
        )
        sys.exit(1)

    if args.nolog and (args.l or args.logfolder):
        print("The --logfolder and -l directives are not compatible with --nolog")
        sys.exit(1)

    filename = "loki_%s_%s.log" % (
        getHostname(os_platform),
        datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
    )
    if args.logfolder and args.l:
        print(
            "Must specify either log folder with --logfolder, which uses the default filename, "
            "or log file with -l. Log file can be an absolute path"
        )
        sys.exit(1)
    elif args.logfolder:
        args.logfolder = os.path.abspath(args.logfolder)
        args.l = os.path.join(args.logfolder, filename)
    elif not args.l:
        args.l = filename

    args.excludeprocess = [x.lower() for x in args.excludeprocess]

    return args


# MAIN ################################################################
if __name__ == "__main__":
    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # Signal handler for SIGTERM
    signal_module.signal(signal_module.SIGTERM, signal_handler_term)

    # Argument parsing
    args = main()

    # Remove old log file
    if os.path.exists(args.l):
        os.remove(args.l)

    # Logger
    LokiCustomFormatter = None
    logger = LokiLogger(
        args.nolog,
        args.l,
        getHostname(os_platform),
        args.r,
        int(args.t),
        args.syslogtcp,
        args.csv,
        args.onlyrelevant,
        args.debug,
        platform=os_platform,
        caller="main",
        customformatter=LokiCustomFormatter,
    )

    # Show version
    if args.version:
        sys.exit(0)

    # Update
    if args.update:
        updateLoki(sigsOnly=False)
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
            getHostname(os_platform),
            getSyslogTimestamp(),
            platform_full,
            logger.version,
        ),
    )

    # Loki
    loki = Loki(args.intense)

    # Check if admin
    isAdmin = False

    if os.geteuid() == 0:
        isAdmin = True
        logger.log("INFO", "Init", "Current user is root - very good")
    else:
        logger.log(
            "NOTICE",
            "Init",
            "Program should be run as 'root' to ensure all access rights to process memory and file objects.",
        )

    # Scan Processes --------------------------------------------------
    resultProc = False
    if not args.noprocscan and os_platform == "linux":
        if isAdmin:
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
                                getHostname(os_platform),
                                getSyslogTimestamp(),
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

    # Result
    logger.log(
        "NOTICE",
        "Results",
        "Results: {0} alerts, {1} warnings, {2} notices".format(
            logger.alerts, logger.warnings, logger.notices
        ),
    )
    if logger.alerts:
        logger.log("RESULT", "Results", "Indicators detected!")
        logger.log(
            "RESULT",
            "Results",
            "Loki recommends checking the elements on virustotal.com "
            "or Google and triage with a professional tool like "
            "THOR https://nextron-systems.com/thor in corporate networks.",
        )
    elif logger.warnings:
        logger.log("RESULT", "Results", "Suspicious objects detected!")
        logger.log(
            "RESULT",
            "Results",
            "Loki recommends a deeper analysis of the suspicious objects.",
        )
    else:
        logger.log("RESULT", "Results", "SYSTEM SEEMS TO BE CLEAN.")

    logger.log(
        "INFO",
        "Results",
        "Please report false positives via https://github.com/Neo23x0/signature-base",
    )
    logger.log(
        "NOTICE",
        "Results",
        "Finished LOKI Scan SYSTEM: %s TIME: %s"
        % (getHostname(os_platform), getSyslogTimestamp()),
    )
