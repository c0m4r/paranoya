"""
Arguments parser
"""

import argparse

# Parse Arguments
parser = argparse.ArgumentParser(description="Loki - Simple IOC Scanner")
parser.add_argument("-p", help="Path to scan", metavar="path", default="/")
parser.add_argument(
    "-s",
    help="Maximum file size to check in KB (default 5000 KB)",
    metavar="kilobyte",
    default=5000,
)
parser.add_argument("-l", "--logfile", default="")
parser.add_argument("-a", help="Alert score", metavar="alert-level", default=100)
parser.add_argument("-w", help="Warning score", metavar="warning-level", default=60)
parser.add_argument("-n", help="Notice score", metavar="notice-level", default=40)
parser.add_argument("-d", help="Run as a daemon", action="store_true", default=False)
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
    "--silent",
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
parser.add_argument("--debug", action="store_true", default=False, help="Debug output")
parser.add_argument(
    "--maxworkingset",
    type=int,
    default=200,
    help="Maximum working set size of processes to scan (in MB, default 100 MB)",
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
    help="Specify an executable name to exclude from scans,"
    " can be used multiple times",
    default=[],
)
parser.add_argument(
    "--force",
    action="store_true",
    help="Force the scan on a certain folder "
    "(even if excluded with hard exclude in LOKI's code",
    default=False,
)
parser.add_argument(
    "--version",
    action="store_true",
    help="Shows welcome text and version of loki, then exit",
    default=False,
)
parser.add_argument(
    "--progress",
    action="store_true",
    help="Show a progress bar (experimental)",
    default=False,
)
