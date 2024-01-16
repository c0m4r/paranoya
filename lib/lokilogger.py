"""
Loki (daemonized) lib/lokilogger.py
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

import codecs
import datetime
import os
import re
import sys
import traceback

from lib.lokivenv import venv_check

# venv before loading custom modules
venv_check("lib")

# Custom modules
try:
    from colorama import Fore, Back, Style
    from colorama import init
except Exception as e:
    print(e)
    sys.exit(0)

__version__ = "3.2.1"


class LokiLogger:
    """
    Loki logger
    """

    STDOUT_CSV = 0
    STDOUT_LINE = 1
    FILE_CSV = 2
    FILE_LINE = 3
    SYSLOG_LINE = 4

    no_log_file = False
    log_file = "loki.log"
    csv = False
    alerts = 0
    warnings = 0
    notices = 0
    messagecount = 0
    silent = False
    debug = False
    linesep = "\n"

    def __init__(
        self,
        no_log_file: bool,
        log_file: str,
        csv: bool,
        silent: bool,
        debug: bool,
    ):
        self.version = __version__
        self.no_log_file = no_log_file
        self.log_file = log_file
        self.csv = csv
        self.silent = silent
        self.debug = debug

        # Colorization
        init()

        # Welcome
        if not self.csv:
            self.print_welcome()

    def log(self, mes_type: str, module: str, message: str) -> None:
        """
        log
        """
        if not self.debug and mes_type == "DEBUG":
            return

        # Counter
        if mes_type == "ALERT":
            self.alerts += 1
        if mes_type == "WARNING":
            self.warnings += 1
        if mes_type == "NOTICE":
            self.notices += 1
        self.messagecount += 1

        if self.silent:
            if mes_type not in ("ALERT", "WARNING"):
                return

        # to file
        if not self.no_log_file:
            self.log_to_file(message, mes_type, module)

        # to stdout
        try:
            self.log_to_stdout(message, mes_type)
        except Exception:
            print(
                "Cannot print certain characters to command line, "
                "see log file for full unicode encoded log line"
            )
            self.log_to_stdout(message, mes_type)

    def log_format(self, message: str, *args: str) -> str:
        """
        log format
        """
        return message.format(*args)

    def set_color(self, mes_type: str, message: str) -> tuple[str, str]:
        """
        set color
        """
        if mes_type == "NOTICE":
            base_color = Fore.CYAN
        elif mes_type == "INFO":
            base_color = Fore.GREEN
        elif mes_type == "WARNING":
            base_color = Fore.YELLOW
        elif mes_type == "ALERT":
            base_color = Fore.RED
        elif mes_type == "DEBUG":
            base_color = Fore.WHITE
        elif mes_type == "ERROR":
            base_color = Fore.MAGENTA
        elif mes_type == "RESULT":
            if "clean" in message.lower():
                base_color = Fore.GREEN
            elif "suspicious" in message.lower():
                base_color = Fore.YELLOW
            else:
                base_color = Fore.RED
        high_color = base_color
        return high_color, base_color

    def log_to_stdout(self, message: str, mes_type: str) -> None:
        """
        log to stdout
        """
        if self.csv:
            print(
                self.log_format(
                    "{0},{1},{2},{3}",
                    get_syslog_timestamp(),
                    os.uname().nodename,
                    mes_type,
                    message,
                )
            )

        else:
            try:
                reset_all = Style.NORMAL + Fore.RESET
                key_color = Fore.WHITE
                base_color = Fore.WHITE
                high_color = Back.RESET

                high_color, base_color = self.set_color(mes_type, message)

                # Colorize Type Word at the beginning of the line
                type_colorer = re.compile(r"([A-Z]{3,})", re.VERBOSE)
                mes_type = type_colorer.sub(high_color + r"[\1]" + base_color, mes_type)
                # Break Line before REASONS
                linebreaker = re.compile(
                    "(MD5:|SHA1:|SHA256:|MATCHES:|FILE:|FIRST_BYTES:|DESCRIPTION:|REASON_[0-9]+)",
                    re.VERBOSE,
                )
                message = linebreaker.sub(r"\n\1", message)
                # Colorize Key Words
                colorer = re.compile(r"([A-Z_0-9]{2,}:)\s", re.VERBOSE)
                message = colorer.sub(
                    key_color + r"\1 " + base_color + Style.NORMAL,
                    message,
                )

                # Print to console
                if mes_type == "RESULT":
                    res_message = f"\b\b{mes_type} {message}"
                    print(base_color + " " + res_message + " ")
                    print(Fore.WHITE + " " + Style.NORMAL)
                else:
                    sys.stdout.write(
                        f"{reset_all}{base_color}\b\b{mes_type} "
                        f"{message}{Back.RESET}{Fore.WHITE}{Style.NORMAL}\n"
                    )

            except Exception:
                if self.debug:
                    traceback.print_exc()
                    sys.exit(1)
                print("Cannot print to cmd line - formatting error")

    def log_to_file(self, message: str, mes_type: str, module: str) -> None:
        """
        log to file
        """
        try:
            # Write to file
            with codecs.open(self.log_file, "a", encoding="utf-8") as logfile:
                if self.csv:
                    logfile.write(
                        self.log_format(
                            "{0},{1},{2},{3},{4}{5}",
                            get_syslog_timestamp(),
                            os.uname().nodename,
                            mes_type,
                            module,
                            message,
                            self.linesep,
                        )
                    )
                else:
                    logfile.write(
                        self.log_format(
                            "{0} {1} LOKI: {2}: MODULE: {3} MESSAGE: {4}{5}",
                            get_syslog_timestamp(),
                            os.uname().nodename,
                            mes_type.title(),
                            module,
                            message,
                            self.linesep,
                        )
                    )
        except Exception:
            if self.debug:
                traceback.print_exc()
                sys.exit(1)
            print(f"Cannot print line to log file {self.log_file}")

    def print_results(self) -> None:
        """
        print results
        """
        # Result
        self.log(
            "NOTICE",
            "Results",
            "Results: {0} alerts, {1} warnings, {2} notices".format(
                self.alerts, self.warnings, self.notices
            ),
        )
        if self.alerts:
            self.log("RESULT", "Results", "Indicators detected!")
            self.log(
                "RESULT",
                "Results",
                "Loki recommends checking the elements on virustotal.com "
                "or Google and triage with a professional tool like "
                "THOR https://nextron-systems.com/thor in corporate networks.",
            )
        elif self.warnings:
            self.log("RESULT", "Results", "Suspicious objects detected!")
            self.log(
                "RESULT",
                "Results",
                "Loki recommends a deeper analysis of the suspicious objects.",
            )
        else:
            self.log("RESULT", "Results", "SYSTEM SEEMS TO BE CLEAN.")

        self.log(
            "INFO",
            "Results",
            "Please report false positives via https://github.com/Neo23x0/signature-base",
        )
        self.log(
            "NOTICE",
            "Results",
            "Finished LOKI Scan SYSTEM: %s TIME: %s"
            % (os.uname().nodename, get_syslog_timestamp()),
        )

    def print_welcome(self) -> None:
        """
        print welcome
        """
        try:
            termsize = os.get_terminal_size().columns
        except Exception:
            termsize = 80
        print(str(Style.BRIGHT))
        if termsize > 80:
            print(
                rf"    {Fore.GREEN}__   ____  __ ______{Fore.RESET}     "
                rf"{Fore.RED}__                         _            __{Fore.RESET}"
            )
            print(
                rf"   {Fore.GREEN}/ /  / __ \/ //_/  _/{Fore.RESET} "
                rf"{Fore.RED}___/ /__ ____ __ _  ___  ___  (_)__ ___ ___/ /{Fore.RESET}"
            )
            print(
                rf"  {Fore.GREEN}/ /__/ /_/ / ,< _/ /{Fore.RESET}  "
                rf"{Fore.RED}/ _  / _ `/ -_)  ' \/ _ \/ _ \/ /_ // -_) _  / {Fore.RESET}"
            )
            print(
                rf" {Fore.GREEN}/____/\____/_/|_/___/{Fore.RESET}  "
                rf"{Fore.RED}\_,_/\_,_/\__/_/_/_/\___/_//_/_//__/\__/\_,_/  {Fore.RESET}"
            )
        else:
            print(r" Loki (daemonized)")
        print(" YARA and IOC Scanner")
        print("")
        print(" Copyright (c) 2014-2023 Florian Roth")
        print(" Copyright (c) 2023-2024 c0m4r")
        print(f" version {__version__}\n")
        print(" GNU General Public License v3.0\n")
        print(" DISCLAIMER - USE AT YOUR OWN RISK & DON'T BE EVIL")
        print(Back.RESET)


def get_syslog_timestamp() -> str:
    """
    get syslog timestamp
    """
    date_obj = datetime.datetime.utcnow()
    date_str = date_obj.strftime("%Y%m%dT%H:%M:%SZ")
    return date_str
