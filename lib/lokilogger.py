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

import codecs
import datetime
import logging
import re
import socket
import sys
import traceback

from logging import handlers
from os import get_terminal_size

# Modules
from colorama import Fore, Back, Style
from colorama import init
import rfc5424logging

__version__ = "1.0.4"


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
    hostname = "NOTSET"
    alerts = 0
    warnings = 0
    notices = 0
    messagecount = 0
    only_relevant = False
    remote_logging = False
    debug = False
    linesep = "\n"

    def __init__(
        self,
        no_log_file,
        log_file,
        hostname,
        remote_host,
        remote_port,
        syslog_tcp,
        csv,
        only_relevant,
        debug,
        caller,
        custom_formatter=None,
    ):
        self.version = __version__
        self.no_log_file = no_log_file
        self.log_file = log_file
        self.hostname = hostname
        self.csv = csv
        self.only_relevant = only_relevant
        self.debug = debug
        self.caller = caller
        self.custom_formatter = custom_formatter

        # Colorization
        init()

        # Welcome
        if not self.csv:
            self.print_welcome()

        # Syslog server target
        if remote_host:
            try:
                # Create remote logger
                self.remote_logger = logging.getLogger("LOKI")
                self.remote_logger.setLevel(logging.DEBUG)
                socket_type = socket.SOCK_STREAM if syslog_tcp else socket.SOCK_DGRAM
                remote_syslog_handler = rfc5424logging.Rfc5424SysLogHandler(
                    address=(remote_host, remote_port),
                    facility=handlers.SysLogHandler.LOG_LOCAL3,
                    socktype=socket_type,
                )
                self.remote_logger.addHandler(remote_syslog_handler)
                self.remote_logging = True
            except Exception as e:
                print(f"Failed to create remote logger: {str(e)}")
                sys.exit(1)

    def log(self, mes_type, module, message) -> None:
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

        if self.only_relevant:
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

        # to syslog server
        if self.remote_logging:
            self.log_to_remotesys(message, mes_type, module)

    def log_format(self, type, message, *args) -> str:
        """
        log format
        """
        if not self.custom_formatter:
            return message.format(*args)
        else:
            return self.custom_formatter(type, message, args)

    def log_to_stdout(self, message, mes_type):
        """
        log to stdout
        """
        if self.csv:
            print(
                self.log_format(
                    self.STDOUT_CSV,
                    "{0},{1},{2},{3}",
                    get_syslog_timestamp(),
                    self.hostname,
                    mes_type,
                    message,
                )
            )

        else:
            try:
                reset_all = Style.NORMAL + Fore.RESET
                key_color = Fore.WHITE
                base_color = Back.BLACK + Fore.WHITE
                high_color = Fore.WHITE + Back.BLACK

                if mes_type == "NOTICE":
                    base_color = Fore.CYAN + "" + Back.BLACK
                    high_color = Fore.BLACK + "" + Back.CYAN
                elif mes_type == "INFO":
                    base_color = Fore.GREEN + "" + Back.BLACK
                    high_color = Fore.BLACK + "" + Back.GREEN
                elif mes_type == "WARNING":
                    base_color = Fore.YELLOW + "" + Back.BLACK
                    high_color = Fore.BLACK + "" + Back.YELLOW
                elif mes_type == "ALERT":
                    base_color = Fore.RED + "" + Back.BLACK
                    high_color = Fore.BLACK + "" + Back.RED
                elif mes_type == "DEBUG":
                    base_color = Fore.WHITE + "" + Back.BLACK
                    high_color = Fore.BLACK + "" + Back.WHITE
                elif mes_type == "ERROR":
                    base_color = Fore.MAGENTA + "" + Back.BLACK
                    high_color = Fore.WHITE + "" + Back.MAGENTA
                elif mes_type == "RESULT":
                    if "clean" in message.lower():
                        high_color = Fore.BLACK + Back.GREEN
                        base_color = Fore.GREEN + Back.BLACK
                    elif "suspicious" in message.lower():
                        high_color = Fore.BLACK + Back.YELLOW
                        base_color = Fore.YELLOW + Back.BLACK
                    else:
                        high_color = Fore.BLACK + Back.RED
                        base_color = Fore.RED + Back.BLACK

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
                    key_color + Style.BRIGHT + r"\1 " + base_color + Style.NORMAL,
                    message,
                )

                # Print to console
                if mes_type == "RESULT":
                    res_message = "\b\b%s %s" % (mes_type, message)
                    print(base_color + " " + res_message + " " + Back.BLACK)
                    print(Fore.WHITE + " " + Style.NORMAL)
                else:
                    sys.stdout.write(
                        "%s%s\b\b%s %s%s%s%s\n"
                        % (
                            reset_all,
                            base_color,
                            mes_type,
                            message,
                            Back.BLACK,
                            Fore.WHITE,
                            Style.NORMAL,
                        )
                    )

            except Exception:
                if self.debug:
                    traceback.print_exc()
                    sys.exit(1)
                print("Cannot print to cmd line - formatting error")

    def log_to_file(self, message, mes_type, module):
        """
        log to file
        """
        try:
            # Write to file
            with codecs.open(self.log_file, "a", encoding="utf-8") as logfile:
                if self.csv:
                    logfile.write(
                        self.log_format(
                            self.FILE_CSV,
                            "{0},{1},{2},{3},{4}{5}",
                            get_syslog_timestamp(),
                            self.hostname,
                            mes_type,
                            module,
                            message,
                            self.linesep,
                        )
                    )
                else:
                    logfile.write(
                        self.log_format(
                            self.FILE_LINE,
                            "{0} {1} LOKI: {2}: MODULE: {3} MESSAGE: {4}{5}",
                            get_syslog_timestamp(),
                            self.hostname,
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
            print("Cannot print line to log file {0}".format(self.log_file))

    def log_to_remotesys(self, message, mes_type, module):
        """
        log to remotesys
        """
        # Preparing the message
        syslog_message = self.log_format(
            self.SYSLOG_LINE,
            "LOKI: {0}: MODULE: {1} MESSAGE: {2}",
            mes_type.title(),
            module,
            message,
        )
        try:
            # Mapping LOKI's levels to the syslog levels
            if mes_type == "NOTICE":
                self.remote_logger.info(
                    syslog_message, extra={"msgid": str(self.messagecount)}
                )
            elif mes_type == "INFO":
                self.remote_logger.info(
                    syslog_message, extra={"msgid": str(self.messagecount)}
                )
            elif mes_type == "WARNING":
                self.remote_logger.warning(
                    syslog_message, extra={"msgid": str(self.messagecount)}
                )
            elif mes_type == "ALERT":
                self.remote_logger.critical(
                    syslog_message, extra={"msgid": str(self.messagecount)}
                )
            elif mes_type == "DEBUG":
                self.remote_logger.debug(
                    syslog_message, extra={"msgid": str(self.messagecount)}
                )
            elif mes_type == "ERROR":
                self.remote_logger.error(
                    syslog_message, extra={"msgid": str(self.messagecount)}
                )
        except Exception as e:
            if self.debug:
                traceback.print_exc()
                sys.exit(1)
            print(f"Error while logging to remote syslog server ERROR: {str(e)}")

    def print_welcome(self) -> None:
        """
        print welcome
        """
        if self.caller == "main":
            try:
                termsize = get_terminal_size().columns
            except Exception:
                termsize = 80
            print(str(Back.WHITE))
            print(" ".ljust(79) + Back.BLACK + Style.BRIGHT)
            if termsize > 80:
                print(
                    r"      __   ____  __ ______     __                         _            __"
                )
                print(
                    r"     / /  / __ \/ //_/  _/ ___/ /__ ____ __ _  ___  ___  (_)__ ___ ___/ /"
                )
                print(
                    r"    / /__/ /_/ / ,< _/ /  / _  / _ `/ -_)  ' \/ _ \/ _ \/ /_ // -_) _  / "
                )
                print(
                    r"   /____/\____/_/|_/___/  \_,_/\_,_/\__/_/_/_/\___/_//_/_//__/\__/\_,_/  "
                )
            else:
                print("   ")
                print(r"   Loki (daemonized)")
            print("   YARA and IOC Scanner")
            print("  ")
            print("   Copyright (c) 2014-2023 Florian Roth")
            print("   Copyright (c) 2023-2024 c0m4r")
            print(f"   version {__version__}")
            print("  ")
            print("   GNU General Public License v3.0")
            print("  ")
            print("   DISCLAIMER - USE AT YOUR OWN RISK & DON'T BE EVIL")
            print(str(Back.WHITE))
            print(" ".ljust(79) + Back.BLACK + Fore.GREEN)
            print(Fore.WHITE + "" + Back.BLACK)
        else:
            print("  ")
            print(Back.GREEN + " ".ljust(79) + Back.BLACK + Fore.GREEN)
            print("  ")
            print("  LOKI UPGRADER ")
            print("  ")
            print(Back.GREEN + " ".ljust(79) + Back.BLACK)
            print(Fore.WHITE + "" + Back.BLACK)


def get_syslog_timestamp() -> str:
    """
    get syslog timestamp
    """
    date_obj = datetime.datetime.utcnow()
    date_str = date_obj.strftime("%Y%m%dT%H:%M:%SZ")
    return date_str
