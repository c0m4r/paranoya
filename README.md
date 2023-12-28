![loki-daemonized-icon.png](loki-daemonized-icon.png)

## Loki (daemonized) - Simple IOC and YARA Scanner fork

A fork of [Loki - Simple IOC and YARA Scanner](https://github.com/Neo23x0/Loki), modified to support single file scan, as well as a daemon mode to accept scans in client/server manner.

The idea is that we can load all the rules once and then perform only individual file scans, which significantly reduces the load on hardware resources. This way, we can use Loki to scan, for example, files uploaded to the server.

Modifications tries to preserve original functionality, although I only care about Linux, so I do not guarantee compatibility with other platforms.

## Dependencies

* [Python3](https://www.python.org/)
  * [colorama](https://pypi.org/project/colorama/)
  * [future](https://pypi.org/project/future/)
  * [netaddr](https://pypi.org/project/netaddr/)
  * [psutil](https://pypi.org/project/psutil/)
  * [rfc5424-logging-handler](https://pypi.org/project/rfc5424-logging-handler/)
  * [yara-python](https://pypi.org/project/yara-python/)

## Installation

```
cd /opt
git clone https://github.com/c0m4r/Loki-daemonized.git
cd Loki-daemonized
python3 -m venv .
. bin/activate
pip3 install -r requirements.txt
./loki-upgrader.py --sigsonly
python3 loki.py -d --nolog --intense
deactivate
```

## Patch file

Patch file contains changes made to original loki.py.

To apply the patch on original Loki you have to convert loki.py before and after due to DOS line-ending characters used by original author, which the patch does not have.

```
wget https://github.com/Neo23x0/Loki/blob/5b7175882a9b7247714b47347c2f9dccdf38d894/loki.py
dos2unix loki.py
patch < loki-daemonized.patch
unix2dos loki.py
```

## Daemonized usage

#### Daemon (server)

Start as a daemon and bind on default localhost:1337

```
python3 loki.py -s 20000 -d --noindicator --csv --nolog --force --intense
```

You can also change default bind address/port with `--listen-host` and `--listen-port` args. Check `--help` for details.

#### Client

```
python3 loki_client.py /path/to/scan
```

## Changes

* Focuses on Linux
* Single file scan if given path is a file
* Daemon mode (-d) with listening socket (--listen-host, --listen-port) accepting scans requested from loki_client.py

Derived from https://github.com/Neo23x0/Loki/blob/5b7175882a9b7247714b47347c2f9dccdf38d894/loki.py

```diff
--- loki.py.original	2023-12-28 14:31:22.375121479 +0100
+++ loki.py	2023-12-28 14:31:51.105255142 +0100
@@ -48,6 +48,10 @@
 from lib.doublepulsar import DoublePulsar
 from lib.vuln_checker import VulnChecker
 
+# Daemon mode
+import socket
+from threading import Thread
+
 # Platform
 os_platform = ""
 
@@ -196,6 +200,14 @@
 
     def scan_path(self, path):
 
+        if os.path.isfile(path) and os_platform == "linux":
+            logger.log("INFO", "Init", "Single file mode for " + os_platform)
+            root = ''
+            directories = ''
+            files = [ path ]
+            loki.scan_path_files(root, directories, files)
+            return
+
         # Check if path exists
         if not os.path.exists(path):
             logger.log("ERROR", "FileScan", "None Existing Scanning Path %s ...  " % path)
@@ -210,9 +222,6 @@
                            "Skipping %s directory [fixed excludes] (try using --force, --allhds or --alldrives)" % skip)
                 return
 
-        # Counter
-        c = 0
-
         for root, directories, files in os.walk(path, onerror=walk_error, followlinks=False):
 
             # Skip paths that start with ..
@@ -233,6 +242,13 @@
                     newDirectories.append(dir)
             directories[:] = newDirectories
 
+            loki.scan_path_files(root, directories, files);
+
+    def scan_path_files(self, root, directories, files):
+
+            # Counter
+            c = 0
+
             # Loop through files
             for filename in files:
                 try:
@@ -475,10 +491,13 @@
                     # Now print the total result
                     if total_score >= args.a:
                         message_type = "ALERT"
+                        threading.current_thread().message = "ALERT"
                     elif total_score >= args.w:
                         message_type = "WARNING"
+                        threading.current_thread().message = "WARNING"
                     elif total_score >= args.n:
                         message_type = "NOTICE"
+                        threading.current_thread().message = "NOTICE"
 
                     if total_score < args.n:
                         continue
@@ -1452,6 +1471,14 @@
         print('LOKI\'s work has been interrupted by a human. Returning to Asgard.')
     sys.exit(0)
 
+def signal_handler_term(signal_name, frame):
+    try:
+        os.remove("loki.pid")
+    except:
+        pass
+    print('SIGTERM')
+    sys.exit(0)
+
 def main():
     """
     Argument parsing function
@@ -1468,6 +1495,9 @@
     parser.add_argument('-a', help='Alert score', metavar='alert-level', default=100)
     parser.add_argument('-w', help='Warning score', metavar='warning-level', default=60)
     parser.add_argument('-n', help='Notice score', metavar='notice-level', default=40)
+    parser.add_argument('-d', help='Run as a daemon', action='store_true', default=False)
+    parser.add_argument('--listen-host', help='Listen host for daemon mode', metavar='listen-host', default='localhost')
+    parser.add_argument('--listen-port', help='Listen port for daemon mode', metavar='listen-port', type=int, default=1337)
     parser.add_argument('--allhds', action='store_true', help='Scan all local hard drives (Windows only)', default=False)
     parser.add_argument('--alldrives', action='store_true', help='Scan all drives (including network drives and removable media)', default=False)
     parser.add_argument('--printall', action='store_true', help='Print all files that are scanned', default=False)
@@ -1532,9 +1562,17 @@
     # Signal handler for CTRL+C
     signal_module.signal(signal_module.SIGINT, signal_handler)
 
+    # Signal handler for SIGTERM
+    signal_module.signal(signal_module.SIGTERM, signal_handler_term)
+
     # Argument parsing
     args = main()
 
+    # Save pidfile
+    if args.d == True:
+        with open('loki.pid', 'w', encoding='utf-8') as f:
+            f.write(str(os.getpid()))
+
     # Remove old log file
     if os.path.exists(args.l):
         os.remove(args.l)
@@ -1553,8 +1591,17 @@
         updateLoki(sigsOnly=False)
         sys.exit(0)
 
+    if os_platform == "linux":
+        for key, val in platform.freedesktop_os_release().items():
+            if key == 'PRETTY_NAME':
+                platform_pretty_name = val
+        platform_machine = platform.machine()
+        platform_full = platform_pretty_name + " (" + platform_machine + ")"
+    else:
+        platform_full = getPlatformFull()
+
     logger.log("NOTICE", "Init", "Starting Loki Scan VERSION: {3} SYSTEM: {0} TIME: {1} PLATFORM: {2}".format(
-        getHostname(os_platform), getSyslogTimestamp(), getPlatformFull(), logger.version))
+        getHostname(os_platform), getSyslogTimestamp(), platform_full, logger.version))
 
     # Loki
     loki = Loki(args.intense)
@@ -1619,6 +1666,45 @@
                 loki.scan_path(defaultPath)
 
         # Linux & macOS
+        elif args.d == True:
+           logger.log("NOTICE", "Init", "Loki-daemonized (c) 2023 c0m4r")
+           server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+           server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
+           server.bind((args.listen_host, args.listen_port))
+           server.listen(5)
+           
+           def handle_client(client_socket, address):
+               size = 1024
+               while True:
+                   try:
+                       clientid = threading.current_thread().name
+                       threading.current_thread().message = ''
+                       data = client_socket.recv(size)
+                       logger.log("INFO", "Init", "Received: " + data.decode() + " from: " + str(address[0]) + ":" + str(address[1]))
+                       loki.scan_path(data.decode())
+                       # Result ----------------------------------------------------------
+                       if threading.current_thread().message == 'ALERT':
+                           logger.log("RESULT", "Results", "Indicators detected! (Client: " + clientid + ")")
+                           client_socket.send('RESULT: Indicators detected!'.encode())
+                       elif threading.current_thread().message == 'WARNING':
+                           logger.log("RESULT", "Results", "Suspicious objects detected! (Client: " + clientid + ")")
+                           client_socket.send('RESULT: Suspicious objects detected!'.encode())
+                       else:
+                           logger.log("RESULT", "Results", "SYSTEM SEEMS TO BE CLEAN. (Client: " + clientid + ")")
+                           client_socket.send('RESULT: SYSTEM SEEMS TO BE CLEAN.'.encode())
+
+                       logger.log("NOTICE", "Results", "Finished LOKI Scan CLIENT: %s SYSTEM: %s TIME: %s" % (clientid, getHostname(os_platform), getSyslogTimestamp()))
+                       client_socket.close()
+                       return False
+                   except socket.error:
+                       client_socket.close()
+                       return False
+
+           logger.log("NOTICE", "Init", "Listening on " + args.listen_host + ":" + str(args.listen_port))
+           while True:
+               client, addr = server.accept()
+               Thread(target=handle_client, args=(client, addr), name=str(addr[0]) + ":" + str(addr[1])).start()
+
         else:
            loki.scan_path(defaultPath)
 
```

## Usage

```
usage: loki.py [-h] [-p path] [-s kilobyte] [-l log-file] [-r remote-loghost] [-t remote-syslog-port] [-a alert-level] [-w warning-level] [-n notice-level] [-d] [--listen-host listen-host]
               [--listen-port listen-port] [--allhds] [--alldrives] [--printall] [--allreasons] [--noprocscan] [--nofilescan] [--vulnchecks] [--nolevcheck] [--scriptanalysis] [--rootkit] [--noindicator]
               [--dontwait] [--intense] [--csv] [--onlyrelevant] [--nolog] [--update] [--debug] [--maxworkingset MAXWORKINGSET] [--syslogtcp] [--logfolder log-folder] [--nopesieve] [--pesieveshellc]
               [--python PYTHON] [--nolisten] [--excludeprocess EXCLUDEPROCESS] [--force] [--version]

Loki - Simple IOC Scanner

options:
  -h, --help            show this help message and exit
  -p path               Path to scan
  -s kilobyte           Maximum file size to check in KB (default 5000 KB)
  -l log-file           Log file
  -r remote-loghost     Remote syslog system
  -t remote-syslog-port
                        Remote syslog port
  -a alert-level        Alert score
  -w warning-level      Warning score
  -n notice-level       Notice score
  -d                    Run as a daemon
  --listen-host listen-host
                        Listen host for daemon mode
  --listen-port listen-port
                        Listen port for daemon mode
  --allhds              Scan all local hard drives (Windows only)
  --alldrives           Scan all drives (including network drives and removable media)
  --printall            Print all files that are scanned
  --allreasons          Print all reasons that caused the score
  --noprocscan          Skip the process scan
  --nofilescan          Skip the file scan
  --vulnchecks          Run the vulnerability checks
  --nolevcheck          Skip the Levenshtein distance check
  --scriptanalysis      Statistical analysis for scripts to detect obfuscated code (beta)
  --rootkit             Skip the rootkit check
  --noindicator         Do not show a progress indicator
  --dontwait            Do not wait on exit
  --intense             Intense scan mode (also scan unknown file types and all extensions)
  --csv                 Write CSV log format to STDOUT (machine processing)
  --onlyrelevant        Only print warnings or alerts
  --nolog               Don't write a local log file
  --update              Update the signatures from the "signature-base" sub repository
  --debug               Debug output
  --maxworkingset MAXWORKINGSET
                        Maximum working set size of processes to scan (in MB, default 100 MB)
  --syslogtcp           Use TCP instead of UDP for syslog logging
  --logfolder log-folder
                        Folder to use for logging when log file is not specified
  --nopesieve           Do not perform pe-sieve scans
  --pesieveshellc       Perform pe-sieve shellcode scan
  --python PYTHON       Override default python path
  --nolisten            Dot not show listening connections
  --excludeprocess EXCLUDEPROCESS
                        Specify an executable name to exclude from scans, can be used multiple times
  --force               Force the scan on a certain folder (even if excluded with hard exclude in LOKI's code
  --version             Shows welcome text and version of loki, then exit
```

---
## Licensed under GPL 3.0
* Loki - Simple IOC Scanner Copyright (c) 2015 Florian Roth
* Loki (daemonized) - Simple IOC and YARA Scanner fork (c) 2023 c0m4r

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/
