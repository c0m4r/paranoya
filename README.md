## Loki (daemonized) - Simple IOC and YARA Scanner fork

A fork of [Loki](https://github.com/Neo23x0/Loki), modified to support single file scan, as well as a daemon mode to accept scans in client/server manner.

The idea is that we can load all the rules once and then perform only individual file scans, which significantly reduces the load on hardware resources. This way, we can use Loki to scan, for example, files uploaded to the server.

Modifications tries to preserve original functionalit, although I only care about Linux, so I do not guarantee compatibility with other platforms.

## Installation

```
git clone https://github.com/c0m4r/Loki-daemonized.git Loki
cd Loki
python3 -m venv .
. bin/activate
pip3 install -r requirements.txt
./loki-upgrader.py
deactivate
```

## Usage

#### Daemon (server)

Start as a daemon and bind on default localhost:1337

```
python3 loki.py -s 20000 -d --noprocscan --noindicator --dontwait --intense --csv --nolog --force
```

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
--- loki.py.original	2023-12-27 15:10:45.935734777 +0100
+++ loki.py	2023-12-27 10:25:00.047296255 +0100
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
@@ -1468,6 +1484,9 @@
     parser.add_argument('-a', help='Alert score', metavar='alert-level', default=100)
     parser.add_argument('-w', help='Warning score', metavar='warning-level', default=60)
     parser.add_argument('-n', help='Notice score', metavar='notice-level', default=40)
+    parser.add_argument('-d', help='Run as a daemon', action='store_true', default=False)
+    parser.add_argument('--listen-host', help='Listen host for daemon mode', metavar='listen-host', default='localhost')
+    parser.add_argument('--listen-port', help='Listen port for daemon mode', metavar='listen-port', type=int, default=1337)
     parser.add_argument('--allhds', action='store_true', help='Scan all local hard drives (Windows only)', default=False)
     parser.add_argument('--alldrives', action='store_true', help='Scan all drives (including network drives and removable media)', default=False)
     parser.add_argument('--printall', action='store_true', help='Print all files that are scanned', default=False)
@@ -1619,6 +1638,50 @@
                 loki.scan_path(defaultPath)
 
         # Linux & macOS
+        elif args.d == True:
+           logger.log("INFO", "Init", "Running daemon mode")
+           server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+           server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
+           server.bind((args.listen_host, args.listen_port))
+           server.listen(5)
+              
+           def handle_client(client_socket, address):
+               size = 1024
+               while True:
+                   try:
+                       data = client_socket.recv(size)
+                       print('Received: ' + data.decode() + ' from: ' + str(address[0]) + ':' + str(address[1]))
+                       loki.scan_path(data.decode())
+                       # Result ----------------------------------------------------------
+                       logger.log("NOTICE", "Results", "Results: {0} alerts, {1} warnings, {2} notices".format(logger.alerts, logger.warnings, logger.notices))
+                       if logger.alerts:
+                           logger.log("RESULT", "Results", "Indicators detected!")
+                           logger.log("RESULT", "Results", "Loki recommends checking the elements on virustotal.com or Google and triage with a "
+                                                "professional tool like THOR https://nextron-systems.com/thor in corporate networks.")
+                           client_socket.send('RESULT: Indicators detected!'.encode())
+                           logger.alerts = 0
+                       elif logger.warnings:
+                           logger.log("RESULT", "Results", "Suspicious objects detected!")
+                           logger.log("RESULT", "Results", "Loki recommends a deeper analysis of the suspicious objects.")
+                           client_socket.send('RESULT: Suspicious objects detected!'.encode())
+                           logger.warnings = 0
+                       else:
+                           logger.log("RESULT", "Results", "SYSTEM SEEMS TO BE CLEAN.")
+                           client_socket.send('RESULT: SYSTEM SEEMS TO BE CLEAN.'.encode())
+
+                       logger.log("INFO", "Results", "Please report false positives via https://github.com/Neo23x0/signature-base")
+                       logger.log("NOTICE", "Results", "Finished LOKI Scan SYSTEM: %s TIME: %s" % (getHostname(os_platform), getSyslogTimestamp()))
+                       client_socket.close()
+                       return False
+                   except socket.error:
+                       client_socket.close()
+                       return False
+
+           print('Listening...')
+           while True:
+               client, addr = server.accept()
+               Thread(target=handle_client, args=(client, addr)).start()
+
         else:
            loki.scan_path(defaultPath)
```

---
## Licensed under GPL 3.0
* Loki - Simple IOC Scanner Copyright (c) 2015 Florian Roth
* Modifications by c0m4r 2023
