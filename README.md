Port Scanner 

About

This is a multi-threaded, fast port scanner written in Python. Not your average toy scanner—this beast can:

* Scan TCP ports with speed
* Grab banners (with SSL support)
* Detect basic OS info
* Log scan results
* Detect known vulnerable services like:

  * `vsftpd 2.3.4` (CVE-2011-2523)
  * `Apache/2.2.8` (CVE-2007-5000)

No external libraries. Just raw sockets, threads, and Python power.

Why tho?

Because sometimes you need to poke the box harder than `nmap` does by default. And because you're a real one who likes to learn and break stuff responsibly.



Features

* Threaded scanning (fast)
* Banner grabbing over SSL and plain TCP
* OS fingerprinting (basic)
* Logs results to `scan_results.log`
* CLI-powered. Script-kiddie resistant.

---

Usage

```bash
python3 portscanner.py <target> <start_port> <end_port> [-t THREADS]
```

### Example:

```bash
python3 portscanner.py scanme.nmap.org 20 100 -t 50
```

This scans ports 20 to 100 on `scanme.nmap.org` using 50 threads.

---

Output Example

```text
Scanning 45.33.32.156 from port 20 to 100 using 50 threads.
[+] Port 22: OPEN
    └─ Banner: OpenSSH 7.6p1 Ubuntu-4ubuntu0.3
[+] Port 80: OPEN
    └─ Banner: Apache/2.2.8 (Ubuntu)
    VULNERABLE: CVE-2007-5000 (Apache DoS)
[*] TTL Guess: 45.33.32.156
[*] Host OS Guess: Linux 5.15.0
```

OS Detection

Super basic OS guessing based on TTL and local platform info. Not accurate, but better than nothing.


Logging

All results get dumped into `scan_results.log` for later analysis.


Disclaimer

> FOR EDUCATIONAL PURPOSES ONLY
> Only scan hosts you own or have explicit permission to scan.
> This tool is loud and might get flagged by firewalls or IDS so tread carefully


Requirements

* Python 3.6+
* The following Python modules would need to be installed if you don't have them on your machine:
* socket
* ssl
* threading
* queue
* logging
* argparse
* platform


Possible and Potential Future Plans 

* UDP scanning
* OS detection via TTL distance
* CVE database integration
* Dark mode for terminal output (just kidding... unless?)


Author

Kevin Hamusute — a Zambian teen hacker who talks to AI more than humans and lives by the code.

Support & Shoutout

If this helped you:

* Drop a ⭐ on GitHub
* Spread the word, especially on LinkedIn and X
* Don't snitch

Stay paranoid, stay ethical and stay curious
