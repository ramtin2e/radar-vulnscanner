#!/usr/bin/env python3
"""
radar.py — a local machine security scanner
made by Ramtin Karimi

Radar sweeps your machine for the stuff that quietly sits there waiting
to cause problems: open ports that shouldn't be open, config files with
the wrong permissions, SSH settings that were "temporary", and kernel
parameters that nobody ever touched after install.

No pip install. No external libraries. Just Python and stdlib.
Run it, read the output, fix the things that are red.
"""

import sys
import os
import socket
import subprocess
import json
import platform
import time
import threading
import argparse
import ipaddress
import stat
from datetime import datetime


# ── colors ────────────────────────────────────────────────────
# ANSI escape codes wrapped in a class so we can strip them all
# at once when the terminal doesn't support them.
#
# Windows note: cmd.exe and older PowerShell don't process ANSI
# codes by default — they just print the raw escape characters
# (the ←[96m garbage). We fix this two ways: try to enable VT mode
# via the Windows console API, and fall back to no-color if that
# doesn't work. Either way, no garbled output.

def _enable_windows_ansi():
    
    if platform.system() != "Windows":
        return True  # not our problem on Linux/macOS
    try:
        import ctypes
        import ctypes.wintypes
        kernel32 = ctypes.windll.kernel32
        handle   = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode     = ctypes.wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"

    @staticmethod
    def disable():
        # wipe every attribute so escape sequences vanish from output
        for attr in ["RESET","BOLD","DIM","RED","YELLOW","GREEN","CYAN",
                     "BLUE","MAGENTA","WHITE","GRAY","BG_RED"]:
            setattr(C, attr, "")


# ── severity display ──────────────────────────────────────────
# every finding gets one of these levels. CRITICAL means drop
# everything right now, OK means you're good, everything else
# lives somewhere in between.
#
# these are functions rather than module-level dicts so that the
# C.* values are read at print time (after main() has decided
# whether to enable or disable colors), not at import time.

def _sev_color(sev):
    return {
        "CRITICAL": C.RED,
        "HIGH":     C.RED,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.CYAN,
        "INFO":     C.GREEN,
        "OK":       C.GREEN,
    }.get(sev, C.WHITE)

def _sev_symbol(sev):
    return {
        "CRITICAL": "✘✘",
        "HIGH":     "✘",
        "MEDIUM":   "⚠",
        "LOW":      "i",
        "INFO":     ".",
        "OK":       "✔",
    }.get(sev, "?")

# how many points we knock off your security score per finding
SEV_COST = {
    "CRITICAL": 30,
    "HIGH":     15,
    "MEDIUM":   7,
    "LOW":      2,
}

def finding(severity, title, detail=""):
    return {"severity": severity, "title": title, "detail": detail}

def ok(title):
    return finding("OK", title)

def info(title, detail=""):
    return finding("INFO", title, detail)


# ── the ASCII banner ──────────────────────────────────────────
# built as a function (not a module-level f-string) so that color
# codes are read from C.* at call time — after main() has already
# decided whether to enable or disable them. if it were a static
# f-string the escape codes would get baked in at import time and
# C.disable() wouldn't be able to strip them.

def _make_banner():
    return (
        f"{C.CYAN}{C.BOLD}\n"
        f"  ██████╗  █████╗ ██████╗  █████╗ ██████╗\n"
        f"  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗\n"
        f"  ██████╔╝███████║██║  ██║███████║██████╔╝\n"
        f"  ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗\n"
        f"  ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║\n"
        f"  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\n"
        f"{C.RESET}{C.GRAY}  local machine security scanner  ·  by Ramtin Karimi  ·  v1.0.0{C.RESET}\n"
    )

def print_banner():
    print(_make_banner())
    w = 60
    sep = "  " + "─" * w
    # C.WHITE is invisible on light-background terminals (like Windows cmd)
    # because it's literally white text. when colors are disabled it also
    # becomes an empty string "", making the values vanish entirely.
    # dropping C.WHITE means the text just uses the terminal's default
    # foreground color — readable on both dark and light backgrounds.
    print(sep)
    print(f"  {C.GRAY}host   {C.RESET}{socket.gethostname()}")
    print(f"  {C.GRAY}os     {C.RESET}{platform.system()} {platform.release()} ({platform.machine()})")
    print(f"  {C.GRAY}time   {C.RESET}{datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
    print(sep + "\n")


# ── spinner ────────────────────────────────────────────────────
# shows something's happening while a check runs in the background.
# uses a daemon thread so it can't accidentally block exit.

class Spinner:
    _frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, label):
        self.label   = label
        self._done   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        i = 0
        while not self._done.is_set():
            frame = self._frames[i % len(self._frames)]
            sys.stdout.write(f"\r  {C.CYAN}{frame}{C.RESET}  {self.label}  ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._done.set()
        self._thread.join()
        # clear the spinner line
        sys.stdout.write("\r" + " " * (len(self.label) + 16) + "\r")
        sys.stdout.flush()


# ── output helpers ────────────────────────────────────────────

def section(title, icon="◈"):
    print(f"\n  {C.BLUE}{C.BOLD}{icon}  {title.upper()}{C.RESET}")
    print(f"  {C.BLUE}{'─' * 66}{C.RESET}")

def show_finding(f):
    sev    = f["severity"]
    color  = _sev_color(sev)
    symbol = _sev_symbol(sev)
    print(f"  {color}{C.BOLD}[{symbol}]{C.RESET}  {C.WHITE}{f['title']}{C.RESET}")
    if f.get("detail"):
        for line in f["detail"].splitlines():
            print(f"        {C.GRAY}{line}{C.RESET}")


PORT_DB = {
    21:    ("FTP",            "HIGH",     "transfers files in plain text — anyone on the network can read your data. switch to SFTP or SCP."),
    22:    ("SSH",            "LOW",      "this is fine if it's intentional. make sure you're using key auth and PasswordAuthentication is off."),
    23:    ("Telnet",         "CRITICAL", "sends everything including passwords in clear text over the network. there is no scenario where you want this open. replace with SSH immediately."),
    25:    ("SMTP",           "MEDIUM",   "an open mail relay will get you on every spam blacklist within hours. restrict relay to authenticated users only."),
    53:    ("DNS",            "LOW",      "make sure only the resolvers you expect can query this. open recursion can be abused for amplification attacks."),
    80:    ("HTTP",           "MEDIUM",   "plain HTTP means passwords and session cookies cross the wire unencrypted. set up a redirect to HTTPS."),
    110:   ("POP3",           "MEDIUM",   "clear-text mail protocol. your email credentials are visible to anyone between you and the server. use POP3S on 995."),
    111:   ("RPC portmapper", "HIGH",     "opens the door to further RPC enumeration. disable unless you specifically need NFS or other RPC services."),
    135:   ("MS-RPC",         "HIGH",     "Windows RPC endpoint mapper. this gets targeted a lot. firewall it off from anything that doesn't need it."),
    137:   ("NetBIOS-NS",     "HIGH",     "leaks hostnames and workgroup names to anyone who asks. disable NetBIOS if you don't need legacy Windows networking."),
    139:   ("NetBIOS-SSN",    "HIGH",     "SMBv1 over NetBIOS. SMBv1 is what WannaCry used. disable it."),
    143:   ("IMAP",           "MEDIUM",   "clear-text mail access. use IMAPS on 993 instead."),
    161:   ("SNMP",           "HIGH",     "SNMPv1 and v2 community strings are just plain text passwords. if you need SNMP, use v3 with auth and encryption."),
    389:   ("LDAP",           "HIGH",     "directory queries and credentials go over the wire unencrypted. use LDAPS on 636."),
    443:   ("HTTPS",          "INFO",     "looks good. just make sure your TLS version is 1.2 or higher and your cert isn't expiring soon."),
    445:   ("SMB",            "HIGH",     "direct SMB without NetBIOS. patch for EternalBlue (MS17-010) if you haven't already, and disable SMBv1."),
    512:   ("rexec",          "CRITICAL", "remote execution with a clear-text password. this is from the 1980s. it should not be running."),
    513:   ("rlogin",         "CRITICAL", "legacy remote login, no encryption, often no real auth. kill it."),
    514:   ("rsh",            "CRITICAL", "remote shell with no encryption. same family as rlogin. should not exist on any modern system."),
    554:   ("RTSP",           "MEDIUM",   "streaming protocol, common on IP cameras. check whether you've changed the default credentials."),
    631:   ("CUPS/IPP",       "LOW",      "printer service. fine locally, but bind it to 127.0.0.1 if it doesn't need to be network-accessible."),
    1433:  ("MSSQL",          "HIGH",     "SQL Server should never be directly internet-facing. firewall it to only the app servers that need it."),
    1521:  ("Oracle DB",      "HIGH",     "same deal as MSSQL — database ports should be firewalled tightly, not exposed to the whole network."),
    2049:  ("NFS",            "HIGH",     "NFS exports can hand your entire filesystem to anyone on the LAN who asks nicely. restrict exports carefully."),
    2375:  ("Docker daemon",  "CRITICAL", "unauthenticated Docker API. anyone who can reach this port owns the host — they can mount / and do whatever they want."),
    2376:  ("Docker TLS",     "MEDIUM",   "Docker with TLS is better, but make sure client certificate auth is actually being enforced, not just available."),
    3000:  ("dev server",     "LOW",      "Node, Grafana, or something else running on 3000. fine for local dev, but shouldn't be public-facing."),
    3306:  ("MySQL",          "HIGH",     "bind MySQL to 127.0.0.1. it should never be accepting connections from outside the machine unless you have a very specific reason."),
    3389:  ("RDP",            "HIGH",     "exposed RDP is one of the top entry points for ransomware. if you need remote desktop, put it behind a VPN."),
    4444:  ("Metasploit",     "CRITICAL", "this is the default Metasploit handler port. if this is open on a non-pentest machine, something is very wrong."),
    5000:  ("dev/UPnP",       "LOW",      "often Flask or a UPnP service. fine locally, but bind to loopback if it's just for development."),
    5432:  ("PostgreSQL",     "HIGH",     "same as MySQL — databases should be bound to localhost, not 0.0.0.0. add a strong password too."),
    5900:  ("VNC",            "HIGH",     "VNC is often set up with weak passwords or none at all. if you need remote desktop, tunnel VNC over SSH."),
    5985:  ("WinRM HTTP",     "HIGH",     "Windows Remote Management over plain HTTP. use the HTTPS version (5986) and restrict access."),
    5986:  ("WinRM HTTPS",    "MEDIUM",   "WinRM over HTTPS is better. make sure you've got a valid cert and restricted which hosts can connect."),
    6379:  ("Redis",          "HIGH",     "Redis has no authentication by default and attackers know it. people lose servers to this all the time — it's used to write SSH keys into authorized_keys."),
    6443:  ("Kubernetes API", "HIGH",     "K8s API server. lock it down with RBAC, valid certs, and don't expose it to the internet."),
    8080:  ("HTTP-alt",       "MEDIUM",   "common proxy or dev server port. check whether this needs auth and whether it should be public."),
    8443:  ("HTTPS-alt",      "LOW",      "HTTPS on a non-standard port. verify the cert is valid and the service is intentional."),
    8888:  ("Jupyter",        "HIGH",     "Jupyter Notebook. by default it has no real authentication. if this is exposed, someone can run arbitrary code on your machine."),
    9000:  ("PHP-FPM/Portainer","HIGH",   "PHP-FPM process manager or Portainer. both can be escalated to full server control without proper auth."),
    9090:  ("Prometheus",     "MEDIUM",   "Prometheus metrics endpoint. usually doesn't need auth out of the box, but leaks a lot of info about your infrastructure."),
    9200:  ("Elasticsearch",  "CRITICAL", "Elasticsearch has no authentication in its default config. this has caused more data breaches than almost anything else on this list."),
    9300:  ("ES transport",   "HIGH",     "Elasticsearch cluster transport port. keep this on a private network only."),
    11211: ("Memcached",      "HIGH",     "Memcached UDP can be weaponized for massive DDoS amplification, and there's no auth. firewall UDP 11211 externally."),
    27017: ("MongoDB",        "CRITICAL", "MongoDB's default config is no authentication. this has leaked millions of records. if this is open, check immediately whether auth is on."),
    27018: ("MongoDB shard",  "HIGH",     "MongoDB sharding port. same auth story applies. restrict to internal network."),
}

# ports we scan — the dangerous ones plus a few common alternates
SCAN_PORTS = sorted(PORT_DB.keys()) + [8000, 8001, 8008, 4200, 4443, 7000, 7001, 9100, 50000]
SCAN_PORTS = sorted(set(SCAN_PORTS))


def _try_connect(host, port, timeout=0.5):
    """attempt a TCP connect and return True if it works"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _grab_banner(host, port, timeout=1.0):
    """try to read a banner from an open port; useful context for the report"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(256).decode(errors="replace").strip()[:80]
            except Exception:
                return ""
    except Exception:
        return ""


def scan_ports(host="127.0.0.1"):
    """
    blast through all the target ports using threads, then report
    on anything that's open. grabs a banner too where it can.
    """
    findings = []
    results  = {}

    # kick off one thread per port — they all run in parallel
    threads = []
    for port in SCAN_PORTS:
        t = threading.Thread(target=lambda p=port: results.__setitem__(p, _try_connect(host, p)), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    open_ports = [p for p, is_open in sorted(results.items()) if is_open]

    if not open_ports:
        findings.append(ok("no well-known risky ports found open on localhost"))
        return findings

    for port in open_ports:
        if port in PORT_DB:
            name, sev, desc = PORT_DB[port]
            banner = _grab_banner(host, port)
            detail = desc
            if banner:
                detail += f"\n  banner: {banner}"
            findings.append(finding(sev, f"port {port}/tcp is open  —  {name}", detail))
        else:
            findings.append(finding("LOW", f"port {port}/tcp is open  —  unrecognized service",
                                    "not in the known-port database. worth investigating if you weren't expecting this."))

    return findings


# the boring config stuff that quietly creates privilege escalation
# paths. most of these take five minutes to fix once you know
# they're there, which is kind of the whole point.

def check_world_writable_files():
    """
    files in /etc or system bin dirs that anyone can write to.
    if an attacker can write to /etc/cron.d they can run anything.
    """
    findings = []
    dirs_to_check = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    bad = []

    for d in dirs_to_check:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.scandir(d):
                try:
                    if entry.stat().st_mode & stat.S_IWOTH:
                        bad.append(entry.path)
                except (PermissionError, OSError):
                    pass
        except PermissionError:
            pass

    if bad:
        detail = "\n  ".join(bad[:8])
        if len(bad) > 8:
            detail += f"\n  ... and {len(bad) - 8} more"
        findings.append(finding("HIGH",
            f"world-writable files in sensitive directories ({len(bad)} found)",
            detail))
    else:
        findings.append(ok("no world-writable files in sensitive system directories"))

    return findings


def check_suid_binaries():
    """
    SUID binaries run as root no matter who executes them.
    the ones in the whitelist below are expected.. everything
    else is worth a second look.
    """
    findings = []

    # these are the ones you'd normally expect to see as SUID
    expected_suid = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/bin/su", "/usr/bin/su",
        "/usr/bin/pkexec", "/bin/ping", "/usr/bin/ping",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chfn",
        "/usr/bin/chsh", "/usr/bin/at", "/usr/bin/crontab",
        "/usr/sbin/pppd", "/usr/bin/fusermount",
    }

    unexpected = []
    for d in ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.scandir(d):
                try:
                    if (entry.stat().st_mode & stat.S_ISUID) and entry.path not in expected_suid:
                        unexpected.append(entry.path)
                except (PermissionError, OSError):
                    pass
        except PermissionError:
            pass

    if unexpected:
        detail = "\n  ".join(unexpected[:10])
        findings.append(finding("MEDIUM",
            f"unexpected SUID binaries found ({len(unexpected)})",
            detail + "\n  these all run as root — investigate anything unfamiliar"))
    else:
        findings.append(ok("no unexpected SUID binaries in system directories"))

    return findings


def check_critical_file_perms():
    """
    /etc/shadow readable by the wrong people, /etc/sudoers writable,
    that kind of thing. these are the classic escalation paths.
    """
    findings = []

    # file → (correct mode, severity if wrong)
    should_be = {
        "/etc/passwd":          (0o644, "MEDIUM"),
        "/etc/shadow":          (0o640, "HIGH"),
        "/etc/sudoers":         (0o440, "HIGH"),
        "/etc/ssh/sshd_config": (0o600, "MEDIUM"),
    }

    for path, (expected, sev) in should_be.items():
        if not os.path.exists(path):
            continue
        try:
            actual = stat.S_IMODE(os.stat(path).st_mode)
            if actual != expected:
                findings.append(finding(sev,
                    f"{path}  has wrong permissions",
                    f"expected {oct(expected)},  got {oct(actual)}  —  fix with: chmod {oct(expected)[2:]} {path}"))
            else:
                findings.append(ok(f"{path}  permissions look correct  ({oct(actual)})"))
        except PermissionError:
            findings.append(info(f"can't check {path}  (run as root to see this)"))

    return findings


def check_empty_passwords():
    """reads /etc/shadow and looks for accounts with no password set"""
    findings = []
    try:
        empty = []
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empty.append(parts[0])

        if empty:
            findings.append(finding("CRITICAL",
                "accounts with empty passwords",
                ", ".join(empty) + "\n  set a password or lock these accounts immediately"))
        else:
            findings.append(ok("no empty passwords found in /etc/shadow"))

    except PermissionError:
        findings.append(info("can't read /etc/shadow without root  —  skipping empty password check"))
    except FileNotFoundError:
        findings.append(info("/etc/shadow not found  (are you on Linux?)"))

    return findings


def check_ssh_config():
    """
    parses sshd_config and flags the settings people forget to change
    after standing up a new server. PermitRootLogin yes is by far the
    most common one.
    """
    findings = []
    cfg_path = "/etc/ssh/sshd_config"

    if not os.path.exists(cfg_path):
        findings.append(info("sshd_config not found  —  SSH might not be installed"))
        return findings

    try:
        content = open(cfg_path).read().lower()
    except PermissionError:
        findings.append(info("can't read sshd_config without root"))
        return findings

    # things that should raise a flag
    bad_settings = [
        ("permitrootlogin yes",       "HIGH",     "PermitRootLogin is YES — attackers will try root directly. set it to 'no' or 'prohibit-password'."),
        ("passwordauthentication yes","MEDIUM",   "PasswordAuthentication is YES — brute force is trivially easy. switch to key-based auth."),
        ("permitemptypasswords yes",  "CRITICAL", "PermitEmptyPasswords is YES — this allows login with no password at all."),
        ("x11forwarding yes",         "LOW",      "X11Forwarding is on — disable it unless you actually need to forward GUI apps over SSH."),
        ("usedns yes",                "LOW",      "UseDNS YES adds login latency and can cause issues — usually unnecessary."),
    ]

    # things that are good to see
    good_settings = [
        ("permitrootlogin no",          "root SSH login is disabled  ✓"),
        ("passwordauthentication no",   "password auth is off, keys only  ✓"),
        ("protocol 2",                  "SSH protocol 2 enforced  ✓"),
    ]

    any_bad  = False
    for pattern, sev, msg in bad_settings:
        if pattern in content:
            findings.append(finding(sev, f"SSH config: {msg.split('—')[0].strip()}", msg))
            any_bad = True

    for pattern, msg in good_settings:
        if pattern in content:
            findings.append(ok(f"SSH config: {msg}"))

    if not any_bad:
        findings.append(ok("SSH config: no obvious misconfigurations found"))

    return findings


def check_firewall():
    """
    checks whether ufw or iptables is actually doing something.
    a lot of people install a firewall and forget to enable it.
    """
    findings = []

    # try ufw first — it's the most common on Ubuntu/Debian
    try:
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if "inactive" in result.stdout.lower():
                findings.append(finding("HIGH",
                    "UFW is installed but not active",
                    "you have a firewall but it's switched off. run: sudo ufw enable"))
            else:
                status_line = result.stdout.strip().split("\n")[0]
                findings.append(ok(f"UFW firewall is active  —  {status_line}"))
            return findings
    except FileNotFoundError:
        pass  # no ufw, try iptables
    except subprocess.TimeoutExpired:
        pass

    # fall back to iptables
    try:
        result = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # a default all-ACCEPT policy with no rules is basically no firewall
            lines = result.stdout.strip().split("\n")
            rule_count = sum(1 for l in lines if l.startswith("-") or (l and not l.startswith("Chain") and not l.startswith("target")))
            if rule_count < 2:
                findings.append(finding("MEDIUM",
                    "iptables is present but has no meaningful rules",
                    "default ACCEPT on everything is effectively no firewall."))
            else:
                findings.append(ok("iptables rules are in place"))
            return findings
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        pass

    # nothing found
    findings.append(finding("HIGH",
        "no firewall detected",
        "install and enable ufw: sudo apt install ufw && sudo ufw enable\n"
        "or configure iptables rules manually."))
    return findings


def check_running_services():
    """
    scans the process list for services that are almost never intentional
    on a modern system — Telnet, FTP, rsh, that sort of thing.
    """
    findings = []

    # service name substring → (severity, why it's a problem)
    risky = {
        "telnetd":  ("CRITICAL", "Telnet daemon is running — unencrypted remote access. replace with SSH."),
        "ftpd":     ("HIGH",     "FTP daemon is running — clear-text file transfer. use SFTP."),
        "vsftpd":   ("HIGH",     "vsftpd is running — if you need file transfer, use SFTP instead."),
        "rshd":     ("CRITICAL", "rsh daemon is running — legacy unencrypted remote shell."),
        "rlogind":  ("CRITICAL", "rlogin daemon is running — legacy unencrypted remote login."),
        "snmpd":    ("MEDIUM",   "SNMP daemon is running — make sure you're using v3 with auth and privacy."),
        "xinetd":   ("MEDIUM",   "xinetd super-server is running — check which sub-services it's hosting."),
        "inetd":    ("MEDIUM",   "inetd is running — same as xinetd, audit the services it manages."),
        "exim4":    ("LOW",      "Exim4 MTA is running — make sure it's not an open relay."),
        "sendmail": ("LOW",      "sendmail is running — make sure relay is restricted."),
    }

    try:
        result = subprocess.run(["ps", "aux", "--no-headers"], capture_output=True, text=True, timeout=5)
        running = result.stdout.lower()

        found = False
        for svc, (sev, msg) in risky.items():
            if svc in running:
                findings.append(finding(sev, f"risky service detected: {svc}", msg))
                found = True

        if not found:
            findings.append(ok("no risky legacy services found in the process list"))

    except Exception as e:
        findings.append(info(f"couldn't enumerate running processes: {e}"))

    return findings


def check_cron_permissions():
    """
    cron files that are world-writable are a trivial privilege escalation.
    anyone on the system can edit them and get code run as root.
    """
    findings = []
    cron_dirs = [
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly",
    ]
    bad = []

    for d in cron_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.scandir(d):
                try:
                    if entry.stat().st_mode & stat.S_IWOTH:
                        bad.append(entry.path)
                except (OSError, PermissionError):
                    pass
        except PermissionError:
            pass

    if bad:
        findings.append(finding("HIGH",
            "world-writable cron job files found",
            "\n  ".join(bad) + "\n  fix with: chmod 644 <file>"))
    else:
        findings.append(ok("cron job files have appropriate permissions"))

    return findings


# figures out what IP addresses your machine is listening on and
# whether any of them are publicly routable. also reads the
# kernel's own socket table to catch things the port scanner
# might miss (like a DB bound to 0.0.0.0 on a loopback-only scan).

def get_network_interfaces():
    """returns {interface_name: [addr/prefix, ...]} using ip or ifconfig"""
    ifaces = {}

    # modern Linux: ip -j addr gives us clean JSON
    try:
        r = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for iface in json.loads(r.stdout):
                name  = iface.get("ifname", "?")
                addrs = [f"{ai['local']}/{ai.get('prefixlen','?')}"
                         for ai in iface.get("addr_info", [])]
                ifaces[name] = addrs
            return ifaces
    except Exception:
        pass

    # fallback: parse ifconfig output
    try:
        r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            current = None
            for line in r.stdout.splitlines():
                if not line.startswith(" ") and ":" in line:
                    current = line.split(":")[0]
                    ifaces[current] = []
                elif current and "inet " in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "inet" and i + 1 < len(parts):
                            ifaces[current].append(parts[i + 1])
    except Exception:
        pass

    return ifaces


def check_network_interfaces():
    """flags any interfaces with publicly routable IP addresses"""
    findings = []
    ifaces = get_network_interfaces()

    if not ifaces:
        findings.append(info("couldn't enumerate network interfaces — try running as root"))
        return findings

    public = []
    for name, addrs in ifaces.items():
        for addr in addrs:
            ip_str = addr.split("/")[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_private and not ip.is_loopback and not ip.is_link_local:
                    public.append(f"{name}:  {addr}")
            except ValueError:
                pass

    if public:
        detail = "\n  ".join(public)
        findings.append(finding("MEDIUM",
            f"public IP addresses on {len(public)} interface(s)",
            detail + "\n  make sure your firewall rules match your intentions here"))
    else:
        findings.append(ok("no publicly routable IP addresses on any interface"))

    # always show the full interface list for reference
    all_ifaces = "\n  ".join(
        f"{name}:  {', '.join(addrs) or 'no address'}" for name, addrs in ifaces.items()
    )
    findings.append(info(f"all network interfaces  ({len(ifaces)} found)", all_ifaces))

    return findings


def check_kernel_listening_ports():
    """
    reads /proc/net/tcp directly - catches listening ports regardless
    of what the port scanner found. useful for catching services bound
    to 0.0.0.0 that might be reachable from the network.
    """
    findings = []
    if platform.system() != "Linux":
        return findings  # /proc is Linux-only

    listening = set()
    for proto_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
        if not os.path.exists(proto_file):
            continue
        try:
            with open(proto_file) as f:
                next(f)  # skip header line
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    state = parts[3]
                    if state == "0A":  # 0A = LISTEN in the /proc format
                        port = int(parts[1].split(":")[1], 16)
                        listening.add(port)
        except (PermissionError, OSError):
            pass

    if listening:
        port_list = ", ".join(str(p) for p in sorted(listening))
        findings.append(info(
            f"kernel-level listening TCP ports  ({len(listening)} total)",
            port_list + "\n  cross-reference with the port scan above to see if anything unexpected is listening"))
    return findings


#
# sysctl values that affect security. these are the ones that
# matter most — ASLR, SYN cookie protection, ICMP redirect handling.
# most of them default to safe values on modern distros, but it's
# worth checking because they can be changed by any script with root.

def check_sysctl():
    """
    checks a focused set of sysctl parameters against their secure values.
    reads directly from /proc/sys/ so it works without the sysctl binary.
    """
    findings = []
    if platform.system() != "Linux":
        findings.append(info("sysctl checks are Linux-only"))
        return findings

    # parameter → (safe value, severity if wrong, explanation)
    params = {
        "kernel.randomize_va_space":             ("2",  "HIGH",   "ASLR disabled — makes memory exploitation significantly easier"),
        "net.ipv4.conf.all.accept_redirects":    ("0",  "MEDIUM", "ICMP redirects accepted — attackers can poison your routing table"),
        "net.ipv4.conf.all.send_redirects":      ("0",  "LOW",    "sending ICMP redirects — usually not needed on a non-router host"),
        "net.ipv4.tcp_syncookies":               ("1",  "MEDIUM", "SYN cookies off — your machine is more vulnerable to SYN flood DoS"),
        "net.ipv4.conf.all.rp_filter":           ("1",  "LOW",    "reverse path filtering off — makes IP spoofing easier"),
        "net.ipv4.ip_forward":                   ("0",  "LOW",    "IP forwarding on — this machine is acting as a router, intentional?"),
        "kernel.dmesg_restrict":                 ("1",  "LOW",    "any user can read kernel messages — can leak memory addresses and system info"),
        "fs.suid_dumpable":                      ("0",  "MEDIUM", "core dumps allowed for SUID programs — can leak sensitive memory contents"),
        "net.ipv6.conf.all.accept_redirects":    ("0",  "MEDIUM", "IPv6 ICMP redirects accepted — same routing table poison risk as IPv4"),
        "kernel.core_uses_pid":                  ("1",  "LOW",    "core dump files don't use PID suffix — harder to track which process crashed"),
    }

    for param, (expected, sev, reason) in params.items():
        path = "/proc/sys/" + param.replace(".", "/")
        if not os.path.exists(path):
            continue
        try:
            actual = open(path).read().strip()
            if actual != expected:
                findings.append(finding(sev,
                    f"sysctl  {param}  =  {actual}  (should be {expected})",
                    reason))
            else:
                findings.append(ok(f"sysctl  {param}  =  {actual}"))
        except (PermissionError, OSError):
            pass

    return findings


def check_pending_updates():
    """asks the package manager if there are updates waiting — out-of-date packages are how a lot of compromises start"""
    findings = []

    # try each package manager in order
    managers = [
        (["apt", "list", "--upgradable", "-q"],   "apt"),
        (["yum", "check-update", "--quiet"],       "yum"),
        (["dnf", "check-update", "--quiet"],       "dnf"),
    ]

    for cmd, name in managers:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            lines = [l for l in result.stdout.strip().splitlines()
                     if l and "/" in l and not l.startswith("Listing")]
            if lines:
                sample = "\n  ".join(lines[:5])
                if len(lines) > 5:
                    sample += f"\n  ... and {len(lines) - 5} more"
                findings.append(finding("MEDIUM",
                    f"{len(lines)} package update(s) available via {name}",
                    sample + "\n  run: sudo " + name + " upgrade"))
            else:
                findings.append(ok(f"no pending updates  ({name})"))
            return findings
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    findings.append(info("couldn't check for updates  —  no supported package manager found"))
    return findings


def check_umask():
    """
    umask controls the default permissions on new files.
    too permissive means new files might be readable by everyone.
    """
    findings = []
    try:
        # read then immediately restore
        current = os.umask(0o022)
        os.umask(current)

        if current < 0o022:
            findings.append(finding("MEDIUM",
                f"permissive umask: {oct(current)}",
                "new files may be created world-readable. recommend 0022 or stricter (0027 for servers)"))
        elif current > 0o022:
            findings.append(finding("LOW",
                f"restrictive umask: {oct(current)}",
                "files might be over-restricted — applications may behave unexpectedly"))
        else:
            findings.append(ok(f"umask is {oct(current)}  —  sensible default"))
    except Exception as e:
        findings.append(info(f"couldn't read umask: {e}"))
    return findings


def check_home_directories():
    """
    home directories that are group- or world-accessible let other
    users on the system snoop through your files. they should be 700.
    """
    findings = []
    bad = []

    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 7:
                    continue
                username, _, uid_str, _, _, home, _ = parts[:7]
                # only check regular user accounts (uid >= 1000)
                if int(uid_str) < 1000 or not os.path.isdir(home):
                    continue
                try:
                    mode = stat.S_IMODE(os.stat(home).st_mode)
                    if mode & 0o077:
                        bad.append(f"{home}  (fix: chmod 700 {home})")
                except (PermissionError, OSError):
                    pass
    except FileNotFoundError:
        pass

    if bad:
        findings.append(finding("MEDIUM",
            "home directories are group or world accessible",
            "\n  ".join(bad)))
    else:
        findings.append(ok("home directories have appropriate permissions"))

    return findings


def count_by_severity(all_findings):
    counts = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","OK"]}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def compute_score(all_findings):
    score = 100
    for f in all_findings:
        score -= SEV_COST.get(f["severity"], 0)
    return max(0, score)


def print_summary(all_findings):
    counts = count_by_severity(all_findings)
    score  = compute_score(all_findings)
    w      = 60

    print(f"\n\n  {C.WHITE}{C.BOLD}{'═' * w}{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}  results{C.RESET}")
    print(f"  {C.WHITE}{'═' * w}{C.RESET}\n")

    # breakdown bar per severity
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","OK"]:
        count = counts.get(sev, 0)
        color = _sev_color(sev)
        bar   = "█" * min(count * 2, 40)
        print(f"  {color}{C.BOLD}{sev:<10}{C.RESET}  {color}{bar:<40}{C.RESET}  {count}")

    # overall score with color-coded verdict
    if score >= 80:
        sc_color = C.GREEN
        verdict  = "looking pretty solid — address the remaining findings when you can."
    elif score >= 50:
        sc_color = C.YELLOW
        verdict  = "some work to do — the HIGH and CRITICAL items should come first."
    else:
        sc_color = C.RED
        verdict  = "significant issues found — please take action on the red items now."

    print(f"\n  {C.BOLD}score{C.RESET}   {sc_color}{C.BOLD}{score} / 100{C.RESET}")
    print(f"  {C.GRAY}{verdict}{C.RESET}\n")
    print(f"  {C.GRAY}{len(all_findings)} total findings  ·  scanned {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"  {C.WHITE}{'═' * w}{C.RESET}\n")


def save_json_report(all_findings, path):
    """writes a structured JSON report — useful for CI pipelines or log aggregators"""
    report = {
        "tool":      "Radar",
        "author":    "Ramtin Karimi",
        "version":   "1.0.0",
        "host":      socket.gethostname(),
        "os":        f"{platform.system()} {platform.release()}",
        "timestamp": datetime.now().isoformat(),
        "summary":   count_by_severity(all_findings),
        "score":     compute_score(all_findings),
        "findings":  all_findings,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  {C.GREEN}✔  report saved to {path}{C.RESET}\n")


def show_menu():
    print(f"  {C.CYAN}{C.BOLD}what do you want to scan?{C.RESET}\n")

    options = [
        ("1", "Port Scan",               "checks ~55 common ports for open / risky services"),
        ("2", "System Misconfigurations","file perms, SUID bins, SSH config, services, cron"),
        ("3", "Network Exposure",        "interfaces, public IPs, kernel-level open sockets"),
        ("4", "Kernel & System",         "sysctl params, pending updates, umask, home dirs"),
        ("A", "Full Scan",               "runs all four modules in sequence"),
        ("Q", "Quit",                    ""),
    ]

    for key, title, desc in options:
        key_str  = f"{C.CYAN}{C.BOLD}[{key}]{C.RESET}"
        desc_str = f"  {C.GRAY}{desc}{C.RESET}" if desc else ""
        print(f"  {key_str}  {C.WHITE}{title:<30}{C.RESET}{desc_str}")

    print()
    while True:
        choice = input(f"  {C.CYAN}›{C.RESET} ").strip().upper()
        if choice in {"1","2","3","4","A","Q"}:
            return choice
        print(f"  {C.YELLOW}type one of: 1  2  3  4  A  Q{C.RESET}")


MODULES = {
    "1": [
        ("Port Scan",                  scan_ports),
    ],
    "2": [
        ("World-Writable Files",       check_world_writable_files),
        ("SUID/SGID Binaries",         check_suid_binaries),
        ("Critical File Permissions",  check_critical_file_perms),
        ("Empty Password Accounts",    check_empty_passwords),
        ("SSH Configuration",          check_ssh_config),
        ("Firewall Status",            check_firewall),
        ("Running Services",           check_running_services),
        ("Cron Job Permissions",       check_cron_permissions),
    ],
    "3": [
        ("Network Interfaces",         check_network_interfaces),
        ("Kernel Listening Ports",     check_kernel_listening_ports),
    ],
    "4": [
        ("Kernel sysctl Parameters",   check_sysctl),
        ("Pending System Updates",     check_pending_updates),
        ("Process umask",              check_umask),
        ("Home Directory Permissions", check_home_directories),
    ],
}


def run(module_keys, report_path=None):
    """runs the selected modules and prints everything as it goes"""
    all_findings = []

    for key in module_keys:
        for title, fn in MODULES.get(key, []):
            section(title)
            with Spinner(f"running {title.lower()}"):
                try:
                    results = fn()
                except Exception as e:
                    results = [info(f"check failed unexpectedly: {e}")]
            for f in results:
                show_finding(f)
                all_findings.append(f)

    print_summary(all_findings)

    if report_path:
        save_json_report(all_findings, report_path)

    return all_findings



def build_cli():
    p = argparse.ArgumentParser(
        prog="radar",
        description="Radar — local machine security scanner by Ramtin Karimi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python radar.py                     # interactive menu
  python radar.py --full              # scan everything
  python radar.py --ports             # just the port scan
  python radar.py --misconfig         # just misconfiguration checks
  python radar.py --network           # just network exposure
  python radar.py --sysctl            # just kernel/system settings
  python radar.py --full --output report.json
  sudo python radar.py --full         # root gives deeper results
        """,
    )
    p.add_argument("--full",      action="store_true", help="run all scan modules")
    p.add_argument("--ports",     action="store_true", help="port scan only")
    p.add_argument("--misconfig", action="store_true", help="misconfiguration checks only")
    p.add_argument("--network",   action="store_true", help="network exposure only")
    p.add_argument("--sysctl",    action="store_true", help="kernel / system settings only")
    p.add_argument("--output",    metavar="FILE",      help="save JSON report to FILE")
    p.add_argument("--no-color",  action="store_true", help="strip color from output")
    p.add_argument("--version",   action="version",    version="Radar 1.0.0  —  by Ramtin Karimi")
    return p


def prompt_return_to_menu():
    """
    shown after a scan finishes. waits for the user to press enter,
    then returns True so the caller can loop back to the menu.
    skipped entirely when running with CLI flags (non-interactive mode).
    """
    print(f"\n  {C.DIM}{'─' * 60}{C.RESET}")
    input(f"  {C.GRAY}press enter to return to the menu...{C.RESET}  ")


def main():
    parser = build_cli()
    args   = parser.parse_args()

    # on Windows, try to enable ANSI color support in the console.
    # if that fails (old cmd.exe, redirected output, etc.) just strip
    # all the color codes so nothing garbled gets printed.
    # --no-color always wins regardless of platform.
    if args.no_color:
        C.disable()
    elif not sys.stdout.isatty():
        C.disable()
    elif not _enable_windows_ansi():
        C.disable()

    # ── non-interactive (CLI flags) ────────────────────────────
    # if any scan flag was passed, just run once and exit —
    # no menu loop, no "press enter" prompt.
    cli_modules = []
    if args.full:
        cli_modules = ["1","2","3","4"]
    else:
        if args.ports:     cli_modules.append("1")
        if args.misconfig: cli_modules.append("2")
        if args.network:   cli_modules.append("3")
        if args.sysctl:    cli_modules.append("4")

    if cli_modules:
        print_banner()
        run(cli_modules, report_path=args.output)
        return

    # ── interactive menu loop ──────────────────────────────────
    # keeps running until the user picks Q. after every scan it
    # pauses with "press enter to return to the menu" so the
    # results stay on screen as long as needed before clearing back.
    print_banner()
    while True:
        choice = show_menu()

        if choice == "Q":
            print(f"\n  {C.GRAY}bye.{C.RESET}\n")
            sys.exit(0)

        modules = ["1","2","3","4"] if choice == "A" else [choice]
        print()
        run(modules, report_path=args.output)
        prompt_return_to_menu()

        # clear the screen and reprint the banner so the menu
        # feels like a fresh start rather than endless scrollback
        print("\033[2J\033[H", end="")  # ANSI clear screen + move to top
        print_banner()


if __name__ == "__main__":
    main()
