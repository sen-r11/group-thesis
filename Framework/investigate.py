# Checks a process, and what its indicators point at, before reporting

# Sysmon says what a process did, not what it is, and not what it left
# behind. This answers the second question in two stages.
#
# The program on disk gives a base bar: a signed program from a known
# publisher has to score higher before it is reported, because signed
# malware exists and CISA (2023) records signed remote management tools used
# as a backdoor.
#
# Each indicator then gets its own follow up. A persistence indicator points
# at a registry value or a scheduled task, so this reads what that entry
# runs and checks that program too. A beacon points at an address, so this
# classifies it and looks up its name. Findings that support the alert lower
# the bar, findings that explain it raise the bar.
#
# All of it reads the machine the process ran on, so it only works live.
# Detection/engine.py does not call it.

import ipaddress
import os
import re
import socket
import subprocess
import time

TRUSTED_PUBLISHERS = (
    "microsoft corporation",
    "microsoft windows",
    "microsoft windows publisher",
    "microsoft windows hardware compatibility publisher",
    "google llc",
    "mozilla corporation",
    "python software foundation",
    "canonical group limited",
    "valve corp",
    "nvidia corporation",
    "intel corporation",
    "dropbox, inc",
    "docker inc",
)

# How much more score a process must reach before it is reported
TRUSTED_MULTIPLIER = 2.0
SIGNED_MULTIPLIER = 1.3
UNSIGNED_MULTIPLIER = 1.0

# A follow up can move the bar by at most this much, so no single check can
# force an alert on its own
MAX_SUPPORT = 0.6

SIGNATURE_TIMEOUT = 20
DNS_TIMEOUT = 2.0
RECENT_FILE_SECONDS = 3600

USER_WRITABLE = ("\\downloads\\", "\\appdata\\", "\\temp\\", "\\public\\",
                 "\\programdata\\")

# The ranges that really are somebody's local network
LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

# Names that mean the address belongs to a content or service network
KNOWN_NETWORKS = ("akamai", "cloudflare", "amazonaws", "azure", "microsoft",
                  "google", "gstatic", "fastly", "edgekey", "akadns",
                  "windowsupdate", "apple", "cloudfront")

# The first commands an operator usually runs on a new machine
RECON_COMMANDS = ("whoami", "ipconfig", "systeminfo", "net user", "net group",
                  "nltest", "netstat", "tasklist", "wmic", "query user",
                  "arp -a", "route print")

_CACHE = {}
_DNS_CACHE = {}


def clear_cache():
    _CACHE.clear()
    _DNS_CACHE.clear()


# ------------------------------------------------------- the program on disk

def _powershell(script):
    try:
        finished = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=SIGNATURE_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    if finished.returncode != 0:
        return None
    return finished.stdout.decode("utf-8", "replace").strip()


def common_name(subject):
    for part in (subject or "").split(","):
        part = part.strip()
        if part.lower().startswith("cn="):
            return part[3:].strip()
    return ""


def signature(path):
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath '%s'; "
        "Write-Output \"$($s.Status)|$($s.SignerCertificate.Subject)\""
        % path.replace("'", "''"))
    output = _powershell(script)
    if not output or "|" not in output:
        return "Unknown", ""
    status, subject = output.split("|", 1)
    return status.strip(), common_name(subject)


def version_info(path):
    try:
        import win32api
    except ImportError:
        return {}
    try:
        translation = win32api.GetFileVersionInfo(path, "\\VarFileInfo\\Translation")
        language, codepage = translation[0]
        prefix = "\\StringFileInfo\\%04X%04X\\" % (language, codepage)
        found = {}
        for key in ("CompanyName", "ProductName", "OriginalFilename"):
            try:
                value = win32api.GetFileVersionInfo(path, prefix + key)
                if value:
                    found[key] = str(value).strip()
            except Exception:
                continue
        return found
    except Exception:
        return {}


def investigate(path):
    if path in _CACHE:
        return _CACHE[path]

    report = {
        "path": path,
        "exists": False,
        "status": "Unknown",
        "signer": "",
        "trust": "unsigned",
        "company": "",
        "age_seconds": None,
        "notes": [],
    }

    if not path or not os.path.isfile(path):
        report["notes"].append("the program is not on disk to check")
        _CACHE[path] = report
        return report

    report["exists"] = True
    try:
        report["age_seconds"] = max(0.0, time.time() - os.path.getmtime(path))
    except OSError:
        pass

    status, signer = signature(path)
    report["status"] = status
    report["signer"] = signer
    report["company"] = version_info(path).get("CompanyName", "")

    if status == "Valid" and signer.lower() in TRUSTED_PUBLISHERS:
        report["trust"] = "trusted"
        report["notes"].append("signed by %s, a publisher on the trusted list" % signer)
    elif status == "Valid":
        report["trust"] = "signed"
        report["notes"].append("signed by %s, which is not on the trusted list" % signer)
    elif status == "HashMismatch":
        report["trust"] = "tampered"
        report["notes"].append("the file was changed after it was signed")
    else:
        report["trust"] = "unsigned"
        report["notes"].append("no valid signature (%s)" % status)

    if not report["company"]:
        report["notes"].append("the file declares no company name")

    age = report["age_seconds"]
    if age is not None and age < RECENT_FILE_SECONDS:
        report["notes"].append("the program was written %d minutes ago" % int(age // 60))

    _CACHE[path] = report
    return report


# ------------------------------------------------------------------ helpers

def executable_in(text):
    # Pull a program path out of a command line or a registry value
    text = str(text or "")
    quoted = re.search(r'"([^"]+\.(?:exe|dll|scr|bat|cmd|ps1|js|vbs))"', text, re.I)
    if quoted:
        return quoted.group(1)
    bare = re.search(r'([A-Za-z]:\\[^\s,;"]+\.(?:exe|dll|scr|bat|cmd|ps1|js|vbs))',
                     text, re.I)
    return bare.group(1) if bare else ""


def classify_address(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if any(address in network for network in LOCAL_NETWORKS):
        return "local"
    if address.is_global:
        return "public"
    # is_private also covers the documentation and reserved ranges, which are
    # not a local network and should not excuse anything
    return "reserved"


def resolve_name(value):
    value = str(value).strip()
    if value in _DNS_CACHE:
        return _DNS_CACHE[value]
    previous = socket.getdefaulttimeout()
    name = ""
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        name = socket.gethostbyaddr(value)[0]
    except Exception:
        name = ""
    finally:
        socket.setdefaulttimeout(previous)
    _DNS_CACHE[value] = name
    return name


def read_registry_value(target):
    # Sysmon writes the full path, so the last part is the value name
    try:
        import winreg
    except ImportError:
        return None
    hives = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKU": winreg.HKEY_USERS,
        "HKEY_USERS": winreg.HKEY_USERS,
    }
    parts = str(target or "").split("\\")
    if len(parts) < 3:
        return None
    hive = hives.get(parts[0].upper())
    if hive is None:
        return None
    path = "\\".join(parts[1:-1])
    name = parts[-1]
    try:
        with winreg.OpenKey(hive, path) as key:
            value, _kind = winreg.QueryValueEx(key, name)
            return str(value)
    except OSError:
        return None


def in_user_writable(path):
    lowered = str(path or "").lower()
    return any(location in lowered for location in USER_WRITABLE)


def process_alive(pid):
    try:
        import win32api
        import win32con
    except ImportError:
        return None
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION,
                                      False, int(pid))
    except Exception:
        return False
    if not handle:
        return False
    win32api.CloseHandle(handle)
    return True


def check_program(path, role):
    # Follow a path an indicator pointed at, and judge what it runs
    if not path:
        return []
    report = investigate(path)
    name = os.path.basename(path)
    if not report["exists"]:
        return [(0.1, "the %s runs %s, which is not on disk" % (role, name))]
    if report["trust"] == "trusted":
        return [(-0.3, "the %s runs %s, signed by %s"
                 % (role, name, report["signer"]))]
    if report["trust"] == "tampered":
        return [(0.5, "the %s runs %s, which was changed after signing"
                 % (role, name))]
    if in_user_writable(path):
        return [(0.5, "the %s runs %s from a user-writable folder, unsigned"
                 % (role, name))]
    return [(0.2, "the %s runs %s, which is unsigned" % (role, name))]


# ------------------------------------------------- one check per indicator

def check_beacon(details):
    found = []
    destination = details.get("destination", "")
    kind = classify_address(destination)
    if kind in ("loopback", "link-local", "multicast"):
        found.append((-0.5, "the destination %s is this machine or its own link"
                      % destination))
        return found
    if kind == "local":
        found.append((-0.35, "the destination %s is on the local network"
                      % destination))
        return found
    if kind == "reserved":
        found.append((0.1, "the destination %s is in a reserved range"
                      % destination))
        return found
    if kind == "public":
        name = resolve_name(destination)
        if name and any(known in name.lower() for known in KNOWN_NETWORKS):
            found.append((-0.3, "the destination %s resolves to %s, a service network"
                          % (destination, name)))
        elif name:
            found.append((0.15, "the destination %s resolves to %s"
                          % (destination, name)))
        else:
            found.append((0.25, "the destination %s has no reverse name"
                          % destination))
    return found


def check_registry_persistence(details):
    found = []
    target = details.get("registry", "")
    written = details.get("detail", "")
    live = read_registry_value(target)
    if live is None:
        found.append((0.1, "the registry value is no longer set"))
    else:
        found.append((0.15, "the registry value is still set to %s" % live[:60]))
    found += check_program(executable_in(live or written), "autorun entry")
    return found


def check_scheduled_task(details):
    # The command line holds what the task will run, after /tr
    cmdline = details.get("command_line", "")
    match = re.search(r'/tr\s+("[^"]+"|\S+)', cmdline, re.I)
    target = executable_in(match.group(1)) if match else executable_in(cmdline)
    return check_program(target, "scheduled task")


def check_remote_shell(details):
    found = []
    cmdline = str(details.get("command_line", "")).lower()
    if details.get("encoded"):
        found.append((0.4, "the command was base64 encoded"))
    hits = [name for name in RECON_COMMANDS if name in cmdline]
    if hits:
        found.append((0.35, "the command runs %s, which reads the machine"
                      % ", ".join(hits[:3])))
    return found


def check_privileged_access(details):
    target = details.get("target", "")
    name = os.path.basename(str(target)).lower()
    # Section 2.7.7 records a command and control module injected into an
    # internet-facing process, so the target being one matters
    if name in ("chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe",
                "svchost.exe", "lsass.exe"):
        return [(0.35, "the process it opened was %s" % name)]
    return [(0.1, "the process it opened was %s" % (name or "unknown"))]


def check_dns_fanout(details):
    names = [name.strip() for name in
             str(details.get("names", "")).split(",") if name.strip()]
    if len(names) < 2:
        return []
    suffixes = {".".join(name.split(".")[-2:]) for name in names}
    if len(suffixes) == 1:
        return [(-0.3, "every name shares the suffix %s" % suffixes.pop())]
    return [(0.2, "the names span %d different domains" % len(suffixes))]


CHECKS = {
    "c2_beaconing": check_beacon,
    "registry_persistence": check_registry_persistence,
    "scheduled_task_persistence": check_scheduled_task,
    "remote_command_execution": check_remote_shell,
    "privileged_process_access": check_privileged_access,
    "dns_fanout": check_dns_fanout,
}


def follow_up(alert):
    # Run the check that belongs to each indicator that fired
    found = []
    done = set()
    for item in alert.get("evidence") or []:
        indicator = item.get("indicator")
        check = CHECKS.get(indicator)
        if check is None or indicator in done:
            continue
        done.add(indicator)
        try:
            found += check(item.get("details") or {})
        except Exception:
            continue

    alive = process_alive(alert.get("pid"))
    if alive:
        found.append((0.1, "the process is still running"))
    return found


# ------------------------------------------------------------- the decision

def required_score(report, threshold):
    if report["trust"] == "trusted":
        return threshold * TRUSTED_MULTIPLIER
    if report["trust"] == "signed":
        return threshold * SIGNED_MULTIPLIER
    return threshold * UNSIGNED_MULTIPLIER


def judge(alert, threshold):
    report = dict(investigate(str(alert.get("process") or "")))
    base = required_score(report, threshold)
    score = float(alert.get("score") or 0.0)

    found = follow_up(alert)
    support = sum(weight for weight, _note in found)
    support = max(-MAX_SUPPORT, min(MAX_SUPPORT, support))
    needed = max(0.1, base - support)

    report["follow_up"] = [note for _weight, note in found]
    report["support"] = round(support, 2)
    report["base_required"] = round(base, 2)
    report["required"] = round(needed, 2)

    # A file that no longer matches its own signature is evidence in itself
    if report["trust"] == "tampered":
        report["decision"] = "reported: the file was changed after signing"
        return True, report

    if score >= needed:
        if support > 0 and score < base:
            report["decision"] = (
                "reported: %.2f, and the follow up lowered the bar from %.2f to %.2f"
                % (score, base, needed))
        elif report["trust"] in ("trusted", "signed"):
            report["decision"] = (
                "reported anyway: %.2f reached the raised bar of %.2f"
                % (score, needed))
        else:
            report["decision"] = "reported: %.2f reached %.2f" % (score, needed)
        return True, report

    report["decision"] = (
        "held back: %.2f did not reach %.2f, the bar for a %s program"
        % (score, needed, report["trust"]))
    return False, report
