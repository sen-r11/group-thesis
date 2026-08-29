# Live detection. Reads the Sysmon channel and alerts while it runs.

# python live.py --seconds 600     capture and alert
# python live.py --check           report what the machine can do
# python live.py --setup           start Sysmon with the matching config
#
# The engine already works event by event, so this only supplies a live
# source of events, a view of what is happening, and somewhere for the
# alerts to go. The channel needs administrator rights, so this asks Windows
# for them and starts itself again if it does not have them.

import argparse
import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

import investigate
import parse
import schema
from Detection.engine import DEFAULT_THRESHOLD, DetectionEngine

SYSMON_SERVICES = ("Sysmon64", "Sysmon", "SysmonDrv")
SYSMON_BINARIES = ("Sysmon64.exe", "Sysmon.exe", "sysmon.exe")

DEFAULT_CONFIG = "sysmon-config.xml"

SHELL_EXECUTE_MIN_SUCCESS = 32
SE_ERR_ACCESSDENIED = 5

DEFAULT_EVICT_AFTER = 900.0
DEFAULT_REARM_AFTER = 300.0
DEFAULT_DECAY_HALFLIFE = 600.0
DEFAULT_STATUS_EVERY = 1.0
PRUNE_EVERY = 500
# A replay skips a gap longer than this rather than sit through it, and
# does not bother sleeping for one shorter than the timer can hold
REPLAY_MAX_GAP = 60.0
REPLAY_MIN_SLEEP = 0.001
SILENT_AFTER = 60.0
WATCHING_SHOWN = 5

# The event IDs a rule reads, used for the coverage warning
NEEDED_EVENT_IDS = (1, 3, 8, 10, 11, 13, 17, 22, 23, 25)

WIDTH = 74
OUTPUT_LOCK = threading.Lock()

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"


# Set to True by PyInstaller in a packed build
FROZEN = getattr(sys, "frozen", False)

# The launcher sets this to the subcommand name, so that asking for
# administrator rights can start the same command again
COMMAND_PREFIX = []


def say(text=""):
    with OUTPUT_LOCK:
        print(text)


def app_dir():
    # Where the program lives. In a packed build __file__ points inside a
    # temporary unpack folder, so the exe's own folder is the useful one.
    if FROZEN:
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def bundled(name):
    # A data file packed into the exe is unpacked beside the code, so look
    # there first, then next to the exe, then take the name as given
    base = getattr(sys, "_MEIPASS", None)
    if base and os.path.isfile(os.path.join(base, name)):
        return os.path.join(base, name)
    beside = os.path.join(app_dir(), name)
    if os.path.isfile(beside):
        return beside
    return name


# ---------------------------------------------------------------- elevation

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated(argv, script=None):
    # A packed build starts itself. A script build starts Python on the
    # script, so the two need different command lines.
    if FROZEN:
        workdir = app_dir()
        arguments = subprocess.list2cmdline(
            list(COMMAND_PREFIX) + list(argv) + ["--elevated"])
    else:
        script = os.path.abspath(script or __file__)
        workdir = os.path.dirname(script)
        arguments = subprocess.list2cmdline([script] + list(argv) + ["--elevated"])

    say("The Sysmon channel needs administrator rights.")
    say("Asking Windows for them. Answer the prompt to continue.")

    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, arguments, workdir, 1)

    if result > SHELL_EXECUTE_MIN_SUCCESS:
        say("Started with administrator rights in a new window.")
        return 0
    # Anything at or below 32 is an error code. ShellExecuteEx reports a
    # refused prompt as 1223 instead, which is above 32, so testing for
    # success first would hide it.
    if result == SE_ERR_ACCESSDENIED:
        print("error: the prompt was refused, so the channel cannot be read.",
              file=sys.stderr)
        return 1
    print("error: could not start with administrator rights (code %d)." % result,
          file=sys.stderr)
    return 1


# ------------------------------------------------------------------- sysmon

def run_command(command, timeout=60):
    try:
        finished = subprocess.run(command, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as problem:
        return 1, str(problem)
    raw = (finished.stdout or b"") + (finished.stderr or b"")
    return finished.returncode, decode_output(raw)


def decode_output(raw):
    # Sysmon writes UTF-16 and sc writes 8 bit text. Trying UTF-16 first does
    # not work as a guess, because 8 bit text decodes as UTF-16 without
    # raising and gives back nonsense. A NUL byte is the reliable difference.
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if b"\x00" in raw:
        return raw.decode("utf-16-le", "replace")
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", "replace")


def service_state(name):
    code, text = run_command(["sc", "query", name], timeout=15)
    if code != 0:
        return None
    for line in text.splitlines():
        if "STATE" in line:
            parts = line.split()
            return parts[-1] if parts else None
    return None


def running_services():
    return [name for name in SYSMON_SERVICES
            if (service_state(name) or "").upper() == "RUNNING"]


def installed_services():
    return [name for name in SYSMON_SERVICES if service_state(name)]


def which(name):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory.strip('"'), name)
        if os.path.isfile(candidate):
            return candidate
    return None


def find_sysmon():
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    directories = [
        system_root,
        os.path.join(system_root, "System32"),
        app_dir(),
        os.getcwd(),
    ]
    for directory in directories:
        for name in SYSMON_BINARIES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
    for name in SYSMON_BINARIES:
        found = which(name)
        if found:
            return found
    return None


def config_state(sysmon):
    # Without administrator rights Sysmon prints only its banner, so None
    # means the answer is not known and nothing is changed
    code, text = run_command([sysmon, "-c"], timeout=30)
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    for line in lines:
        lowered = line.lower()
        if "rule configuration" in lowered:
            version = lowered.split("version")[-1].strip(" ():")
            return version not in ("", "0.00", "0"), line
    if code != 0 or not any("configuration" in line.lower() for line in lines):
        return None, "could not be read"
    return False, "no rule configuration is loaded"


def start_sysmon_service(name):
    say("Starting the %s service." % name)
    code, text = run_command(["sc", "start", name], timeout=60)
    if code == 0:
        return True
    first = (text.strip().splitlines() or [""])[0]
    say("could not start %s: %s" % (name, first))
    return False


def apply_config(sysmon, config, installing):
    if installing:
        command = [sysmon, "-accepteula", "-i", config]
        say("Installing Sysmon with %s" % os.path.basename(config))
    else:
        command = [sysmon, "-c", config]
        say("Loading %s into the running Sysmon." % os.path.basename(config))

    code, text = run_command(command, timeout=120)
    for line in [line.strip() for line in text.splitlines() if line.strip()][-4:]:
        say("  %s" % line)
    if code != 0:
        say("Sysmon returned %d." % code)
    return code == 0


def confirm(question, assume_yes):
    if assume_yes:
        return True
    try:
        answer = input("%s [y/N] " % question).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def setup_sysmon(config, assume_yes):
    # A Sysmon config is machine wide, so replacing one that is already
    # loaded asks first. Starting a stopped service, or loading a config
    # where there is none, takes nothing away and goes ahead.
    config = os.path.abspath(config)
    if not os.path.isfile(config):
        print("error: no config file at %s" % config, file=sys.stderr)
        return 2

    sysmon = find_sysmon()
    installed = installed_services()

    if sysmon is None and not installed:
        print("error: Sysmon is not on this machine.", file=sys.stderr)
        print("Get it from Microsoft Sysinternals, put Sysmon64.exe beside this",
              file=sys.stderr)
        print("script, then run: python live.py --setup", file=sys.stderr)
        return 2

    if sysmon is None:
        say("The Sysmon service is installed but the program was not found.")
        say("Put Sysmon64.exe beside this script to manage its config.")
        return 2

    say("Sysmon program   %s" % sysmon)
    say("Config to load   %s" % config)

    if not installed:
        say("Sysmon is not installed as a service.")
        if not confirm("Install Sysmon with this config?", assume_yes):
            say("Left alone.")
            return 1
        return 0 if apply_config(sysmon, config, installing=True) else 2

    for name in installed:
        if (service_state(name) or "").upper() != "RUNNING":
            start_sysmon_service(name)

    has_rules, current = config_state(sysmon)
    say("Current config   %s" % current)

    if has_rules is None:
        say("")
        say("The current config could not be read, so it is left alone.")
        say("Run this as administrator to manage it.")
        return 1

    if has_rules:
        say("")
        say("A config is already loaded. Replacing it changes what Sysmon")
        say("records for everything on this machine, not only this framework.")
        if not confirm("Replace it with %s?" % os.path.basename(config), assume_yes):
            say("Left alone. A capture will use the config already loaded.")
            return 1

    if not apply_config(sysmon, config, installing=False):
        return 2
    say("")
    say("Sysmon now logs the event IDs that the schema maps.")
    return 0


# ---------------------------------------------------------------- pre-flight

def check_machine():
    problems = []

    if not sys.platform.startswith("win"):
        problems.append(
            "this reads a Windows event channel, and the platform is %s"
            % sys.platform)
        return problems

    try:
        import win32evtlog       # noqa: F401
        import win32event        # noqa: F401
    except ImportError:
        problems.append(
            "pywin32 is missing. Install it with: pip install -r requirements.txt")

    if not running_services():
        problems.append(
            "no running Sysmon service was found. Start it with:\n"
            "        python live.py --setup")

    return problems


def report_machine(config):
    say("platform         %s" % sys.platform)
    say("administrator    %s" % ("yes" if is_admin() else "no"))

    try:
        import win32evtlog       # noqa: F401
        say("pywin32          present")
    except ImportError:
        say("pywin32          MISSING")

    sysmon = find_sysmon()
    say("Sysmon program   %s" % (sysmon or "not found"))
    say("config file      %s" % (
        os.path.abspath(config) if os.path.isfile(config)
        else "MISSING: %s" % config))

    for name in SYSMON_SERVICES:
        state = service_state(name)
        if state:
            say("service %-9s %s" % (name, state))

    if sysmon and is_admin():
        has_rules, current = config_state(sysmon)
        say("current config   %s" % current)
        if has_rules is False:
            say("                 nothing would be logged. Run --setup.")
    elif sysmon:
        say("current config   needs administrator rights to read")

    problems = check_machine()
    if problems:
        say("")
        say("not ready:")
        for problem in problems:
            say("  - %s" % problem)
        return 1

    say("")
    say("ready. A capture still needs administrator rights.")
    return 0


# ---------------------------------------------------------------- state size

def prune_state(engine, now, evict_after):
    # A process that has alerted is kept, because its evidence is the reason
    # the alert fired
    alerted = {pid for pid, _family in engine._alerted}
    stale = [
        pid for pid, state in engine.state.processes.items()
        if pid not in alerted
        and state.last_seen is not None
        and now - state.last_seen > evict_after
    ]
    for pid in stale:
        del engine.state.processes[pid]
        for table_name in ("rat_connections", "rat_dns"):
            table = getattr(engine.state, table_name, None)
            if not table:
                continue
            for key in [k for k in table if (k[0] if isinstance(k, tuple) else k) == pid]:
                del table[key]
    return len(stale)


def decay_scores(engine, elapsed, half_life):
    # Scores only ever went up, so a long lived process drifted towards the
    # threshold. Malware gathers its score in seconds and ordinary software
    # gathers the same total over hours, so the speed of the rise is the
    # signal. Decay runs on wall clock, not idle time: a browser earns score
    # all day while staying busy, so waiting for a quiet spell never shaves it.
    if half_life <= 0 or elapsed <= 0:
        return
    factor = 0.5 ** (elapsed / half_life)
    alerted = {pid for pid, _family in engine._alerted}
    for pid, state in engine.state.processes.items():
        if pid in alerted:
            continue
        total = 0.0
        for family in state.family_scores:
            value = state.family_scores[family] * factor
            state.family_scores[family] = 0.0 if value < 0.01 else value
            total += state.family_scores[family]
        if total == 0.0 and state.scored:
            state.scored.clear()


def rearm(engine, last_alert, now, rearm_after):
    # The engine never reports the same process and family twice. Clearing a
    # pair from its record puts it back in play, so the next indicator that
    # fires raises a fresh alert.
    for key in [k for k, when in last_alert.items() if now - when > rearm_after]:
        engine._alerted.discard(key)
        del last_alert[key]


# ---------------------------------------------------------------- the screen

STD_OUTPUT_HANDLE = -11
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


def enable_vt():
    # Windows Terminal handles escape sequences already. The older console
    # host prints them as text unless this is asked for.
    if not sys.stdout.isatty():
        return False
    try:
        handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode = ctypes.c_uint32()
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        wanted = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if wanted != mode.value:
            if not ctypes.windll.kernel32.SetConsoleMode(handle, wanted):
                return False
        return True
    except Exception:
        return False


class Screen:
    HOME = "\x1b[H"
    CLEAR_BELOW = "\x1b[0J"
    HIDE_CURSOR = "\x1b[?25l"
    SHOW_CURSOR = "\x1b[?25h"
    CLEAR_ALL = "\x1b[2J"

    def __init__(self):
        self.started = False

    def size(self):
        try:
            size = os.get_terminal_size()
            return max(60, size.columns), max(16, size.lines)
        except OSError:
            return 100, 30

    def start(self):
        sys.stdout.write(self.CLEAR_ALL + self.HOME + self.HIDE_CURSOR)
        sys.stdout.flush()
        self.started = True

    def draw(self, lines):
        # A coloured line is trusted as built, because slicing it could cut
        # through an escape sequence and leave the console painting red
        width, _height = self.size()
        body = "\r\n".join(
            (line if "\x1b[" in line else line[:width]) + "\x1b[K"
            for line in lines)
        sys.stdout.write(self.HOME + body + "\r\n" + self.CLEAR_BELOW)
        sys.stdout.flush()

    def stop(self):
        if self.started:
            sys.stdout.write(self.SHOW_CURSOR + "\r\n")
            sys.stdout.flush()
            self.started = False


# ------------------------------------------------------------------ the view

def short_name(path):
    return str(path or "unknown").replace("/", "\\").split("\\")[-1]


def duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm %02ds" % (seconds // 60, seconds % 60)
    return "%dh %02dm" % (seconds // 3600, (seconds % 3600) // 60)


class LiveView:

    def __init__(self, engine, threshold):
        self.engine = engine
        self.threshold = threshold
        self.started = time.time()
        self.events = 0
        self.alerts = 0
        self.evicted = 0
        self.counts = {}
        self.last_event_at = None
        self.said_first_event = False
        self.recent = []
        self.held = []
        self.held_back = 0
        self.prev_scores = {}

    def record(self, event):
        self.events += 1
        event_id = int(event.get("event_id") or 0)
        self.counts[event_id] = self.counts.get(event_id, 0) + 1
        self.last_event_at = time.time()
        if not self.said_first_event:
            self.said_first_event = True
            say("The channel is live. First event: %s from %s"
                % (schema.name_of(event_id), short_name(event.get("process"))))

    def watching(self):
        rows = []
        for state in self.engine.state.processes.values():
            family, score = state.best_family()
            if 0 < score < self.threshold:
                rows.append((score, family, state))
        rows.sort(key=lambda row: row[0], reverse=True)
        return rows[:WATCHING_SHOWN]

    def missing_event_ids(self):
        return [number for number in NEEDED_EVENT_IDS if number not in self.counts]

    def note_alert(self, alert):
        evidence = alert.get("evidence") or []
        self.recent.insert(0, {
            "at": datetime.now().strftime("%H:%M:%S"),
            "family": str(alert.get("family", "")).upper(),
            "score": alert.get("score", 0.0),
            "process": short_name(alert.get("process")),
            "pid": alert.get("pid"),
            "indicators": list(alert.get("triggered_indicators", [])),
            "desc": evidence[-1].get("description", "") if evidence else "",
        })

    def note_held(self, alert, report):
        self.held.insert(0, {
            "at": datetime.now().strftime("%H:%M:%S"),
            "score": alert.get("score", 0.0),
            "process": short_name(alert.get("process")),
            "pid": alert.get("pid"),
            "trust": report.get("trust", ""),
            "signer": report.get("signer", "") or "unsigned",
        })

    def bar(self, score, cells=10):
        if self.threshold <= 0:
            return " " * cells
        filled = min(cells, int(round(cells * score / self.threshold)))
        return "█" * filled + "░" * (cells - filled)

    def trend(self, pid, score):
        arrow = "↑" if score > self.prev_scores.get(pid, 0.0) + 1e-9 else " "
        self.prev_scores[pid] = score
        return arrow

    def render(self, width, height, colour=False):
        def paint(text, code):
            return code + text + RESET if colour else text

        now = time.time()
        elapsed = now - self.started
        rule = paint("-" * width, DIM)
        rate = ("%.0f/s" % (self.events / elapsed)) if elapsed >= 2.0 else "-"

        header = " LIVE DETECTION  Sysmon/Operational"
        clock = "%s  up %s" % (datetime.now().strftime("%H:%M:%S"),
                               duration(elapsed))
        lines = [
            paint("%s%s%s" % (header,
                              " " * max(2, width - len(header) - len(clock) - 1),
                              clock), BOLD),
            rule,
            paint("  %s events · %s · %d processes · threshold %.2f"
                  % (format(self.events, ","), rate,
                     len(self.engine.state.processes), self.threshold), DIM),
            "",
        ]

        lines.append("  " + paint("ALERTED (%d)" % self.alerts,
                                  RED if self.alerts else DIM))
        if not self.recent:
            lines.append(paint("   nothing has crossed the threshold", DIM))
        else:
            for alert in self.recent[:4]:
                lines.append(paint(
                    "   %s  %-20s pid %-6s %s %s %.2f/%.2f"
                    % (alert["at"], alert["process"][:20], alert["pid"],
                       alert["family"].lower(), self.bar(alert["score"]),
                       alert["score"], self.threshold), RED))
                what = alert.get("desc") or (alert["indicators"] or [""])[0]
                more = len(alert["indicators"]) - 1
                lines.append(paint(
                    "             %s%s"
                    % (what[:width - 22],
                       "  and %d more signs" % more if more > 0 else ""), RED))

        lines.append("")
        rows = self.watching()
        lines.append("  " + paint("WATCHING  rising towards %.2f" % self.threshold,
                                  YELLOW if rows else DIM))
        if not rows:
            lines.append(paint("   nothing is scoring", DIM))
        for score, family, state in rows:
            lines.append(paint(
                "   %-20s pid %-6s %s %s %.2f/%.2f %s"
                % (short_name(state.process)[:20], state.pid, family[:3],
                   self.bar(score), score, self.threshold,
                   self.trend(state.pid, score)), YELLOW))

        # A cleared alert is still a detection, so it stays visible
        if self.held:
            lines.append("")
            lines.append("  " + paint("CLEARED  scored, but the program is signed"
                                      " and known (%d)" % self.held_back, DIM))
            for item in self.held[:3]:
                lines.append(paint(
                    "   %s  %-20s %.2f  %s"
                    % (item["at"], item["process"][:20], item["score"],
                       item["signer"][:30]), DIM))

        missing = self.missing_event_ids()
        if self.last_event_at is None:
            note = "waiting for the first event"
        elif now - self.last_event_at > SILENT_AFTER:
            note = ("no events for %s. Is the config logging?"
                    % duration(now - self.last_event_at))
        elif missing:
            note = "not logged yet: %s" % ", ".join(
                schema.name_of(number) for number in missing[:4])
        else:
            note = "every event ID a rule reads has arrived"
        lines.append("")
        lines.append(rule)
        lines.append(paint("  %s%sCtrl+C to stop"
                           % (note, " " * max(2, width - len(note) - 18)), DIM))
        return lines

    def run_status_thread(self, every, stop, screen=None):
        # The reader blocks in the Windows call while it waits for events, so
        # the capture loop cannot draw during a quiet spell
        def loop():
            while not stop.wait(every):
                if screen is not None:
                    width, height = screen.size()
                    with OUTPUT_LOCK:
                        screen.draw(self.render(width, height, colour=True))
                else:
                    with OUTPUT_LOCK:
                        print("")
                        for line in self.render(WIDTH, 30):
                            print(line)

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        return thread


# --------------------------------------------------------------- the alerts

def load_formatter():
    try:
        from Alerts.formatting import formatHumanReadable, formatMachineReadable
        return formatHumanReadable, formatMachineReadable
    except Exception:
        return None


def show_alert(alert, human):
    stamp = datetime.now().strftime("%H:%M:%S")
    with OUTPUT_LOCK:
        print()
        print("=" * WIDTH)
        print(" %s  ALERT  %s  score %.2f"
              % (stamp, str(alert.get("family", "")).upper(),
                 alert.get("score", 0.0)))
        print("=" * WIDTH)
        if human is not None:
            print(human(alert))
        else:
            print("[%s] %s (pid %s)"
                  % (str(alert.get("verdict", "")).upper(),
                     alert.get("process"), alert.get("pid")))
            for indicator in alert.get("triggered_indicators", []):
                print("  - %s" % indicator)
        print("=" * WIDTH)
        print()


# --------------------------------------------------------------- the capture

def replay_events(path, speed):
    # Feed a recording to the engine in the order it was recorded. At speed 0
    # the events arrive as fast as the file reads, which is what a test wants.
    # Above 0 the recorded clock is honoured, divided by the speed, so the
    # view behaves the way it did when the events happened.
    #
    # Waiting out one gap at a time looks simpler and runs long. Windows wakes
    # a sleeping thread about half a millisecond late, most of the gaps in a
    # capture are shorter than that, and the miss lands on every event: a
    # five minute capture takes six. So each event is timed against the start
    # of the replay, which leaves the error on the event it happened to and
    # keeps it off the ones that follow.
    first = None
    started = None
    previous = None
    skipped = 0.0
    for event in parse.open_file(path):
        stamp = float(event.get("time") or 0.0)
        # An event with no clock cannot be placed, so it is passed straight
        # through and the pacing carries on from the last one that had one
        if speed > 0 and stamp:
            if first is None:
                first = stamp
                started = time.monotonic()
            else:
                # Dead air is not worth sitting through. Drop the wait, and
                # take it off the clock so the rest still arrives on time
                if stamp - previous >= REPLAY_MAX_GAP:
                    skipped += stamp - previous
                due = started + (stamp - first - skipped) / speed
                waiting = due - time.monotonic()
                # Under the floor the sleep would overshoot more than it
                # waits, and behind schedule there is nothing to wait for
                if waiting >= REPLAY_MIN_SLEEP:
                    time.sleep(waiting)
            previous = stamp
        yield event


# The detector shows up in the channel it is reading: the process it runs in,
# and the helpers it starts to check a program on disk. Judging that work would
# report the tool doing the reporting, so it is dropped before anything sees it
def own_work(event, mine):
    pid = int(event.get("pid") or 0)

    ppid = event.get("ppid")
    if isinstance(ppid, str) and ppid.isdigit():
        ppid = int(ppid)

    # Anything the detector starts belongs to the detector as well
    if int(event.get("event_id") or 0) == 1 and ppid in mine:
        mine.add(pid)
        return True

    # Only the process acting is skipped. Another process opening the detector
    # is worth seeing, and that event is recorded against the one opening it
    return pid in mine


def capture(args):
    formatters = load_formatter()
    human = formatters[0] if formatters else None
    machine = formatters[1] if formatters else None

    engine = DetectionEngine(threshold=args.threshold)
    view = LiveView(engine, args.threshold)
    last_alert = {}

    replaying = bool(getattr(args, "replay", None))
    # Eviction, decay and re-arming all measure elapsed time. Live, that is
    # the wall clock. Replaying a recording, the wall clock stands still
    # while the events span hours, so every process would look stale at once
    # and be evicted. The events carry their own clock, so replay uses it.
    clock = 0.0
    last_decay = 0.0

    out = open(args.out, "a", encoding="utf-8") if args.out else None

    # Live, these are the PIDs of this program and whatever it starts. A
    # recording is someone else's machine, where the same numbers mean other
    # processes, so nothing is skipped while replaying
    mine = {os.getpid()}

    say("=" * WIDTH)
    if replaying:
        say(" Replaying %s" % os.path.abspath(args.replay))
    else:
        say(" Live detection on Microsoft-Windows-Sysmon/Operational")
    say("=" * WIDTH)
    say(" threshold  %.2f" % args.threshold)
    if replaying:
        say(" feeding    the recorded events in order, %s"
            % ("as fast as they read" if args.speed <= 0
               else "at %g times the speed they happened" % args.speed))
    else:
        say(" stopping   %s" % ("after %s" % duration(args.seconds)
                                if args.seconds else "on Ctrl+C"))
    if out:
        say(" alerts to  %s" % os.path.abspath(args.out))
    say(" evicting   quiet processes after %s" % duration(args.evict_after))
    say(" re-arming  alerts after %s" % duration(args.rearm_after))
    say(" checking   %s" % (
        "the program on disk before reporting an alert"
        if args.investigate else "nothing. Every alert is reported."))
    say("=" * WIDTH)
    say("")
    if replaying:
        say("The engine sees these events exactly as it would see them live.")
        if args.investigate:
            say("The programs are checked on this machine, not the recorded one.")
    else:
        say("Waiting for events. Only activity from now on is recorded.")
    say("")

    screen = None
    if not args.plain and args.status_every > 0 and enable_vt():
        screen = Screen()
        screen.start()

    stop = threading.Event()
    if args.status_every > 0:
        view.run_status_thread(args.status_every, stop, screen)

    if replaying:
        stream = replay_events(args.replay, args.speed)
    else:
        stream = parse.from_live(seconds=args.seconds)

    try:
        for event in stream:
            if not replaying and own_work(event, mine):
                continue

            view.record(event)
            clock = float(event.get("time") or 0.0) if replaying else time.time()
            if not last_decay:
                last_decay = clock

            for alert in engine.process_event(event):
                # The engine builds an alert without this count and the
                # formatter prints it, so supply it here
                alert["events_processed"] = engine.events_processed
                last_alert[(alert["pid"], alert["family"])] = clock

                if args.investigate:
                    worth_reporting, report = investigate.judge(
                        alert, args.threshold)
                    alert["investigation"] = report
                    if not worth_reporting:
                        view.held_back += 1
                        view.note_held(alert, report)
                        if out:
                            record = machine(alert) if machine else dict(alert)
                            record["investigation"] = report
                            record["reported"] = False
                            out.write(json.dumps(record) + "\n")
                            out.flush()
                        continue

                view.alerts += 1
                view.note_alert(alert)
                if screen is not None:
                    # Printing the alert here would scroll the screen away
                    width, height = screen.size()
                    with OUTPUT_LOCK:
                        screen.draw(view.render(width, height, colour=True))
                elif not args.quiet:
                    show_alert(alert, human)
                if out:
                    record = machine(alert) if machine else alert
                    out.write(json.dumps(record) + "\n")
                    out.flush()

            if view.events % PRUNE_EVERY == 0:
                view.evicted += prune_state(engine, clock, args.evict_after)
                rearm(engine, last_alert, clock, args.rearm_after)
                decay_scores(engine, clock - last_decay, args.decay_halflife)
                last_decay = clock

    except KeyboardInterrupt:
        pass
    except RuntimeError as problem:
        stop.set()
        if screen is not None:
            screen.stop()
        print("error: %s" % problem, file=sys.stderr)
        return 2
    finally:
        stop.set()
        if screen is not None:
            screen.stop()
        if out:
            out.close()

    # The panel only had room for one line an alert
    if screen is not None and view.alerts and not args.quiet:
        say("")
        say("The alerts from this run, in full:")
        for alert in reversed(engine.alerts):
            show_alert(alert, human)

    return summary(view)


def summary(view):
    say("")
    say("=" * WIDTH)
    say(" Run summary")
    say("=" * WIDTH)
    say(" ran for    %s" % duration(time.time() - view.started))
    say(" events     %s" % format(view.events, ","))
    say(" alerts     %d" % view.alerts)
    if view.held_back:
        say(" cleared    %d scored, but the program is signed and known"
            % view.held_back)
        for item in view.held[:8]:
            say("            %.2f  %-24s %s"
                % (item["score"], item["process"][:24], item["signer"]))
    say(" processes  %d held, %d dropped when quiet"
        % (len(view.engine.state.processes), view.evicted))

    if view.counts:
        say("")
        for event_id in sorted(view.counts):
            say("  %-3d %-20s %s"
                % (event_id, schema.name_of(event_id),
                   format(view.counts[event_id], ",")))

    missing = view.missing_event_ids()
    if not view.events:
        say("")
        say(" No events arrived at all. Sysmon may be running without a config")
        say(" that logs anything. Check it with: python live.py --check")
    elif missing:
        say("")
        say(" These event IDs never arrived, so every rule that reads them was")
        say(" blind for this run:")
        for event_id in missing:
            say("   %-3d %s" % (event_id, schema.name_of(event_id)))
        say(" Load the config that matches the schema: python live.py --setup")
    say("=" * WIDTH)
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    elevated = "--elevated" in argv

    arg_parser = argparse.ArgumentParser(
        description="Detect malware behaviour on the live Sysmon channel.")
    arg_parser.add_argument(
        "--seconds", type=float,
        help="stop after this long. omit to run until Ctrl+C")
    arg_parser.add_argument(
        "--threshold", type=float, default=DEFAULT_THRESHOLD,
        help="score needed for a malicious verdict")
    arg_parser.add_argument(
        "--out", metavar="FILE", default="live_alerts.jsonl",
        help="append machine readable alerts here. empty string turns it off")
    arg_parser.add_argument(
        "--evict-after", type=float, default=DEFAULT_EVICT_AFTER,
        help="drop a process after this many quiet seconds")
    arg_parser.add_argument(
        "--rearm-after", type=float, default=DEFAULT_REARM_AFTER,
        help="let a process alert again after this many seconds")
    arg_parser.add_argument(
        "--decay-halflife", type=float, default=DEFAULT_DECAY_HALFLIFE,
        help="halve a quiet process's scores over this many seconds. 0 turns it off")
    arg_parser.add_argument(
        "--status-every", type=float, default=DEFAULT_STATUS_EVERY,
        help="seconds between screen refreshes. 0 turns them off")
    arg_parser.add_argument(
        "--replay", metavar="FILE",
        help="feed a recorded capture through the live path instead of the channel")
    arg_parser.add_argument(
        "--speed", type=float, default=1.0,
        help="replay pacing. 1 is the speed it happened, 0 is as fast as it reads")
    arg_parser.add_argument(
        "--plain", action="store_true",
        help="scroll the status instead of redrawing a screen in place")
    arg_parser.add_argument(
        "--no-investigate", dest="investigate", action="store_false",
        help="report every alert without checking the program on disk")
    arg_parser.add_argument(
        "--quiet", action="store_true", help="write alerts to the file only")
    arg_parser.add_argument(
        "--check", action="store_true",
        help="report what the machine can do, then stop")
    arg_parser.add_argument(
        "--setup", action="store_true",
        help="start Sysmon and load the config that matches the schema, then stop")
    arg_parser.add_argument(
        "--config", metavar="FILE", default=DEFAULT_CONFIG,
        help="the Sysmon config that --setup loads")
    arg_parser.add_argument(
        "--yes", action="store_true",
        help="do not ask before replacing a config that is already loaded")
    arg_parser.add_argument(
        "--elevated", action="store_true", help=argparse.SUPPRESS)
    args = arg_parser.parse_args(argv)

    code = 0
    try:
        if args.check:
            return report_machine(bundled(args.config))

        # A recording needs no channel, so replay wants neither Sysmon nor
        # administrator rights and runs on any machine
        if args.replay:
            if not os.path.isfile(args.replay):
                print("error: no capture at %s" % args.replay, file=sys.stderr)
                return 2
            return capture(args)

        if not is_admin():
            return relaunch_elevated([a for a in argv if a != "--elevated"])

        if args.setup:
            return setup_sysmon(bundled(args.config), args.yes)

        problems = check_machine()
        if problems:
            print("cannot start a live capture:", file=sys.stderr)
            for problem in problems:
                print("  - %s" % problem, file=sys.stderr)
            return 2

        code = capture(args)
    finally:
        # This console belongs to the elevated process, so closing it now
        # would take the output with it
        if elevated:
            try:
                input("\nPress Enter to close this window.")
            except (EOFError, KeyboardInterrupt):
                pass
    return code


if __name__ == "__main__":
    sys.exit(main())
