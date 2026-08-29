# One program for the whole framework, so it can be packed into one exe

# gthesis.exe collect --minutes 10 --label benign --note "what I did"
# gthesis.exe live --seconds 600
# gthesis.exe live --replay captures\run.jsonl
# gthesis.exe detect captures\run.jsonl
# gthesis.exe parse sysmon.xml --json events.jsonl
#
# Each command is the same code the scripts run, so nothing behaves
# differently packed.

import sys

import collect
import live
import parse
from Detection import engine

COMMANDS = {
    "collect": (collect.main, "record Sysmon telemetry into a labelled capture"),
    "live": (live.main, "detect on the live channel, or replay a capture"),
    "detect": (engine.main, "run the engine over a capture and report once"),
    "parse": (parse.main, "turn Sysmon records into schema events"),
}


def usage():
    print("usage: %s <command> [options]" % program_name())
    print("")
    print("commands:")
    for name, (_run, description) in COMMANDS.items():
        print("  %-9s %s" % (name, description))
    print("")
    print("Add --help after a command to see its options, for example:")
    print("  %s collect --help" % program_name())
    return 2


def program_name():
    return "gthesis.exe" if live.FROZEN else "python gthesis.py"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        return usage()

    name = argv[0].lower()
    if name not in COMMANDS:
        print("unknown command: %s" % argv[0], file=sys.stderr)
        return usage()

    # Asking for administrator rights starts the program again, so it has to
    # know which command to repeat
    live.COMMAND_PREFIX = [name]
    return COMMANDS[name][0](argv[1:])


if __name__ == "__main__":
    sys.exit(main())
