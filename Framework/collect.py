# Collects Sysmon telemetry from this machine into a labelled capture

# python collect.py --minutes 10 --label benign --note "browsed, saved a doc"
# python collect.py --live 300 --label benign --note "zipped a large folder"
# python collect.py --list
#
# Nothing is executed here. The activity is whatever is done on the machine
# by hand, and this only records what Sysmon logged while it happened.
#
# Sysmon has already written its channel, so the usual way round is to do
# the activity first and then export the window with --minutes. Starting a
# recorder beforehand is only needed when the channel is being cleared
# between runs. The channel needs administrator rights, so this asks Windows
# for them and starts itself again if it does not have them.

import argparse
import csv
import json
import os
import sys
import tempfile
import time
from datetime import datetime

import live
import parse
import schema

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFAULT_MINUTES = 10.0
EXPORT_TIMEOUT = 600


def powershell(script, timeout=EXPORT_TIMEOUT):
    return live.run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout)


def channel_summary():
    code, text = powershell(
        "$l = Get-WinEvent -ListLog '%s';"
        " Write-Output \"$($l.RecordCount)|$($l.FileSize)|$($l.IsEnabled)\""
        % CHANNEL, timeout=60)
    line = (text or "").strip().splitlines()
    if code != 0 or not line or "|" not in line[-1]:
        return None
    count, size, enabled = line[-1].split("|", 2)
    return {"records": count.strip(), "bytes": size.strip(),
            "enabled": enabled.strip()}


def oldest_event_time():
    code, text = powershell(
        "$e = Get-WinEvent -LogName '%s' -Oldest -MaxEvents 1;"
        " Write-Output $e.TimeCreated.ToString('s')" % CHANNEL, timeout=60)
    line = (text or "").strip().splitlines()
    return line[-1].strip() if code == 0 and line else ""


def export_window(minutes, max_events, xml_path):
    # Get-WinEvent returns newest first, so the records are sorted back into
    # the order they happened. The engine keeps per-process state and the
    # beacon rule measures gaps, so out of order events would be wrong.
    script = (
        "$start = (Get-Date).AddMinutes(-%f);"
        " $f = @{LogName='%s'; StartTime=$start};"
        " Get-WinEvent -FilterHashtable $f -MaxEvents %d -ErrorAction Stop |"
        " Sort-Object RecordId |"
        " ForEach-Object { $_.ToXml() } |"
        " Out-File -FilePath '%s' -Encoding utf8"
        % (minutes, CHANNEL, max_events, xml_path.replace("'", "''")))
    return powershell(script)


def export_evtx(minutes, evtx_path):
    # timediff works in milliseconds and counts back from now
    query = ("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]"
             % int(minutes * 60 * 1000))
    return live.run_command(
        ["wevtutil", "epl", CHANNEL, evtx_path, "/q:%s" % query, "/ow:true"],
        timeout=EXPORT_TIMEOUT)


def clear_channel():
    return live.run_command(["wevtutil", "cl", CHANNEL], timeout=60)


def write_jsonl(events, path):
    counts = {}
    total = 0
    with open(path, "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
            total += 1
            event_id = int(event.get("event_id") or 0)
            counts[event_id] = counts.get(event_id, 0) + 1
    return total, counts


def collect_from_history(args, jsonl_path):
    handle, xml_path = tempfile.mkstemp(suffix=".xml", prefix="sysmon-")
    os.close(handle)
    try:
        print(" reading      the last %g minutes of the channel" % args.minutes)
        code, text = export_window(args.minutes, args.max_events, xml_path)
        if code != 0:
            first = (text.strip().splitlines() or [""])[0]
            print("error: could not read the channel: %s" % first, file=sys.stderr)
            return None
        if not os.path.getsize(xml_path):
            print(" nothing was logged in that window")
            return 0, {}
        return write_jsonl(parse.from_xml_file(xml_path), jsonl_path)
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass


def collect_from_live(args, jsonl_path):
    print(" recording    for %g seconds. Do the activity now." % args.live)
    print(" only what happens from this moment is recorded")
    print("")
    counts = {}
    total = 0
    started = time.time()
    try:
        with open(jsonl_path, "w", encoding="utf-8") as handle:
            for event in parse.from_live(seconds=args.live):
                handle.write(json.dumps(event) + "\n")
                total += 1
                event_id = int(event.get("event_id") or 0)
                counts[event_id] = counts.get(event_id, 0) + 1
                if total % 50 == 0:
                    left = args.live - (time.time() - started)
                    print("\r %5.0fs left, %s events" % (max(0, left),
                                                         format(total, ",")),
                          end="")
    except KeyboardInterrupt:
        print("\n stopped early")
    except RuntimeError as problem:
        print("error: %s" % problem, file=sys.stderr)
        return None
    print("")
    return total, counts


def corpus_row(sample_id, jsonl_path, label, family, manifest):
    base = os.path.dirname(os.path.abspath(manifest))
    try:
        relative = os.path.relpath(os.path.abspath(jsonl_path), base)
    except ValueError:
        relative = os.path.abspath(jsonl_path)
    return {"sample_id": sample_id, "path": relative.replace("\\", "/"),
            "label": label, "family": family or ""}


def append_to_corpus(row, manifest):
    columns = ["sample_id", "path", "label", "family"]
    fresh = not os.path.isfile(manifest)
    directory = os.path.dirname(os.path.abspath(manifest))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(manifest, "a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        if fresh:
            writer.writeheader()
        writer.writerow(row)


def report_channel():
    summary = channel_summary()
    if summary is None:
        print("the channel could not be read. Check: python live.py --check")
        return 1
    print("channel      %s" % CHANNEL)
    print("enabled      %s" % summary["enabled"])
    print("records      %s" % summary["records"])
    print("size         %s bytes" % summary["bytes"])
    oldest = oldest_event_time()
    if oldest:
        print("oldest       %s" % oldest)
        print("")
        print("Anything back to that time can still be exported with --minutes.")
    return 0


def run(args):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    sample_id = args.sample_id or "%s-%s" % (args.label, stamp)
    jsonl_path = args.out or os.path.join("captures", "%s.jsonl" % sample_id)
    directory = os.path.dirname(os.path.abspath(jsonl_path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)

    print("=" * 70)
    print(" COLLECT")
    print("=" * 70)
    print(" id           %s" % sample_id)
    print(" label        %s%s" % (args.label,
                                  " / %s" % args.family if args.family else ""))
    if args.note:
        print(" note         %s" % args.note)
    print(" writing      %s" % os.path.abspath(jsonl_path))
    print("")

    if args.clear:
        print(" clearing the channel first, so the window holds only this run")
        code, text = clear_channel()
        if code != 0:
            print(" could not clear it: %s"
                  % (text.strip().splitlines() or [""])[0], file=sys.stderr)
            return 2
        print(" cleared")
        print("")

    started = datetime.now()
    if args.live:
        result = collect_from_live(args, jsonl_path)
    else:
        result = collect_from_history(args, jsonl_path)
    if result is None:
        return 2
    total, counts = result

    if args.evtx:
        evtx_path = os.path.splitext(jsonl_path)[0] + ".evtx"
        code, _text = export_evtx(args.minutes, os.path.abspath(evtx_path))
        print(" archive      %s" % (os.path.abspath(evtx_path) if code == 0
                                    else "could not be written"))

    meta = {
        "sample_id": sample_id,
        "label": args.label,
        "family": args.family or None,
        "note": args.note,
        "collected": started.isoformat(timespec="seconds"),
        "mode": "live %gs" % args.live if args.live else "history %gm" % args.minutes,
        "machine": os.environ.get("COMPUTERNAME", ""),
        "events": total,
        "event_counts": {str(k): v for k, v in sorted(counts.items())},
    }
    meta_path = os.path.splitext(jsonl_path)[0] + ".meta.json"
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2)

    print("")
    print("=" * 70)
    print(" RESULT")
    print("=" * 70)
    print(" events       %s" % format(total, ","))
    for event_id in sorted(counts):
        print("   %-3d %-20s %s" % (event_id, schema.name_of(event_id),
                                    format(counts[event_id], ",")))
    print(" notes        %s" % os.path.abspath(meta_path))

    if not total:
        print("")
        print(" Nothing was captured. Either the window held no activity, or")
        print(" Sysmon is not logging. Check: python live.py --check")
        return 1

    missing = [i for i in live.NEEDED_EVENT_IDS if i not in counts]
    if missing:
        print("")
        print(" These event IDs a rule reads never appeared:")
        for event_id in missing:
            print("   %-3d %s" % (event_id, schema.name_of(event_id)))
        print(" That is expected if the activity did not cause them. If it did,")
        print(" load the matching config: python live.py --setup")

    row = corpus_row(sample_id, jsonl_path, args.label, args.family, args.manifest)
    if args.add_to_corpus:
        append_to_corpus(row, args.manifest)
        print("")
        print(" added to     %s" % os.path.abspath(args.manifest))
    else:
        print("")
        print(" Corpus row for %s:" % args.manifest)
        print("   %s,%s,%s,%s" % (row["sample_id"], row["path"],
                                  row["label"], row["family"]))

    print("")
    print(" Replay it, which gives the same result every time:")
    print("   python -m Detection.engine %s" % jsonl_path)
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    elevated = "--elevated" in argv

    parser = argparse.ArgumentParser(
        description="Record Sysmon telemetry from this machine into a capture.")
    parser.add_argument(
        "--minutes", type=float, default=DEFAULT_MINUTES,
        help="how far back to export from the channel")
    parser.add_argument(
        "--live", type=float, metavar="SECONDS",
        help="record from now instead of exporting history")
    parser.add_argument(
        "--label", choices=("malicious", "benign"), default="benign",
        help="what this capture is expected to be")
    parser.add_argument(
        "--family", choices=("ransomware", "spyware", "rat"),
        help="the expected family, for a malicious capture")
    parser.add_argument(
        "--note", default="", help="what was done during the capture")
    parser.add_argument("--sample-id", help="name for the capture")
    parser.add_argument("--out", metavar="FILE", help="where to write the .jsonl")
    parser.add_argument(
        "--max-events", type=int, default=200000,
        help="stop exporting after this many records")
    parser.add_argument(
        "--evtx", action="store_true",
        help="also save the raw .evtx for the same window")
    parser.add_argument(
        "--clear", action="store_true",
        help="clear the Sysmon channel first, so the window holds only this run")
    parser.add_argument(
        "--manifest", default=os.path.join("Evaluation", "corpus.csv"),
        help="the corpus manifest to add a row to")
    parser.add_argument(
        "--add-to-corpus", action="store_true",
        help="append the row to the manifest instead of printing it")
    parser.add_argument(
        "--list", action="store_true",
        help="report what the channel holds, then stop")
    parser.add_argument(
        "--yes", action="store_true", help="do not ask before clearing")
    parser.add_argument(
        "--elevated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.label == "malicious" and not args.family:
        parser.error("a malicious capture needs --family for the corpus")
    if args.label == "benign" and args.family:
        parser.error("a benign capture has no family")

    code = 0
    try:
        if not live.is_admin():
            return live.relaunch_elevated(
                [a for a in argv if a != "--elevated"], script=__file__)

        if args.list:
            return report_channel()

        if args.clear and not live.confirm(
                "Clearing the channel deletes what Sysmon has already logged."
                " Continue?", args.yes):
            print("Left alone.")
            return 1

        code = run(args)
    finally:
        if elevated:
            try:
                input("\nPress Enter to close this window.")
            except (EOFError, KeyboardInterrupt):
                pass
    return code


if __name__ == "__main__":
    sys.exit(main())
