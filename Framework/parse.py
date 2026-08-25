"""The parser. It changes raw Sysmon records to schema events.

Read a saved export:

    python parse.py sample_sysmon.xml

Read the live Sysmon channel for 60 seconds. This needs administrator rights:

    python parse.py --live 60

Write the events to a .jsonl file, which is the schema on disk:

    python parse.py sample_sysmon.xml --json events.jsonl
"""

import argparse
import json
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime

import schema

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_time(text):
    """Convert a Sysmon timestamp to a Unix timestamp in seconds.

    Sysmon writes seven digits after the point. datetime reads six, so this
    cuts the extra digit. The loss is 100 nanoseconds.
    """
    text = text.replace("Z", "+00:00")
    if "." in text:
        head, rest = text.split(".", 1)
        offset = ""
        for sign in ("+", "-"):
            if sign in rest:
                offset = rest[rest.index(sign):]
                rest = rest[:rest.index(sign)]
                break
        digits = "".join(c for c in rest if c.isdigit())[:6]
        text = "%s.%s%s" % (head, digits.ljust(6, "0"), offset)
    return datetime.fromisoformat(text).timestamp()


def parse_element(root):
    #Convert one <Event> element to a schema event.
    system = root.find(NS + "System")
    event = {
        "kind": schema.HOST,
        "event_id": int(system.find(NS + "EventID").text),
        "time": parse_time(system.find(NS + "TimeCreated").get("SystemTime")),
        "pid": 0,
        "process": "unknown",
    }
    for node in root.iter(NS + "Data"):
        name = schema.FIELD_MAP.get(node.get("Name"))
        if name:
            event[name] = node.text or ""
    for field in ("pid", "ppid"):
        value = event.get(field)
        if isinstance(value, str) and value.isdigit():
            event[field] = int(value)
    return event


def parse_xml(xml_text):
    """Convert one raw Sysmon event in XML text to a schema event."""
    return parse_element(ET.fromstring(xml_text))


def from_xml_file(path):
    #Read a Sysmon export in XML. Event Viewer writes this format.
    #The export holds one <Event> element for each record, and it has no root
    #element around them. XML needs one root, so this adds one when the text
    #does not parse without it.

    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        body = text.strip()
        if body.startswith("<?"):
            body = body[body.index("?>") + 2:]
        root = ET.fromstring("<Events>%s</Events>" % body)
    nodes = [root] if root.tag == NS + "Event" else list(root)
    for node in nodes:
        try:
            yield parse_element(node)
        except Exception:
            continue    # a record that will not parse can't stop the run


def from_evtx(path):
    """Read a saved .evtx file. This needs python-evtx."""
    from Evtx.Evtx import Evtx

    with Evtx(path) as log:
        for record in log.records():
            try:
                yield parse_xml(record.xml())
            except Exception:
                continue


def from_jsonl(path):
    """Read events that the parser wrote before. One JSON object a line."""
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield json.loads(line)


def open_file(path):
    #Pick a reader from the file name.
    lower = path.lower()
    if lower.endswith(".evtx"):
        return from_evtx(path)
    if lower.endswith(".xml"):
        return from_xml_file(path)
    if lower.endswith(".jsonl"):
        return from_jsonl(path)
    raise ValueError("unknown file type: %s" % path)


NO_MORE_ITEMS = 259     # the wait ended and no event arrived. this is normal.
INVALID_OPERATION = 4317    # no read is pending. also normal.
ACCESS_DENIED = 5       # the channel needs administrator rights
MAX_ERRORS = 10         # real errors in a row before the reader gives up

QUIET = (NO_MORE_ITEMS, INVALID_OPERATION)


def from_live(timeout_ms=2000, seconds=None):
    """Read the live Sysmon channel. This needs pywin32, on Windows.

    The reader stops after the given number of seconds. It runs until Ctrl+C
    when seconds is None.

    A quiet channel and a broken channel look the same from one call, so this
    counts the errors that are not the normal timeout. It stops after
    MAX_ERRORS of them. Without that count, a long run can spin and write
    nothing.
    """
    import win32event
    import win32evtlog

    channel = "Microsoft-Windows-Sysmon/Operational"
    # EvtSubscribe needs a signal event or a callback. With neither it
    # answers error 87 and the message does not say why. Windows never
    # signals this event for our subscription, so the reader ignores it and
    # lets EvtNext do the waiting. The name must stay in scope, because the
    # subscription holds it.
    signal = win32event.CreateEvent(None, 0, 0, None)
    try:
        handle = win32evtlog.EvtSubscribe(
            channel, win32evtlog.EvtSubscribeToFutureEvents, signal)
    except Exception as problem:
        if getattr(problem, "winerror", None) == ACCESS_DENIED:
            raise RuntimeError(
                "access denied on %s.\nRead the channel as administrator."
                % channel)
        raise

    end = None if seconds is None else time.time() + seconds
    errors = 0
    while end is None or time.time() < end:
        try:
            records = win32evtlog.EvtNext(handle, 32, int(timeout_ms), 0)
            errors = 0
        except Exception as problem:
            if getattr(problem, "winerror", None) in QUIET:
                continue    # no event arrived inside the timeout
            errors += 1
            if errors >= MAX_ERRORS:
                raise RuntimeError(
                    "the Sysmon channel failed %d times in a row: %s"
                    % (errors, problem))
            time.sleep(1.0)
            continue
        for record in records:
            xml_text = win32evtlog.EvtRender(
                record, win32evtlog.EvtRenderEventXml)
            try:
                yield parse_xml(xml_text)
            except Exception:
                continue


def show(event):
    """Print one event in a readable form."""
    stamp = datetime.fromtimestamp(event["time"]).strftime("%H:%M:%S.%f")[:-3]
    print("%s  %-2d %-18s pid %-6s %s" % (
        stamp, event["event_id"], schema.name_of(event["event_id"]),
        event["pid"], schema.subject(event)))
    for field in schema.extras(event):
        print("%18s%s = %s" % ("", field, event[field]))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Change raw Sysmon records to schema events.")
    parser.add_argument(
        "path", nargs="?", help="a .evtx, .xml or .jsonl file")
    parser.add_argument(
        "--live", type=float, metavar="SECONDS",
        help="read the live Sysmon channel instead of a file")
    parser.add_argument(
        "--json", metavar="FILE", help="write the events to a .jsonl file")
    parser.add_argument(
        "--limit", type=int, metavar="N", help="stop after N events")
    parser.add_argument(
        "--quiet", action="store_true", help="print the counts only")
    args = parser.parse_args(argv)

    if not args.path and args.live is None:
        parser.error("give a file, or give --live SECONDS")

    try:
        if args.live is not None:
            stream = from_live(seconds=args.live)
        else:
            stream = open_file(args.path)
        out = open(args.json, "w", encoding="utf-8") if args.json else None
    except (ValueError, OSError, RuntimeError) as problem:
        print("error: %s" % problem, file=sys.stderr)
        return 2

    counts = {}
    total = 0
    try:
        for event in stream:
            total += 1
            counts[event["event_id"]] = counts.get(event["event_id"], 0) + 1
            if not args.quiet:
                show(event)
            if out:
                out.write(json.dumps(event) + "\n")
            if args.limit and total >= args.limit:
                break
    except KeyboardInterrupt:
        print("\nstopped")
    except (ValueError, OSError, RuntimeError) as problem:
        print("error: %s" % problem, file=sys.stderr)
        return 2
    finally:
        if out:
            out.close()

    print("\n%d events" % total)
    for event_id in sorted(counts):
        print("  %-3d %-18s %d" % (
            event_id, schema.name_of(event_id), counts[event_id]))
    if args.json:
        print("\nwritten to %s" % args.json)
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
