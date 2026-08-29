# Longer history for the RAT rules than StateStore keeps

# StateStore prunes its event history to 60 seconds, which is shorter than a
# beacon interval. These records live on the StateStore instance, so a new
# engine starts empty and one sample cannot carry history into the next.

# Records are kept against the file on disk rather than the PID. Malware
# restarts itself, and history kept per PID starts again every time it does

from collections import deque

MAX_RECORDS = 512


def _table(store, name):
    table = getattr(store, name, None)
    if table is None:
        table = {}
        setattr(store, name, table)
    return table


def record_connection(store, image, time, destination, port):
    table = _table(store, "rat_connections")
    key = (str(image or "").lower(), destination, port)
    history = table.get(key)
    if history is None:
        history = deque(maxlen=MAX_RECORDS)
        table[key] = history
    history.append(float(time))
    return history


def record_dns(store, image, time, name):
    table = _table(store, "rat_dns")
    key = str(image or "").lower()
    history = table.get(key)
    if history is None:
        history = []
        table[key] = history
    if name not in history and len(history) < MAX_RECORDS:
        history.append(name)
    return history
