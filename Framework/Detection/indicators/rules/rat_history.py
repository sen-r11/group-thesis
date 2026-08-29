# Longer history for the RAT rules than StateStore keeps

# StateStore prunes its event history to 60 seconds, which is shorter than a
# beacon interval. These records live on the StateStore instance, so a new
# engine starts empty and one sample cannot carry history into the next.

from collections import deque

MAX_RECORDS = 512


def _table(store, name):
    table = getattr(store, name, None)
    if table is None:
        table = {}
        setattr(store, name, table)
    return table


def record_connection(store, pid, time, destination, port):
    table = _table(store, "rat_connections")
    key = (pid, destination, port)
    history = table.get(key)
    if history is None:
        history = deque(maxlen=MAX_RECORDS)
        table[key] = history
    history.append(float(time))
    return history


def record_dns(store, pid, time, name):
    table = _table(store, "rat_dns")
    history = table.get(pid)
    if history is None:
        history = []
        table[pid] = history
    if name not in history and len(history) < MAX_RECORDS:
        history.append(name)
    return history
