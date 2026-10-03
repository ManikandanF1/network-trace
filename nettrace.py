#!/usr/bin/env python3
"""Simple Network Trace - search simulated call records and flag suspicious activity.

Usage:
    python nettrace.py CALL001          # by Call ID
    python nettrace.py 192.168.1.20     # by source IP
    python nettrace.py Device-A         # by device / number (source or destination)
    python nettrace.py --scan           # scan the whole dataset for alerts
    python nettrace.py                  # interactive prompt
"""
import argparse
import csv
import ipaddress
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

DATA_FILE = Path(__file__).with_name("calls.csv")

# ---- Detection thresholds (tune here) -------------------------------------
BURST_COUNT = 4                         # >= this many calls from one device ...
BURST_WINDOW = timedelta(minutes=10)    # ... inside this window = burst
FANOUT_COUNT = 4                        # >= this many DISTINCT destinations in the window
SHORT_CALL_SEC = 5                      # calls this short or shorter are "very short"
SHORT_CALL_COUNT = 3                    # >= this many very short calls in the window
SHARED_IP_DEVICES = 3                   # >= this many devices behind one IP
HOP_WINDOW = timedelta(minutes=30)      # region change faster than this is suspicious

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
COLORS = {"HIGH": "91", "MEDIUM": "93", "INFO": "96", "BOLD": "1", "DIM": "2"}
USE_COLOR = sys.stdout.isatty()


def paint(text, style):
    return f"\033[{COLORS[style]}m{text}\033[0m" if USE_COLOR else text


@dataclass(frozen=True)
class Call:
    call_id: str
    source: str
    destination: str
    source_ip: str
    timestamp: datetime
    duration: int
    network: str
    region: str


# ---- 1. Read records -------------------------------------------------------
def load_calls(path):
    """Read the CSV, validate each row, skip bad rows with a warning."""
    calls = []
    with open(path, newline="", encoding="utf-8") as f:
        for line_no, row in enumerate(csv.DictReader(f), start=2):
            try:
                calls.append(Call(
                    call_id=row["call_id"].strip(),
                    source=row["source"].strip(),
                    destination=row["destination"].strip(),
                    source_ip=str(ipaddress.ip_address(row["source_ip"].strip())),
                    timestamp=datetime.fromisoformat(row["timestamp"].strip()),
                    duration=int(row["duration_sec"]),
                    network=row["network"].strip(),
                    region=row["region"].strip(),
                ))
            except (ValueError, KeyError, AttributeError) as err:
                print(f"warning: skipping line {line_no}: {err}", file=sys.stderr)
    return sorted(calls, key=lambda c: c.timestamp)


# ---- 2. Search -------------------------------------------------------------
def search(calls, query):
    """Return (kind, matching_calls). Kind is 'IP', 'Call ID', 'Device' or None."""
    q = query.strip()
    try:  # valid IP address? normalise it so "::1" style variants still match
        ip = str(ipaddress.ip_address(q))
        return "IP", [c for c in calls if c.source_ip == ip]
    except ValueError:
        pass
    by_id = [c for c in calls if c.call_id.lower() == q.lower()]
    if by_id:
        return "Call ID", by_id
    by_dev = [c for c in calls if q.lower() in (c.source.lower(), c.destination.lower())]
    return ("Device", by_dev) if by_dev else (None, [])


def related_calls(calls, kind, query, seeds):
    """Everything linked to the match: same device, same IP, or device as destination."""
    if kind == "Call ID":
        devices, ips = {seeds[0].source}, {seeds[0].source_ip}
    elif kind == "IP":
        devices, ips = {c.source for c in seeds}, {seeds[0].source_ip}
    else:  # Device: use the spelling from the data, IPs it has called from
        names = {n for c in seeds for n in (c.source, c.destination) if n.lower() == query.lower()}
        devices = names
        ips = {c.source_ip for c in seeds if c.source in names}
    return [c for c in calls
            if c.source in devices or c.source_ip in ips or c.destination in devices]


# ---- 5. Suspicious-activity rules -----------------------------------------
def _windows(events, window):
    """For each event, the list of events starting at it and falling inside `window`."""
    for i, first in enumerate(events):
        yield [e for e in events[i:] if e.timestamp - first.timestamp <= window]


def _span(events):
    return (events[-1].timestamp - events[0].timestamp).total_seconds() / 60


def analyze(calls):
    """Run all rules on a list of calls. Returns [(severity, message), ...]."""
    alerts = []
    by_device, by_ip = {}, {}
    for c in calls:
        by_device.setdefault(c.source, []).append(c)
        by_ip.setdefault(c.source_ip, []).append(c)

    for dev, evs in by_device.items():
        evs = sorted(evs, key=lambda c: c.timestamp)

        # Rule 1: burst of calls from one device
        best = max(_windows(evs, BURST_WINDOW), key=len)
        if len(best) >= BURST_COUNT:
            alerts.append(("HIGH", f"Multiple calls detected in a short period: {dev} made "
                                   f"{len(best)} calls in {_span(best):.1f} min "
                                   f"({best[0].call_id}..{best[-1].call_id})."))

        # Rule 2: calling many different numbers quickly (robocall / scanning pattern)
        best = max(_windows(evs, BURST_WINDOW), key=lambda w: len({e.destination for e in w}))
        distinct = len({e.destination for e in best})
        if distinct >= FANOUT_COUNT:
            alerts.append(("HIGH", f"High fan-out: {dev} called {distinct} different numbers "
                                   f"in {_span(best):.1f} min (possible robocall/spam)."))

        # Rule 3: many near-zero-length calls (wangiri / ring-and-drop probing)
        shorts = [e for e in evs if e.duration <= SHORT_CALL_SEC]
        best = max(_windows(shorts, BURST_WINDOW), key=len, default=[])
        if len(best) >= SHORT_CALL_COUNT:
            alerts.append(("MEDIUM", f"Repeated very short calls: {dev} placed {len(best)} calls "
                                     f"of <= {SHORT_CALL_SEC}s within {_span(best):.1f} min."))

        # Rule 4: impossible travel - region changes faster than a person/SIM could move
        for a, b in zip(evs, evs[1:]):
            if a.region != b.region and b.timestamp - a.timestamp <= HOP_WINDOW:
                mins = (b.timestamp - a.timestamp).total_seconds() / 60
                alerts.append(("HIGH", f"Location jump: {dev} moved {a.region} -> {b.region} in "
                                       f"{mins:.0f} min ({a.call_id} -> {b.call_id}); possible "
                                       f"SIM cloning, spoofed source or VPN."))

    # Rule 5: many devices behind one source IP
    for ip, evs in by_ip.items():
        devs = sorted({e.source for e in evs})
        if len(devs) >= SHARED_IP_DEVICES:
            alerts.append(("MEDIUM", f"Shared IP: {ip} is used by {len(devs)} devices "
                                     f"({', '.join(devs)}); could be NAT/gateway, or a SIM-box / spoofing."))

    # Info: what kind of address is it?
    for ip in by_ip:
        if not ipaddress.ip_address(ip).is_global:
            alerts.append(("INFO", f"{ip} is not a public internet address (private/reserved); "
                                   f"it cannot be geolocated directly - trace the NAT/gateway instead."))

    return sorted(alerts, key=lambda a: SEVERITY_ORDER[a[0]])


# ---- 3 & 4. Display --------------------------------------------------------
def ip_kind(ip):
    return "public" if ipaddress.ip_address(ip).is_global else "private/reserved"


def print_table(rows, marked_ids):
    head = f"  {'Call ID':<8} {'Time':<19} {'Source':<9} {'Destination':<15} {'IP':<15} {'Dur(s)':>6}  Region"
    print(paint(head, "BOLD"))
    for c in rows:
        mark = ">" if c.call_id in marked_ids else " "
        print(f"{mark} {c.call_id:<8} {c.timestamp:%Y-%m-%d %H:%M:%S} {c.source:<9} "
              f"{c.destination:<15} {c.source_ip:<15} {c.duration:>6}  {c.region}")


def report(calls, query):
    kind, seeds = search(calls, query)
    if not kind:
        print(f"No records found for '{query}'.")
        return False

    related = related_calls(calls, kind, query, seeds)
    print(paint(f"\n=== Trace: {query}  (matched by {kind}) ===", "BOLD"))

    if kind == "Call ID":
        c = seeds[0]
        print(f"Call ID     : {c.call_id}")
        print(f"Source      : {c.source}")
        print(f"Destination : {c.destination}")
        print(f"IP          : {c.source_ip} ({ip_kind(c.source_ip)})")
        print(f"Timestamp   : {c.timestamp:%Y-%m-%d %H:%M:%S}")
        print(f"Duration    : {c.duration}s")
        print(f"Network     : {c.network}")
        print(f"Region      : {c.region}")
    else:
        print(f"Devices     : {', '.join(sorted({c.source for c in related}))}")
        print(f"IPs         : {', '.join(sorted({c.source_ip for c in related}))}")
        print(f"Networks    : {', '.join(sorted({c.network for c in related}))}")
        print(f"Regions     : {', '.join(sorted({c.region for c in related}))}")
        print(f"First/Last  : {related[0].timestamp:%H:%M:%S} / {related[-1].timestamp:%H:%M:%S}")
    print(f"Calls       : {len(related)}")

    print(paint("\nRelated calls/events  ('>' = direct match)", "BOLD"))
    print_table(related, {c.call_id for c in seeds})

    print(paint("\nAlerts", "BOLD"))
    alerts = analyze(related)
    if not any(sev != "INFO" for sev, _ in alerts):
        print("  No suspicious activity detected.")
    for sev, msg in alerts:
        print(f"  {paint(f'[{sev}]', sev)} {msg}")
    print()
    return True


def scan(calls):
    print(paint("\n=== Full dataset scan ===", "BOLD"))
    alerts = [a for a in analyze(calls) if a[0] != "INFO"]
    if not alerts:
        print("  No suspicious activity detected.")
    for sev, msg in alerts:
        print(f"  {paint(f'[{sev}]', sev)} {msg}")
    print(f"\n{len(calls)} records scanned, {len(alerts)} alert(s).\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Simple network/call trace tool (simulated data).")
    parser.add_argument("query", nargs="?", help="Call ID, IP address, or device/number")
    parser.add_argument("-f", "--file", default=DATA_FILE, help="CSV file (default: calls.csv)")
    parser.add_argument("--scan", action="store_true", help="scan every record and list all alerts")
    args = parser.parse_args(argv)

    try:
        calls = load_calls(args.file)
    except FileNotFoundError:
        print(f"error: data file not found: {args.file}", file=sys.stderr)
        return 2

    if args.scan:
        scan(calls)
    elif args.query:
        return 0 if report(calls, args.query) else 1
    else:
        print(f"Loaded {len(calls)} records. Enter a Call ID, IP or device (blank to quit).")
        while True:
            q = input("trace> ").strip()
            if not q:
                break
            report(calls, q)
    return 0


if __name__ == "__main__":
    sys.exit(main())
