# Simple Network Trace

A small terminal tool that reads **simulated** call/network records, lets you search by
**Call ID, source IP, or device**, shows the matching details plus every related call,
and flags simple suspicious patterns.

Pure Python 3.8+ standard library. No installs needed.

> All data in `calls.csv` is fake. IPs come from private ranges (RFC 1918) and
> documentation ranges (RFC 5737), phone numbers are made up.

## Run

```bash
git clone <your-repo-url> && cd network-trace

python nettrace.py CALL001        # search by Call ID
python nettrace.py 192.168.1.20   # search by source IP
python nettrace.py Device-B        # search by device/number (as source OR destination)
python nettrace.py --scan          # scan the whole dataset for alerts
python nettrace.py                 # interactive prompt
python nettrace.py -f other.csv X  # use a different CSV

python -m unittest -v              # run tests
```

## Data format (`calls.csv`)

`call_id, source, destination, source_ip, timestamp (ISO 8601), duration_sec, network, region`

Rows with a bad IP, timestamp or duration are skipped with a warning instead of crashing.

## Example

```
=== Trace: CALL001  (matched by Call ID) ===
Call ID     : CALL001
Source      : Device-A
IP          : 192.168.1.20 (private/reserved)
Network     : Test-Network
Region      : Coimbatore
Calls       : 6
...
Alerts
  [HIGH] Multiple calls detected in a short period: Device-A made 6 calls in 7.2 min (CALL001..CALL006).
```

## How it works

1. **Load** - `csv.DictReader` -> `Call` dataclass. IPs are validated and normalised with
   Python's `ipaddress` module; records are sorted by time.
2. **Search** - the query type is auto-detected: valid IP -> IP search; matches a Call ID -> Call
   ID search; otherwise it is matched against source/destination device names (case-insensitive).
3. **Related events** - from the match I collect the device(s) and IP(s) involved, then pull in
   every call that shares a source device, a source IP, or has that device as destination.
   So tracing one call also reveals other devices on the same IP and the same device on other IPs.
4. **Detection** - rules run over the related set using a sliding time window:

| Rule | Severity | Trigger (tunable constants at top of `nettrace.py`) | Why it matters |
|---|---|---|---|
| Burst | HIGH | >= 4 calls from one device in 10 min | automated dialing, abuse |
| Fan-out | HIGH | >= 4 distinct destinations in 10 min | robocall / spam / number scanning |
| Short calls | MEDIUM | >= 3 calls of <= 5 s in 10 min | wangiri (ring-and-drop), probing |
| Location jump | HIGH | region changes within 30 min | SIM cloning, spoofed source IP, VPN |
| Shared IP | MEDIUM | >= 3 devices behind one source IP | NAT is normal, but also SIM-box / spoofing |
| Non-public IP | INFO | private/reserved address | cannot be geolocated; trace the NAT/gateway |

## Networking notes

- Private (RFC 1918) addresses such as `192.168.x.x` and `10.x.x.x` are not routable on the internet, so a
  real trace would continue at the NAT gateway's public IP.
- `100.64.0.0/10` (Device-I) is carrier-grade NAT space: many subscribers share one public IP, so IP alone
  is weak evidence and must be combined with timestamps and device ID.
- The simulated "public" IPs use documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`), which Python
  correctly reports as non-global, hence the INFO note.

## Limitations / next steps

- Rules are simple thresholds with no baselining per user, so some false positives (e.g. a legitimate call
  centre would trip the burst rule).
- Next steps: per-device baselines, destination reputation lists, IPv6/CDR import, JSON/CSV export of alerts.

## Responsible use

Only run this against simulated data or your own authorised test environment.
