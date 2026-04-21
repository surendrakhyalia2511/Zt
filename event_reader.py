#!/usr/bin/env python3
import json
import os
from collections import defaultdict
from logger import log

EVENTS_FILE = "/var/run/zt-monitor-events.jsonl"


def read_and_clear():
    scan_events = east_west_events = []
    scan_events, east_west_events = [], []
    if not os.path.exists(EVENTS_FILE):
        return scan_events, east_west_events
    try:
        tmp_file = EVENTS_FILE + ".reading"
        os.rename(EVENTS_FILE, tmp_file)
        open(EVENTS_FILE, 'w').close()
        os.chmod(EVENTS_FILE, 0o666)
        with open(tmp_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    event = json.loads(line)
                    etype = event.get("type", "")
                    if etype == "SCAN":
                        scan_events.append(event)
                    elif etype == "EAST_WEST":
                        dsts = [d for d in event.get("dst_ips", []) if not d.endswith(".1")]
                        if dsts:
                            event["dst_ips"] = dsts
                            east_west_events.append(event)
                except json.JSONDecodeError:
                    pass
        os.remove(tmp_file)
    except Exception as e:
        log(f"Event reader error: {e}", "WARN")
    return scan_events, east_west_events


def merge_scan_events(scan_events):
    merged = defaultdict(set)
    for event in scan_events:
        src, targets = event.get("src_ip", ""), event.get("targets", [])
        if src and targets:
            merged[src].update(targets)
    return merged


def merge_east_west_events(east_west_events):
    merged = defaultdict(set)
    for event in east_west_events:
        src, dsts = event.get("src_ip", ""), event.get("dst_ips", [])
        if src and dsts:
            merged[src].update(dsts)
    return merged
