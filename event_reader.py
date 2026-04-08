#!/usr/bin/env python3
"""
event_reader.py
Zero Trust IoT Gateway — Behavioral Monitor Event Reader

Reads events written by behavior_monitor.sh from the shared
JSONL events file. Called by the controller each cycle.

Events file format (JSON Lines — one JSON object per line):
  {"type": "SCAN",       "src_ip": "...", "targets": [...], "count": N, "ts": "..."}
  {"type": "EAST_WEST",  "src_ip": "...", "dst_ips": [...], "count": N, "ts": "..."}

The file is read and immediately cleared after each read so
events are not processed twice across cycles.
"""

import json
import os
from collections import defaultdict
from logger import log

EVENTS_FILE = "/var/run/zt-monitor-events.jsonl"


def read_and_clear():
    """
    Read all pending events from the shared events file.
    Clears the file immediately after reading (atomic swap).

    Returns:
        scan_events      : list of SCAN event dicts
        east_west_events : list of EAST_WEST event dicts
    """
    scan_events      = []
    east_west_events = []

    if not os.path.exists(EVENTS_FILE):
        return scan_events, east_west_events

    try:
        # Read and clear atomically — rename trick avoids race condition
        # with behavior_monitor.sh writing new events
        tmp_file = EVENTS_FILE + ".reading"
        os.rename(EVENTS_FILE, tmp_file)

        # Recreate empty file immediately so monitor can keep writing
        open(EVENTS_FILE, 'w').close()
        os.chmod(EVENTS_FILE, 0o666)

        # Parse events from the snapshot
        with open(tmp_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    etype = event.get("type", "")
                    if etype == "SCAN":
                        scan_events.append(event)
                    elif etype == "EAST_WEST":
                        # Filter out gateway IP (.1) — normal routing, not lateral movement
                        dsts = event.get("dst_ips", [])
                        dsts = [d for d in dsts if not d.endswith(".1")]
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
    """
    Merge multiple SCAN events for the same attacker IP.
    Returns: { attacker_ip: set(target_ips) }
    """
    merged = defaultdict(set)
    for event in scan_events:
        src = event.get("src_ip", "")
        targets = event.get("targets", [])
        if src and targets:
            merged[src].update(targets)
    return merged


def merge_east_west_events(east_west_events):
    """
    Merge multiple EAST_WEST events for the same source device.
    Returns: { src_ip: set(dst_ips) }
    """
    merged = defaultdict(set)
    for event in east_west_events:
        src = event.get("src_ip", "")
        dsts = event.get("dst_ips", [])
        if src and dsts:
            merged[src].update(dsts)
    return merged
