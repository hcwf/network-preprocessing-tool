#!/usr/bin/env python3
"""Remove duplicate packets that were recorded twice: once untagged and once with a VLAN tag.

Some captures contain every frame twice (for example when the same traffic is seen on a physical interface
and on a VLAN sub-interface). The two copies are identical except for the 4-byte 802.1Q tag. tshark counts
both, which doubles packet, window and flow statistics and makes TCP reassembly see every segment twice.

This script reads a classic .pcap file once, in order, and writes a .pcap file without the tagged copy of
every such pair. It is meant to run BEFORE miotta_npt.py. The packets it keeps are written byte for byte,
in the original order; nothing is rewritten.

A packet is removed only when ALL of these hold:
  * it carries an 802.1Q tag whose VLAN ID is one of --vlan (default: 1);
  * an untagged packet with exactly the same bytes (the tag aside) was recorded within --window-us;
  * that untagged packet is not already the twin of another tagged packet (one-to-one matching), so two
    identical untagged packets are never merged with each other, and the untagged copy is always the one kept.
Everything else (other VLAN IDs, tagged packets without an untagged twin, untagged packets) is kept.

Memory depends on the window, not on the file size. Use --dry-run first: it only reports (including the time
gaps between the two copies) and writes nothing.

Give - as input and/or output to read from standard input and/or write to standard output, for example
  mergecap -a -F pcap -w - part*.pcap | dedup_pcap.py - - | tcpdump -r - -w dedup.pcap -C 2000
When the packets go to standard output, the report is printed on standard error.
"""
import argparse
import collections
import contextlib
import os
import struct
import sys
import time

# first four bytes of the file -> (byte order, nanoseconds per timestamp fraction unit)
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),   # microseconds, little endian
    b"\xa1\xb2\xc3\xd4": (">", 1000),   # microseconds, big endian
    b"\x4d\x3c\xb2\xa1": ("<", 1),      # nanoseconds, little endian
    b"\xa1\xb2\x3c\x4d": (">", 1),      # nanoseconds, big endian
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# upper limits (ns) of the buckets of the gap histogram
GAP_BUCKETS = [(1_000, "< 1 us"), (10_000, "< 10 us"), (100_000, "< 100 us"), (1_000_000, "< 1 ms"),
               (10_000_000, "< 10 ms"), (100_000_000, "< 100 ms")]

KEEP, DROP, UNDECIDED = 1, 2, 0


def gap_bucket(gap_ns):
    for index, (limit, _) in enumerate(GAP_BUCKETS):
        if gap_ns < limit:
            return index
    return len(GAP_BUCKETS)


def comparison_key(data):
    """Bytes that two copies of the same frame share.

    Frames shorter than the Ethernet minimum are padded with zeros, and a tagged frame has 4 padding bytes
    fewer than its untagged twin, so for short frames the trailing zeros are ignored.
    """
    return data.rstrip(b"\x00") if len(data) <= 60 else data


def dedup(infile, outfile, window_ns, vlans, max_pending, progress=True, unmatched_tagged=None,
          unmatched_untagged=None):
    """Copy infile to outfile (None = report only) without the tagged twins. Returns (statistics, gap histogram).

    unmatched_tagged / unmatched_untagged: optional binary files that receive the packets that found no twin.
    """
    head = infile.read(24)
    if head[:4] == PCAPNG_MAGIC:
        sys.exit("ERROR: this is a pcapng file. Convert it first: editcap -F pcap input.pcapng output.pcap")
    if len(head) < 24 or head[:4] not in MAGICS:
        sys.exit("ERROR: not a classic pcap file (unknown magic number).")
    endian, unit_ns = MAGICS[head[:4]]
    linktype = struct.unpack(endian + "I", head[20:24])[0] & 0x0FFFFFFF
    if linktype != 1:
        sys.exit(f"ERROR: only Ethernet captures (link type 1) are supported; this file has link type {linktype}.")
    for side in (outfile, unmatched_tagged, unmatched_untagged):
        if side is not None:
            side.write(head)

    unpack_record = struct.Struct(endian + "IIII").unpack
    read = infile.read
    write = outfile.write if outfile is not None else None

    stats = collections.Counter()
    other_vlans = collections.Counter()
    gaps = [0] * (len(GAP_BUCKETS) + 1)

    # Packets are written in their original order. A tagged packet may have to wait (at most one window) until it
    # is known whether its untagged twin shows up, and everything behind it waits too.
    queue = collections.deque()          # items [raw record, state, timestamp]
    pending_tagged = {}                  # key -> deque of undecided tagged items
    order_tagged = collections.deque()   # (timestamp, key, item) in file order, to expire them
    recent_untagged = {}                 # key -> deque of entries [timestamp, used]
    order_untagged = collections.deque() # (key, entry) in file order
    state = {"last": None}

    def flush():
        while queue and queue[0][1] != UNDECIDED:
            item = queue.popleft()
            if item[1] == KEEP and write is not None:
                write(item[0])

    def decide_everything():
        """Give up waiting: every undecided packet is kept (used at the end, after a jump back in time, or when
        too many packets are waiting)."""
        for item in queue:
            if item[1] == UNDECIDED:
                item[1] = KEEP
                stats["tagged_without_twin"] += 1
                if unmatched_tagged is not None:
                    unmatched_tagged.write(item[0])
        for entries in recent_untagged.values():
            stats["untagged_without_twin"] += len(entries)
            if unmatched_untagged is not None:
                for entry in entries:
                    unmatched_untagged.write(entry[2])
        pending_tagged.clear()
        order_tagged.clear()
        recent_untagged.clear()
        order_untagged.clear()
        flush()

    started = time.monotonic()
    while True:
        record_header = read(16)
        if not record_header:
            break
        if len(record_header) < 16:
            stats["truncated_file"] = 1
            break
        seconds, fraction, included, _original = unpack_record(record_header)
        data = read(included)
        if len(data) < included:
            stats["truncated_file"] = 1
            break
        timestamp = seconds * 1_000_000_000 + fraction * unit_ns
        stats["packets"] += 1

        # --- time bookkeeping: forget what is older than the window --------------------------------------------
        last = state["last"]
        if last is None or timestamp > last:
            state["last"] = last = timestamp
        elif timestamp + window_ns < last:        # the file jumps back in time (e.g. appended captures)
            decide_everything()
            stats["jumps_back_in_time"] += 1
            state["last"] = last = timestamp
        cutoff = last - window_ns
        while order_tagged and order_tagged[0][0] < cutoff:
            _, key, item = order_tagged.popleft()
            if item[1] == UNDECIDED:
                item[1] = KEEP
                stats["tagged_without_twin"] += 1
                if unmatched_tagged is not None:
                    unmatched_tagged.write(item[0])
                waiting = pending_tagged[key]
                waiting.popleft()
                if not waiting:
                    del pending_tagged[key]
        while order_untagged and order_untagged[0][1][0] < cutoff:
            key, entry = order_untagged.popleft()
            if not entry[1]:
                stats["untagged_without_twin"] += 1
                if unmatched_untagged is not None:
                    unmatched_untagged.write(entry[2])
                recent = recent_untagged[key]
                recent.popleft()
                if not recent:
                    del recent_untagged[key]

        # --- classify the packet ------------------------------------------------------------------------------
        raw = record_header + data
        tagged = False
        if len(data) >= 14 and data[12] == 0x81 and data[13] == 0x00 and len(data) >= 18:
            vlan_id = ((data[14] << 8) | data[15]) & 0x0FFF
            if vlan_id in vlans:
                tagged = True
                key = comparison_key(data[:12] + data[16:])
            else:
                other_vlans[vlan_id] += 1
                queue.append([raw, KEEP, timestamp])
                flush()
                continue
        elif len(data) >= 14 and data[12] == 0x88 and data[13] == 0xA8:
            other_vlans["802.1ad"] += 1
            queue.append([raw, KEEP, timestamp])
            flush()
            continue
        else:
            key = comparison_key(data)

        if tagged:
            stats["tagged"] += 1
            recent = recent_untagged.get(key)
            if recent and abs(timestamp - recent[0][0]) <= window_ns:
                entry = recent.popleft()
                entry[1] = True
                if not recent:
                    del recent_untagged[key]
                gaps[gap_bucket(abs(timestamp - entry[0]))] += 1
                stats["removed"] += 1
                queue.append([raw, DROP, timestamp])
            else:
                item = [raw, UNDECIDED, timestamp]
                pending_tagged.setdefault(key, collections.deque()).append(item)
                order_tagged.append((timestamp, key, item))
                queue.append(item)
        else:
            stats["untagged"] += 1
            waiting = pending_tagged.get(key)
            if waiting and abs(timestamp - waiting[0][2]) <= window_ns:
                twin = waiting.popleft()
                if not waiting:
                    del pending_tagged[key]
                twin[1] = DROP
                gaps[gap_bucket(abs(timestamp - twin[2]))] += 1
                stats["removed"] += 1
            else:
                entry = [timestamp, False, raw]
                recent_untagged.setdefault(key, collections.deque()).append(entry)
                order_untagged.append((key, entry))
            queue.append([raw, KEEP, timestamp])
        flush()

        if len(queue) > max_pending:
            decide_everything()
            stats["forced_decisions"] += 1
        if progress and stats["packets"] % 5_000_000 == 0:
            rate = stats["packets"] / max(time.monotonic() - started, 1e-9)
            print(f"  {stats['packets']:,} packets read, {stats['removed']:,} removed ({rate:,.0f} packets/s)",
                  file=sys.stderr, flush=True)

    decide_everything()
    stats["other_vlans"] = sum(other_vlans.values())
    return stats, gaps, other_vlans


def print_report(stats, gaps, other_vlans, dry_run, out=None):
    total, removed = stats["packets"], stats["removed"]
    out = out or sys.stdout
    print(f"\nPackets read:                         {total:>14,}", file=out)
    print(f"  untagged:                           {stats['untagged']:>14,}", file=out)
    print(f"  tagged with a chosen VLAN ID:       {stats['tagged']:>14,}", file=out)
    print(f"  other VLAN IDs / 802.1ad (kept):    {stats['other_vlans']:>14,}", file=out)
    for vlan, count in sorted(other_vlans.items(), key=lambda item: -item[1])[:10]:
        print(f"      VLAN {vlan}: {count:,}", file=out)
    print(f"Duplicate pairs found (tagged copy {'would be ' if dry_run else ''}removed): {removed:>8,}", file=out)
    print(f"Packets {'that would be kept' if dry_run else 'written'}:                    {total - removed:>14,}", file=out)
    print(f"Tagged packets without an untagged twin (kept):   {stats['tagged_without_twin']:>8,}", file=out)
    print(f"Untagged packets without a tagged twin (kept):    {stats['untagged_without_twin']:>8,}", file=out)
    if removed:
        print("Time between the two copies of a pair:", file=out)
        labels = [label for _, label in GAP_BUCKETS] + [">= 100 ms"]
        for label, count in zip(labels, gaps):
            print(f"  {label:>10}: {count:>12,}", file=out)
    for key, text in (("jumps_back_in_time", "jumps back in time in the file (undecided packets were kept)"),
                      ("forced_decisions", "times too many packets were waiting (raise --max-pending)")):
        if stats[key]:
            print(f"NOTE: {stats[key]:,} {text}", file=out)
    if stats["truncated_file"]:
        print("WARNING: the input ends in the middle of a packet; the incomplete packet was ignored.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Remove the VLAN-tagged copy of packets that were recorded twice (untagged and tagged). "
                    "Run it before miotta_npt.py; the kept packets are copied unchanged and in order.")
    parser.add_argument("input", help="classic .pcap file, or - for standard input "
                                      "(use editcap -F pcap to convert a pcapng file)")
    parser.add_argument("output", nargs="?", help="where to write the result, or - for standard output; the report "
                                                  "then goes to standard error (not needed with --dry-run)")
    parser.add_argument("--window-us", type=float, default=1000.0,
                        help="largest time difference in microseconds between the two copies (default: 1000 = 1 ms)")
    parser.add_argument("--vlan", type=int, nargs="+", default=[1], metavar="ID",
                        help="VLAN IDs whose tagged packets may be removed as duplicates (default: 1)")
    parser.add_argument("--max-pending", type=int, default=1_000_000,
                        help="safety limit for packets waiting for a decision (default: 1000000)")
    parser.add_argument("--dry-run", action="store_true", help="only report what would be removed; write nothing")
    parser.add_argument("--save-unmatched", metavar="PREFIX",
                        help="also write the packets that found no twin to PREFIX_tagged.pcap and "
                             "PREFIX_untagged.pcap, to look at them with tshark (works with --dry-run)")
    args = parser.parse_args()

    if not args.dry_run and not args.output:
        parser.error("an output file is needed (or use --dry-run)")
    if args.window_us < 0 or args.max_pending < 1:
        parser.error("--window-us must be >= 0 and --max-pending >= 1")
    from_stdin = args.input == "-"
    to_stdout = not args.dry_run and args.output == "-"
    if (args.output and not from_stdin and args.output != "-"
            and os.path.abspath(args.output) == os.path.abspath(args.input)):
        parser.error("the output must not be the input file")
    if from_stdin and sys.stdin.isatty():
        parser.error("standard input is a terminal; pipe a pcap into it")
    if to_stdout and sys.stdout.isatty():
        parser.error("standard output is a terminal; pipe it into another program or give a file name")

    window_ns = int(args.window_us * 1000)
    vlans = set(args.vlan)
    # a file is written as NAME.part and renamed at the end; a pipe cannot be renamed, so it is written directly
    partial = None if args.dry_run or to_stdout else args.output + ".part"
    side_paths = [] if not args.save_unmatched else [args.save_unmatched + "_tagged.pcap",
                                                      args.save_unmatched + "_untagged.pcap"]
    try:
        with contextlib.ExitStack() as files:
            infile = files.enter_context(open(sys.stdin.fileno() if from_stdin else args.input, "rb",
                                              buffering=16 * 1024 * 1024, closefd=not from_stdin))
            if to_stdout:
                outfile = files.enter_context(open(sys.stdout.fileno(), "wb", buffering=16 * 1024 * 1024,
                                                   closefd=False))
            elif partial:
                outfile = files.enter_context(open(partial, "wb", buffering=16 * 1024 * 1024))
            else:
                outfile = None
            sides = [files.enter_context(open(path, "wb", buffering=4 * 1024 * 1024)) for path in side_paths]
            stats, gaps, other_vlans = dedup(infile, outfile, window_ns, vlans, args.max_pending,
                                             unmatched_tagged=sides[0] if sides else None,
                                             unmatched_untagged=sides[1] if sides else None)
        if partial is not None:
            os.replace(partial, args.output)     # the output is either complete or absent
    except BaseException:
        if partial is not None and os.path.exists(partial):
            os.remove(partial)
        raise
    print_report(stats, gaps, other_vlans, args.dry_run, out=sys.stderr if to_stdout else sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # the program reading our standard output has gone away (for example tcpdump stopped)
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())   # no second error at interpreter exit
        except OSError:
            pass
        sys.exit("ERROR: the program reading the output has closed the pipe; the output is incomplete.")
