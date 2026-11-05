#!/usr/bin/env python3
"""Compare two output folders of MIOTTA-NPT file by file, byte for byte.

Use it to check that a change (or a different --workers value) leaves the extracted features untouched:

    python3 miotta_npt.py capture.pcap --config a.yaml      # with the reference version, output_dir: ./out_ref
    python3 miotta_npt.py capture.pcap --config b.yaml      # with the version to check, output_dir: ./out_new
    python3 tools/compare_outputs.py out_ref out_new

Files are read in blocks, so multi-GB outputs are fine. Exit status 0 = every file identical.

With --columns, every file that differs is also compared column by column, to show WHICH columns differ and in
how many rows. Together with --allow, columns that are expected to differ do not count as a failure. Example:
if a change is only supposed to alter two columns, everything else must be identical:

    python3 tools/compare_outputs.py out_ref out_new --columns --allow tcp.analysis.initial_rtt tcp_analysis_initial_rtt

Exit status 0 then means: all files identical, or different only in the allowed columns (same header, same number
of rows). Rows are matched by position, so this is meant for outputs of the same captures with the same settings.
"""
import argparse
import csv
import itertools
import os
import sys

BLOCK = 8 * 1024 * 1024


def first_difference(path_a, path_b):
    """Return (line number, line in a, line in b) of the first differing line (lines cut to 200 chars)."""
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        number = 0
        while True:
            la, lb = fa.readline(), fb.readline()
            number += 1
            if la != lb:
                cut = lambda b: b[:200].decode("utf-8", "replace").rstrip("\n")
                return number, cut(la), cut(lb)
            if not la:
                return None


def same_bytes(path_a, path_b):
    if os.path.getsize(path_a) != os.path.getsize(path_b):
        return False
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        while True:
            a, b = fa.read(BLOCK), fb.read(BLOCK)
            if a != b:
                return False
            if not a:
                return True


def compare_columns(path_a, path_b):
    """Compare two CSV files row by row (matched by position). Returns a dict with
    header_a/header_b, rows_a/rows_b (data rows) and, for every column, how many rows differ plus the first one."""
    csv.field_size_limit(sys.maxsize)
    with open(path_a, newline="", encoding="utf-8", errors="replace") as fa, \
         open(path_b, newline="", encoding="utf-8", errors="replace") as fb:
        ra, rb = csv.reader(fa), csv.reader(fb)
        header_a, header_b = next(ra, None), next(rb, None)
        result = {"header_a": header_a, "header_b": header_b, "rows_a": 0, "rows_b": 0, "columns": {}}
        if header_a != header_b or header_a is None:
            return result
        counts = {name: 0 for name in header_a}
        first = {}
        rows = 0
        for row_a, row_b in itertools.zip_longest(ra, rb):
            if row_a is None or row_b is None:        # one file has more rows
                result["rows_a"] = rows + (0 if row_a is None else 1 + sum(1 for _ in ra))
                result["rows_b"] = rows + (0 if row_b is None else 1 + sum(1 for _ in rb))
                break
            rows += 1
            if row_a != row_b:
                for index, name in enumerate(header_a):
                    va = row_a[index] if index < len(row_a) else None
                    vb = row_b[index] if index < len(row_b) else None
                    if va != vb:
                        counts[name] += 1
                        first.setdefault(name, (rows, va, vb))
        else:
            result["rows_a"] = result["rows_b"] = rows
        result["columns"] = {name: (n, first[name]) for name, n in counts.items() if n}
        return result


def report_columns(info, allowed):
    """Print the column report; return True if the difference is entirely within the allowed columns."""
    if info["header_a"] != info["header_b"] or info["header_a"] is None:
        print("           column report: the two files have different headers (or are not CSV); not comparable")
        return False
    if info["rows_a"] != info["rows_b"]:
        print(f"           column report: different number of rows (ref {info['rows_a']}, new {info['rows_b']}); "
              f"rows cannot be matched")
        return False
    rows = info["rows_a"]
    ok = True
    if not info["columns"]:
        print("           column report: all columns identical as values (the bytes differ only in formatting)")
        return True
    print(f"           columns that differ ({rows} rows compared):")
    for name, (n, (row, va, vb)) in info["columns"].items():
        expected = name in allowed
        ok = ok and expected
        shorten = lambda v: repr(v if v is None or len(v) <= 40 else v[:40] + "...")
        print(f"             {'allowed ' if expected else 'UNEXPECTED'}  {name}: {n} rows ({100.0 * n / rows:.3f}%), "
              f"first at row {row}: ref {shorten(va)} new {shorten(vb)}")
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reference_dir")
    parser.add_argument("new_dir")
    parser.add_argument("--columns", action="store_true",
                        help="for files that differ, also show which columns differ and in how many rows")
    parser.add_argument("--allow", nargs="+", default=[], metavar="COLUMN",
                        help="columns that may differ (implies --columns); the exit status is 0 if nothing else differs")
    args = parser.parse_args()
    args.columns = args.columns or bool(args.allow)

    # Hidden entries (such as .npt_state, the bookkeeping for --resume) are not results and are not compared.
    names_a = {n for n in os.listdir(args.reference_dir) if not n.startswith(".")}
    names_b = {n for n in os.listdir(args.new_dir) if not n.startswith(".")}
    ok = True
    for name in sorted(names_a | names_b):
        if name not in names_b:
            print(f"ONLY IN {args.reference_dir}: {name}")
            ok = False
        elif name not in names_a:
            print(f"ONLY IN {args.new_dir}: {name}")
            ok = False
        elif same_bytes(os.path.join(args.reference_dir, name), os.path.join(args.new_dir, name)):
            print(f"identical  {name}")
        else:
            path_a, path_b = os.path.join(args.reference_dir, name), os.path.join(args.new_dir, name)
            diff = first_difference(path_a, path_b)
            print(f"DIFFERENT  {name}")
            if diff:
                print(f"           first difference at line {diff[0]}:\n           ref: {diff[1]}\n           new: {diff[2]}")
            if args.columns and args.allow:
                ok = report_columns(compare_columns(path_a, path_b), set(args.allow)) and ok
            elif args.columns:
                report_columns(compare_columns(path_a, path_b), set())
                ok = False
            else:
                ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
