#!/usr/bin/env python3
"""Compare two output folders of MIOTTA-NPT file by file, byte for byte.

Use it to check that a change (or a different --workers value) leaves the extracted features untouched:

    python3 miotta_npt.py capture.pcap --config a.yaml      # with the reference version, output_dir: ./out_ref
    python3 miotta_npt.py capture.pcap --config b.yaml      # with the version to check, output_dir: ./out_new
    python3 tools/compare_outputs.py out_ref out_new

Files are read in blocks, so multi-GB outputs are fine. Exit status 0 = every file identical.
"""
import argparse
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reference_dir")
    parser.add_argument("new_dir")
    args = parser.parse_args()

    names_a, names_b = set(os.listdir(args.reference_dir)), set(os.listdir(args.new_dir))
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
            ok = False
            diff = first_difference(os.path.join(args.reference_dir, name), os.path.join(args.new_dir, name))
            print(f"DIFFERENT  {name}")
            if diff:
                print(f"           first difference at line {diff[0]}:\n           ref: {diff[1]}\n           new: {diff[2]}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
