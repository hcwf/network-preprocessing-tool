import os
import sys
import yaml
import argparse
import datetime
import difflib
import hashlib
import json
import subprocess
import time

try:
    import fcntl
except ImportError:   # Windows: no protection against two runs working on the same capture
    fcntl = None

import npt_naming

# Folder of this script: the helper scripts and the nPrint binary are found from here,
# so the tool can be launched from any working directory.
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))

def load_config(yaml_path):
    with open(yaml_path, 'r') as f:
        return yaml.safe_load(f)

# Keys the tool reads, per section ("" = top level). Anything else in the YAML is ignored by the tool.
KNOWN_KEYS = {
    "": {"mode", "output_dir", "classic", "nprint"},
    "classic": {"mode", "size_of_window", "workers"},
    "nprint": {"headers", "masks"},
}

def validate_config(config):
    """Check the YAML before any file is processed.

    Returns a list of warnings for keys that are not used (a typo such as "worker" would otherwise be ignored
    silently and a long batch would run without the setting). Raises ValueError for values that cannot work,
    so a bad value stops the run at the start instead of at the first file.
    """
    if not isinstance(config, dict):
        raise ValueError("The configuration file must contain a YAML mapping (mode, output_dir, ...)")

    warnings = []

    def check_keys(section, values):
        known = KNOWN_KEYS[section]
        where = f"the '{section}:' section" if section else "the top level"
        for key in values:
            if key in known:
                continue
            hint = ""
            close = difflib.get_close_matches(str(key), sorted(known), n=1)
            elsewhere = [name for name, keys in KNOWN_KEYS.items() if name != section and key in keys]
            if close:
                hint = f" Did you mean '{close[0]}'?"
            elif elsewhere:
                hint = " It is a valid key under " + " or ".join(
                    f"'{name}:'" if name else "the top level" for name in elsewhere) + "."
            warnings.append(f"Unknown key '{key}' in {where}: it is ignored.{hint}")

    check_keys("", config)
    for section in ("classic", "nprint"):
        values = config.get(section)
        if values is None:
            continue
        if not isinstance(values, dict):
            raise ValueError(f"'{section}:' must be a mapping of settings, not {type(values).__name__}")
        check_keys(section, values)

    workers = (config.get("classic") or {}).get("workers", 1)
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 0:
        raise ValueError(f"classic.workers must be a whole number >= 0 (0 = all cores), got {workers!r}")

    return warnings

def build_command(config, pcap):
    """Return (label, command line) that processes one capture with the configured mode."""
    output_dir = config["output_dir"]
    if config["mode"] == "classic":
        size = config["classic"]["size_of_window"]
        mode = config["classic"]["mode"]
        workers = config["classic"].get("workers", 1)  # optional; 1 = sequential, as before

        cmd = [
            sys.executable,  # Use the current Python interpreter
            os.path.join(TOOL_DIR, "preprocessing_tool.py"),
            pcap,
            "--size_of_window", str(size),
            "--mode", mode,
            "--output_dir", output_dir,  # results are written there directly
            "--workers", str(workers)
        ]
        return "Classic", cmd

    headers = config["nprint"]["headers"]
    masks = config["nprint"]["masks"]

    cmd = [
        sys.executable,  # Use the current Python interpreter
        os.path.join(TOOL_DIR, "preprocessing_tool_nprint.py"),
        pcap,
        "--headers"
    ] + headers + ["--masks"] + masks + [
        "--output_csv", npt_naming.nprint_output_path(pcap, output_dir)
    ]
    return "nPrint", cmd

# --- Which captures are already finished (for --resume) -------------------------------------------------------
#
# When a capture has been processed successfully, a small marker file is written to <output_dir>/.npt_state/.
# It is removed again when the capture is started, so a run that is interrupted half way is never taken for a
# finished one. --resume skips a capture only if its marker matches the current settings and input file and the
# statistics files still exist.

STATE_DIR = ".npt_state"
STATE_FORMAT = 1   # raise if a change to the tool makes earlier results no longer interchangeable


def settings_fingerprint(config):
    """Hash of every setting that changes what is written. Settings that only change speed (workers, jobs) are left out."""
    if config["mode"] == "classic":
        relevant = {"mode": "classic", "classic_mode": config["classic"]["mode"],
                    "size_of_window": config["classic"]["size_of_window"]}
    else:
        relevant = {"mode": "nprint", "headers": config["nprint"]["headers"], "masks": config["nprint"]["masks"]}
    relevant["state_format"] = STATE_FORMAT
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()[:16]


def marker_path(config, pcap):
    mode = config["mode"]
    return os.path.join(config["output_dir"], STATE_DIR, f"{mode}_{npt_naming.output_key(mode, pcap)}.json")


def required_outputs(config, pcap):
    output_dir = config["output_dir"]
    if config["mode"] == "classic":
        paths = npt_naming.classic_output_paths(pcap, output_dir)
        return [paths[kind] for kind in npt_naming.CLASSIC_REQUIRED[config["classic"]["mode"]]]
    return [npt_naming.nprint_output_path(pcap, output_dir)]


def input_identity(pcap):
    info = os.stat(pcap)
    return {"size": info.st_size, "mtime_ns": info.st_mtime_ns}


def is_finished(config, pcap):
    try:
        with open(marker_path(config, pcap)) as f:
            marker = json.load(f)
    except (OSError, ValueError):
        return False
    identity = input_identity(pcap)
    return (marker.get("fingerprint") == settings_fingerprint(config)
            and marker.get("size") == identity["size"] and marker.get("mtime_ns") == identity["mtime_ns"]
            and all(os.path.exists(path) for path in required_outputs(config, pcap)))


def clear_marker(config, pcap):
    try:
        os.remove(marker_path(config, pcap))
    except FileNotFoundError:
        pass


def write_marker(config, pcap, identity, seconds):
    path = marker_path(config, pcap)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    marker = {"input": os.path.abspath(pcap), **identity, "fingerprint": settings_fingerprint(config),
              "seconds": round(seconds, 1),
              "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(marker, f, indent=1)
    os.replace(tmp, path)   # a marker is either complete or absent


class CaptureBusy(Exception):
    """Another process is still working on this capture's output files."""


def acquire_lock(config, pcap):
    """Take an exclusive lock on this capture's outputs and return its file descriptor (None if unsupported).

    The processing child inherits the descriptor, so the lock is held for as long as the child runs, even if
    this script is killed in the meantime. That matters because killing the script does not stop a child that
    is already running: starting the same capture again (--resume) while it is still writing would mix the
    output of two runs.
    """
    if fcntl is None:
        return None
    path = marker_path(config, pcap)[:-len(".json")] + ".lock"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise CaptureBusy(pcap)
    return fd


def process_capture(config, pcap):
    """Run one capture and record that it finished."""
    lock_fd = acquire_lock(config, pcap)
    try:
        identity = input_identity(pcap)   # taken before the run: a capture that changes meanwhile is not "finished"
        clear_marker(config, pcap)
        started = time.monotonic()
        run_file(config, pcap, pass_fds=() if lock_fd is None else (lock_fd,))
        write_marker(config, pcap, identity, time.monotonic() - started)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)


def run_file(config, pcap, pass_fds=()):
    label, cmd = build_command(config, pcap)
    print(f"Running {label} Preprocessing: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, pass_fds=pass_fds)

def check_inputs(mode, pcap_files):
    """Stop before any work starts if an input is missing or two captures would overwrite each other's output.

    The old behaviour for same-named captures (for example dayA/cap.pcap0 and dayB/cap.pcap0) was that the
    second silently replaced the first one's results. Returns the list of files to process.
    """
    unique = {}
    for path in pcap_files:
        unique.setdefault(os.path.abspath(path), path)
    if len(unique) < len(pcap_files):
        print(f"NOTE: {len(pcap_files) - len(unique)} input path(s) were given more than once and are processed once.")
    files = list(unique.values())

    missing = [p for p in files if not os.path.isfile(p)]
    if missing:
        listed = "\n  ".join(missing[:10]) + (f"\n  ... and {len(missing) - 10} more" if len(missing) > 10 else "")
        sys.exit(f"ERROR: {len(missing)} input file(s) not found:\n  {listed}")

    groups = {}
    for path in files:
        groups.setdefault(npt_naming.output_key(mode, path), []).append(path)
    clashes = {key: paths for key, paths in groups.items() if len(paths) > 1}
    if clashes:
        lines = [f"  {key}: " + ", ".join(paths) for key, paths in list(clashes.items())[:10]]
        sys.exit("ERROR: these captures would write the same output files and overwrite each other. "
                 "Run them separately, with different output_dir values, or rename them:\n" + "\n".join(lines))
    return files

def main():
    parser = argparse.ArgumentParser(description="Unified preprocessor for IoMT traffic")
    parser.add_argument("pcap_files", type=str, nargs='+', help="Paths to the input PCAP files")
    parser.add_argument('--config', required=True, help="Path to YAML configuration file")
    parser.add_argument('--keep-going', action='store_true',
                        help="If a capture fails, carry on with the others and report the failures at the end "
                             "(default: stop at the first failure)")
    parser.add_argument('--resume', action='store_true',
                        help="Skip captures that were already processed successfully with the same settings "
                             "(recorded in <output_dir>/.npt_state). Without it every listed capture is processed again.")
    args = parser.parse_args()

    config = load_config(args.config)
    try:
        warnings = validate_config(config)
    except ValueError as e:
        sys.exit(f"ERROR ({args.config}): {e}")
    for warning in warnings:
        print(f"WARNING ({args.config}): {warning}", file=sys.stderr)
    mode = config["mode"]
    if mode not in ("classic", "nprint"):
        sys.exit(f"ERROR ({args.config}): unsupported mode {mode!r} (use 'classic' or 'nprint')")

    files = check_inputs(mode, args.pcap_files)
    os.makedirs(config["output_dir"], exist_ok=True)

    if args.resume:
        done = {p for p in files if is_finished(config, p)}
        if done:
            print(f"Resume: {len(done)} of {len(files)} capture(s) are already finished and are skipped.")
        files = [p for p in files if p not in done]
        if not files:
            print("Nothing left to do.")

    failed = []
    for index, pcap_file in enumerate(files, 1):
        print(f"Processing file: {pcap_file}")
        try:
            process_capture(config, pcap_file)
        except (subprocess.CalledProcessError, CaptureBusy) as e:
            if isinstance(e, CaptureBusy):
                failed.append((pcap_file, "busy"))
                print(f"ERROR: {pcap_file} is still being processed by another run (for example a run that was "
                      f"killed but whose processing has not ended yet). Wait for it and use --resume.", file=sys.stderr)
            else:
                failed.append((pcap_file, e.returncode))
                print(f"ERROR: {pcap_file} failed (exit code {e.returncode}).", file=sys.stderr)
            if not args.keep_going:
                not_started = len(files) - index
                if not_started:
                    print(f"Stopping: {not_started} capture(s) were not started (use --keep-going to continue "
                          f"after a failure).", file=sys.stderr)
                break

    if failed:
        print(f"\n{len(failed)} of {len(files)} capture(s) failed:", file=sys.stderr)
        for pcap_file, code in failed:
            print(f"  {pcap_file} ({'busy' if code == 'busy' else f'exit code {code}'})", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
