import os
import sys
import yaml
import argparse
import datetime
import difflib
import hashlib
import json
import signal
import subprocess
import threading
import time
import concurrent.futures

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
    "": {"mode", "output_dir", "jobs", "classic", "nprint"},
    "classic": {"mode", "size_of_window", "workers", "session_reset"},
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

    session_reset = (config.get("classic") or {}).get("session_reset", 0)
    if isinstance(session_reset, bool) or not isinstance(session_reset, int) or session_reset < 0:
        raise ValueError(f"classic.session_reset must be a whole number >= 0 (0 = off), got {session_reset!r}")

    jobs = config.get("jobs", 1)
    if isinstance(jobs, bool) or not isinstance(jobs, int) or jobs < 1:
        raise ValueError(f"jobs must be a whole number >= 1, got {jobs!r}")

    return warnings

def session_reset_packets(config):
    """Packets after which tshark forgets its state (classic mode only; 0 = never, as before)."""
    return config["classic"].get("session_reset", 0) if config["mode"] == "classic" else 0


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
        if session_reset_packets(config):
            cmd += ["--session-reset", str(session_reset_packets(config))]
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
    if session_reset_packets(config):      # only when on, so results made without it stay valid for --resume
        relevant["session_reset"] = session_reset_packets(config)
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


def process_capture(config, pcap, log=None):
    """Run one capture and record that it finished. With a log file the child's output goes there."""
    lock_fd = acquire_lock(config, pcap)
    try:
        identity = input_identity(pcap)   # taken before the run: a capture that changes meanwhile is not "finished"
        clear_marker(config, pcap)
        started = time.monotonic()
        run_file(config, pcap, pass_fds=() if lock_fd is None else (lock_fd,), log=log)
        write_marker(config, pcap, identity, time.monotonic() - started)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)


_active = set()          # processing children that are running right now
_active_lock = threading.Lock()
_shutting_down = threading.Event()   # set on interrupt: no new child may start afterwards


def run_tracked(cmd, pass_fds=(), log=None):
    """subprocess.run(cmd, check=True) that remembers the child so it can be stopped on interrupt.

    With log=None the child writes to this terminal as before; with a file it gets stdout and stderr there.
    """
    with _active_lock:
        if _shutting_down.is_set():
            raise KeyboardInterrupt()
        proc = subprocess.Popen(cmd, pass_fds=pass_fds, stdout=log, stderr=subprocess.STDOUT if log else None)
        _active.add(proc)
    try:
        returncode = proc.wait()
    except BaseException:       # Ctrl-C / SIGTERM arrived while waiting: do not leave the child running
        stop_child(proc)
        raise
    finally:
        with _active_lock:
            _active.discard(proc)
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, cmd)


def stop_child(proc):
    if proc.poll() is None:
        proc.terminate()        # the processing scripts turn SIGTERM into a clean exit that stops tshark/nPrint too
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def stop_all_children():
    with _active_lock:
        _shutting_down.set()
        procs = list(_active)
    for proc in procs:
        stop_child(proc)


def run_file(config, pcap, pass_fds=(), log=None):
    label, cmd = build_command(config, pcap)
    if log is None:
        print(f"Running {label} Preprocessing: {' '.join(cmd)}")
    run_tracked(cmd, pass_fds=pass_fds, log=log)

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

    # SIGTERM (kill, systemd, a closing job scheduler) is handled like Ctrl-C: stop the children, leave no marker.
    signal.signal(signal.SIGTERM, lambda signum, frame: (_ for _ in ()).throw(KeyboardInterrupt()))

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
    warn_if_tshark_may_run_out_of_memory(config, files)
    os.makedirs(config["output_dir"], exist_ok=True)

    if args.resume:
        done = {p for p in files if is_finished(config, p)}
        if done:
            print(f"Resume: {len(done)} of {len(files)} capture(s) are already finished and are skipped.")
        files = [p for p in files if p not in done]
        if not files:
            print("Nothing left to do.")

    jobs = min(config.get("jobs", 1), max(len(files), 1))
    warn_if_oversubscribed(config, jobs)
    failed = []
    try:
        if jobs > 1:
            failed = process_parallel(config, files, jobs, args.keep_going)
        else:
            failed = process_sequentially(config, files, args.keep_going)
    except KeyboardInterrupt:
        stop_all_children()
        sys.exit("\nInterrupted. Captures that were finished are kept; run again with --resume to continue.")

    if failed:
        print(f"\n{len(failed)} of {len(files)} capture(s) failed:", file=sys.stderr)
        for pcap_file, code in failed:
            print(f"  {pcap_file} ({'busy' if code == 'busy' else f'exit code {code}'})", file=sys.stderr)
        sys.exit(1)


# Measured with tshark 4.2.2 and the fields of this tool: its memory grows by about 0.5-0.7 KB per packet, i.e. about
# 0.8 GB per GB of capture for typical packet sizes, and it is only released when tshark ends or resets (-M).
TSHARK_GB_PER_CAPTURE_GB = 0.8


def warn_if_tshark_may_run_out_of_memory(config, files):
    if config["mode"] != "classic" or session_reset_packets(config):
        return
    try:
        ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return
    big = [(os.path.getsize(p), p) for p in files if os.path.getsize(p) * TSHARK_GB_PER_CAPTURE_GB > ram / 2]
    if big:
        size, path = max(big)
        print(f"WARNING: {len(big)} capture(s) are large for this machine (largest: {path}, {size / 1e9:.0f} GB). "
              f"tshark needs roughly {size * TSHARK_GB_PER_CAPTURE_GB / 1e9:.0f} GB of memory for it "
              f"({ram / 1e9:.0f} GB installed) and may be killed. Set classic.session_reset in the YAML "
              f"(e.g. 50000000 packets) to cap tshark's memory; only the RTT of connections whose handshake lies "
              f"before a reset is affected.", file=sys.stderr)


def warn_if_oversubscribed(config, jobs):
    workers = (config.get("classic") or {}).get("workers", 1) if config["mode"] == "classic" else 1
    cores = os.cpu_count() or 1
    effective = workers or cores
    if jobs > 1 and jobs * effective > cores:
        print(f"WARNING: jobs ({jobs}) x workers ({effective}) = {jobs * effective} busy processes, but this machine "
              f"has {cores} CPU cores. The captures will compete; consider fewer jobs or workers. Memory also "
              f"scales with jobs x workers.", file=sys.stderr)


def log_path(config, pcap):
    return marker_path(config, pcap)[:-5] + ".log"


def process_parallel(config, files, jobs, keep_going):
    """Process several captures at once. Each capture still runs in its own process exactly as when run alone."""
    os.makedirs(os.path.join(config["output_dir"], STATE_DIR), exist_ok=True)
    failed, stop = [], threading.Event()
    done_count, print_lock = [0], threading.Lock()
    total = len(files)

    def say(text, err=False):
        with print_lock:
            print(text, file=sys.stderr if err else sys.stdout, flush=True)

    def work(pcap):
        if stop.is_set():
            return pcap, "skipped"
        path = log_path(config, pcap)
        started = time.monotonic()
        say(f"Started: {pcap}")
        try:
            with open(path, "w") as log:
                process_capture(config, pcap, log=log)
        except CaptureBusy:
            return pcap, "busy"
        except KeyboardInterrupt:
            return pcap, "skipped"
        except subprocess.CalledProcessError as e:
            return pcap, e.returncode
        os.remove(path)               # logs are only kept for failed captures
        with print_lock:
            done_count[0] += 1
            n = done_count[0]
        say(f"Finished [{n}/{total}] {pcap} ({time.monotonic() - started:.0f}s)")
        return pcap, 0

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
    try:
        futures = [pool.submit(work, p) for p in files]
        for future in concurrent.futures.as_completed(futures):
            pcap, code = future.result()
            if code in (0, "skipped"):
                continue
            failed.append((pcap, code))
            if code == "busy":
                say(f"ERROR: {pcap} is still being processed by another run. Wait for it and use --resume.", True)
            else:
                say(f"ERROR: {pcap} failed (exit code {code}). Its output is in {log_path(config, pcap)}", True)
            if not keep_going and not stop.is_set():
                stop.set()
                say("Stopping: captures that have not started will be skipped (use --keep-going to continue after "
                    "a failure); running ones finish.", True)
    except KeyboardInterrupt:
        stop.set()
        pool.shutdown(wait=False, cancel_futures=True)
        stop_all_children()
        raise
    pool.shutdown()
    return failed


def process_sequentially(config, files, keep_going):
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
            if not keep_going:
                not_started = len(files) - index
                if not_started:
                    print(f"Stopping: {not_started} capture(s) were not started (use --keep-going to continue "
                          f"after a failure).", file=sys.stderr)
                break
    return failed

if __name__ == "__main__":
    main()
