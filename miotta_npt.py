import os
import sys
import yaml
import argparse
import difflib
import signal
import subprocess

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
    "classic": {"mode", "size_of_window", "workers", "session_reset", "tcp_reassembly"},
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

    tcp_reassembly = (config.get("classic") or {}).get("tcp_reassembly", True)
    if not isinstance(tcp_reassembly, bool):
        raise ValueError(f"classic.tcp_reassembly must be true or false, got {tcp_reassembly!r}")

    return warnings

def session_reset_packets(config):
    """Packets after which tshark forgets its state (classic mode only; 0 = never, as before)."""
    return config["classic"].get("session_reset", 0) if config["mode"] == "classic" else 0


def tcp_reassembly_enabled(config):
    """False when tshark must not reassemble TCP streams (classic mode only; default True = as before)."""
    return config["classic"].get("tcp_reassembly", True) if config["mode"] == "classic" else True


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
        if not tcp_reassembly_enabled(config):
            cmd += ["--no-tcp-reassembly"]
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

def run_tracked(cmd):
    """subprocess.run(cmd, check=True) that stops the child when this process is interrupted (Ctrl-C / SIGTERM)."""
    proc = subprocess.Popen(cmd)
    try:
        returncode = proc.wait()
    except BaseException:       # Ctrl-C / SIGTERM arrived while waiting: do not leave the child running
        stop_child(proc)
        raise
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


def run_file(config, pcap):
    label, cmd = build_command(config, pcap)
    print(f"Running {label} Preprocessing: {' '.join(cmd)}")
    run_tracked(cmd)

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
    args = parser.parse_args()

    # SIGTERM (kill, systemd, a closing job scheduler) is handled like Ctrl-C: stop the children, stop the children.
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

    try:
        process_sequentially(config, files)
    except KeyboardInterrupt:      # the running child was already stopped by run_tracked
        sys.exit("\nInterrupted.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERROR: processing failed (exit code {e.returncode}).")


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
              f"(e.g. 40000000 packets) and classic.tcp_reassembly: false to cap tshark's memory; only the RTT of "
              f"connections whose handshake lies before a reset is affected.", file=sys.stderr)


def process_sequentially(config, files):
    for pcap_file in files:
        print(f"Processing file: {pcap_file}")
        run_file(config, pcap_file)

if __name__ == "__main__":
    main()
