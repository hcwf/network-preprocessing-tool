import os
import sys
import yaml
import argparse
import difflib
import subprocess

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

def run_classic(config, pcap):
    output_dir = config["output_dir"]
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

    print(f"Running Classic Preprocessing: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def run_nprint(config, pcap):
    output_dir = config["output_dir"]
    headers = config["nprint"]["headers"]
    masks = config["nprint"]["masks"]

    cmd = [
        sys.executable,  # Use the current Python interpreter
        os.path.join(TOOL_DIR, "preprocessing_tool_nprint.py"),
        pcap,
        "--headers"
    ] + headers + ["--masks"] + masks + [
        "--output_csv", os.path.join(output_dir, os.path.basename(pcap) + ".csv")
    ]

    print(f"Running nPrint Preprocessing: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def main():
    parser = argparse.ArgumentParser(description="Unified preprocessor for IoMT traffic")
    parser.add_argument("pcap_files", type=str, nargs='+', help="Paths to the input PCAP files")
    parser.add_argument('--config', required=True, help="Path to YAML configuration file")
    args = parser.parse_args()

    config = load_config(args.config)
    try:
        warnings = validate_config(config)
    except ValueError as e:
        sys.exit(f"ERROR ({args.config}): {e}")
    for warning in warnings:
        print(f"WARNING ({args.config}): {warning}", file=sys.stderr)
    mode = config["mode"]

    os.makedirs(config["output_dir"], exist_ok=True)

    for pcap_file in args.pcap_files:
        print(f"Processing file: {pcap_file}")
        if mode == "classic":
            run_classic(config, pcap_file)
        elif mode == "nprint":
            run_nprint(config, pcap_file)
        else:
            raise ValueError(f"Unsupported mode: {mode}")

if __name__ == "__main__":
    main()
