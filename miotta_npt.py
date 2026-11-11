import os
import sys
import yaml
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Folder of this script: the helper scripts and the nPrint binary are found from here,
# so the tool can be launched from any working directory.
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))

def load_config(yaml_path):
    with open(yaml_path, 'r') as f:
        return yaml.safe_load(f)

def run_classic(config, pcap):
    output_dir = config["output_dir"]
    size = config["classic"]["size_of_window"]
    mode = config["classic"]["mode"]

    cmd = [
        sys.executable,  # Use the current Python interpreter
        os.path.join(TOOL_DIR, "preprocessing_tool.py"),
        pcap,
        "--size_of_window", str(size),
        "--mode", mode,
        "--output_dir", output_dir,  # results are written there directly
    ]

    if config["classic"].get("disable_smb_dissection", False):
        cmd.append("--disable_smb_dissection")

    if config["classic"].get("disable_tcp_reassembly", False):
        cmd.append("--disable_tcp_reassembly")

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
    os.makedirs(config["output_dir"], exist_ok=True)

    runner = {"classic": run_classic, "nprint": run_nprint}.get(config["mode"])
    if runner is None:
        raise ValueError(f"Unsupported mode: {config['mode']}")

    with (ThreadPoolExecutor(max_workers=config.get("threads", 1)) as executor):
        results = executor.map(lambda pcap: runner(config, pcap), args.pcap_files)
        for pcap_file, _ in zip(args.pcap_files, results):
            print(f"Finished: {pcap_file}")

if __name__ == "__main__":
    main()
