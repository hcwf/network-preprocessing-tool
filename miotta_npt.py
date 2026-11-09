import os
import sys
import yaml
import argparse
import subprocess

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
    dissection = config["classic"]["disable_smb_dissection"]

    cmd = [
        sys.executable,  # Use the current Python interpreter
        os.path.join(TOOL_DIR, "preprocessing_tool.py"),
        pcap,
        "--size_of_window", str(size),
        "--mode", mode,
        "--output_dir", output_dir,  # results are written there directly
        "--disable_smb_dissection", dissection
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
