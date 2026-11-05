# MIOTTA-NPT: Network Traffic Analysis Tool for IoMT and IoT Research

![MIOTTA-NPT Tool Overview](workflow.png)

## 🔍 Overview

**MIOTTA-NPT** is a network traffic preprocessing tool designed to streamline the analysis of `.pcap` files. It allows for the extraction of statistics in `.csv` format based on:
- Individual packet metrics
- Grouping by **windows** of configurable size
- Grouping by **flows** (TCP/UDP)
- **Raw packet** representations using the [nPrint](https://github.com/nprint/nprint) standard

This repository is intended for researchers working on Intrusion Detection Systems (IDS), network machine learning, and traffic analysis in **IoT/IoMT** environments.

---

## ⚙️ Installation

### General Requirements

- Python 3.10+
- `tshark` version 4.0.0 or later (Wireshark CLI; tested with 4.2.2)
- `nPrint` compilation (modified for ARP support; needs `g++`, `make` and `libpcap-dev`) — only for `nprint` mode

### Installing Dependencies

```bash
pip install -r requirements.txt
```

pandas 3 is not supported yet (`requirements.txt` keeps `pandas<3`). Tested with Python 3.12, pandas 2.3.2, numpy 2.3.2, scipy 1.16.2, dpkt 1.9.8 and PyYAML 6.0.3.

### Compiling nPrint (Run Once)

```bash
cd nprint
make
```

## 🚀 Quick Start

```bash
python3 miotta_npt.py file1.pcap file2.pcap --config config/example_config.yaml
```

The tool can be launched from any directory (e.g. `python3 /path/to/miotta_npt.py capture.pcap --config my_config.yaml`). Results are written directly into `output_dir` (relative paths are relative to the directory you launch it from).

### Reproducing the published datasets

The features of the datasets published with this tool (CICIoMT2024 and IoMT-TrafficData unified dataset, DOI [10.34810/DATA3305](https://doi.org/10.34810/DATA3305); HospNet26, DOI [10.34810/DATA3050](https://doi.org/10.34810/DATA3050)) were extracted with `config/iomt_ids_window100.yaml` (`classic` mode, `combinada`, windows of 100 packets):

```bash
python3 miotta_npt.py capture.pcap --config config/iomt_ids_window100.yaml
```

## 🗄️ Large captures (hundreds of GB and more)

`.pcap` and `.pcapng` inputs work in both modes, and no stage loads a whole capture into memory any more:
`classic` mode works on 200,000-row chunks and `nprint` mode on 50,000-row chunks. **The extracted features
are unchanged**: the feature functions are untouched, and on the test captures used during development the
output was byte-identical to the original. Confirm this on your own data with `tools/compare_outputs.py` (below).

- **Speed (`classic` mode).** `workers` in the `classic:` section of the YAML (or `--workers N` on
  `preprocessing_tool.py`; default `1` = sequential as before, `0` = all cores) computes several chunks at the
  same time and writes them back in order. The output is identical for any value. Each worker needs memory for
  one chunk (about a few GB; lower the value if the machine runs out of memory). The tshark pass that comes first
  is single-threaded and is not sped up. `workers > 1` needs the `fork` start method (Linux/macOS).
- **One huge capture (`session_reset`).** tshark keeps state for every packet it has read, about 0.5-0.7 KB each
  (measured with tshark 4.2.2 and this tool's fields), and only frees it when it ends. That is roughly 0.8 GB of
  memory per GB of capture: a 2 GB file needs about 2 GB, an 80 GB file about as much as a 64 GB machine has, and
  hundreds of GB cannot be processed in one run. `session_reset: N` in the `classic:` section (tshark's `-M N`)
  makes tshark forget its state every N packets. With ordinary traffic that caps its memory at roughly
  150 MB + N x 0.6 KB (for example `session_reset: 40000000` is about 25-30 GB), but see `tcp_reassembly` below: a
  stream that never completes can use far more than that between two resets. Notes:
  - Only fields that depend on earlier packets change: `tcp.analysis.initial_rtt` (and its window statistics
    column) is empty for a connection whose handshake lies before a reset. On a real two-file sample, resetting
    every 10,000 packets changed no other column. The fewer the resets, the fewer connections are affected, so pick
    the largest N your memory allows.
  - It is off by default (`0`), and then the tshark command is exactly as before. The tool prints a warning when
    a capture looks too large for the installed memory and `session_reset` is not set.
  - Check the effect on your data with
    `python3 tools/compare_outputs.py out_plain out_reset --allow tcp.analysis.initial_rtt tcp_analysis_initial_rtt`.
  - **`tcp_reassembly: false`** (tshark `-o tcp.desegment_tcp_streams:FALSE`, default `true` = as before) stops tshark
    from reassembling TCP streams. On a real merged capture of about 56M+ packets, tshark reached 46 GB with 16M
    packets since the last reset and slowed from ~18,000 to ~100 packets/s, while it printed `Adding
    tcp.segment.overlap would put more than 1000000 items in the tree`. The likely cause is a TCP stream whose
    upper-layer data never completes, which makes tshark keep (and list) every segment; this was not reproduced
    with synthetic traffic, so treat it as the working explanation. None of the fields this tool extracts is produced
    by reassembly, and the output was identical on the test captures, but check it on a slice of your own data
    (`tools/compare_outputs.py`) before relying on it.
- **Many captures (`--resume`, `--keep-going`).** Give `miotta_npt.py` as many `.pcap`/`.pcapng` files
  as you like (a shell glob works); they are processed one after the other, each written to its own set of
  outputs. Progress is printed as `Finished [k/total]`.
  - `--resume` skips captures that were already processed with the same settings (the markers are in
    `<output_dir>/.npt_state`). A capture counts as finished only if its marker exists, its input file has the same
    size and modification time, and its output files are still there; anything else is processed again. Use it to
    continue after an interruption or a failure, or to add newly recorded files to a finished batch. Without
    `--resume` every listed capture is processed again.
  - `--keep-going` carries on after a failed capture and lists the failures at the end (the exit status is 1).
    Without it the run stops at the first failure.
  - Ctrl-C and `kill` stop tshark/nPrint and the workers as well, and leave no marker for the capture that was
    running. Two runs on the same `output_dir` cannot process the same capture at once (a lock file refuses it).
  - Two captures whose names would produce the same output files (e.g. `a/cap.pcap` and `b/cap.pcap`, or
    `cap.pcap` and `cap.pcapng`) are refused before anything runs.
- **Disk is the limit, not memory.** The outputs themselves are large, and they are what the tool has always
  written. Rough sizes, measured on synthetic traffic, so measure a small slice of your own capture first:
  the packet table `paquetes_*.csv` takes about 135 bytes per packet, and the flow statistics
  (`flujos`/`all`, window of 10) about 200 bytes per packet. In `paquetes` and `all` modes the packet table is
  rewritten, which needs one extra copy of it while it runs. `nprint` rows have more than 1,500 columns, i.e.
  several KB per packet, and nPrint's intermediate CSV (as large as the final output) is created next to the
  output file, so plan for about twice the output size there.
- **Do not change `CHUNK_SIZE`** (`preprocessing_tool.py`) if outputs must stay comparable with datasets made with
  the original tool: windows and column types are decided per chunk.
- **Check a change of your own** with the same tool: run both versions on one capture and
  `python3 tools/compare_outputs.py out_reference out_new`.
  Add `--columns` to see which columns differ and in how many rows, and `--allow COLUMN ...` for columns that
  are expected to differ (the exit status is then 0 if nothing else changed).

## 🛠️ YAML Configuration File

Basic example (`config/example_config.yaml`):

```yaml
mode: "nprint"              # or "classic"
output_dir: "./output"

classic:
  mode: all                 # Analysis type: paquetes (packets), ventana (windows), flujos (flows), combinada (windows + flows), all
  size_of_window: 10        # Number of packets per window

nprint:
  headers: [ethernet, ipv4, ipv6, absolute_time, icmp, tcp, udp, relative_time, arp]    # Protocol headers included in the output
  masks: [ethernet, arp, ipv4, ipv6, tcp, udp, ip, icmp]                                # Headers from which to remove location information
```

The YAML is checked before any file is processed. Keys the tool does not know (a typo such as `worker`, or a
setting placed in the wrong section) are reported as `WARNING` lines on stderr and ignored, with a "did you
mean" hint where possible. A value that cannot work (for example `workers: "2"` or `workers: -1`) stops the
run with an `ERROR` before anything is processed.

## 📂 Generated Outputs

Depending on the method selected, CSV files are generated in the `output_dir` of the configuration (`./output` in the examples).

### Statistical Analysis (`preprocessing_tool.py`)
- `paquetes_*.csv`: complete network traffic
- `estadisticas_ventanas_*.csv`: grouped by windows
- `estadisticas_flujo_*.csv`: grouped by flow
- `estadisticas_combinadas_*.csv`: combination of both (windows and flows)

### nPrint Analysis (`preprocessing_tool_nprint.py`)
- `<pcap file name>.csv`: raw representation of binary headers

## 📁 Repository Structure

```bash
miotta-npt/
├── miotta_npt.py                 # Main script
├── preprocessing_tool.py         # Statistical processing
├── preprocessing_tool_nprint.py  # Processing with nPrint
├── tools/
│   └── compare_outputs.py        # byte-for-byte comparison of two output folders
├── config/
│   ├── example_config.yaml
│   └── iomt_ids_window100.yaml   # configuration of the published datasets
├── output/
├── nprint/
│   └── (sources + Makefile)
├── requirements.txt
├── LICENSE
└── README.md
```

## 📜 License

This project is available under the MIT License (see [LICENSE](LICENSE)). The modified nPrint code in `nprint/` keeps its original Apache 2.0 license (`nprint/LICENSE`, `nprint/NOTICE`).


