"""Names of the files MIOTTA-NPT writes for an input capture.

Both miotta_npt.py (which has to know them to detect clashes and to tell whether a capture is already
processed) and the processing scripts (which write them) use this module, so the two cannot disagree.
"""
import os


def output_base_name(pcap_file):
    """Name of the capture without directory and extension, as used in the classic output names."""
    # ".pcapng" must be removed first: removing only ".pcap" turns "capture.pcapng" into "captureng".
    # Names ending in ".pcap" produce exactly the same output names as before.
    return os.path.basename(pcap_file).replace(".pcapng", "").replace(".pcap", "")


def classic_output_paths(pcap_file, output_dir):
    """The four files classic mode can write, by kind."""
    base = output_base_name(pcap_file)
    return {
        "paquetes": os.path.join(output_dir, f"paquetes_{base}.csv"),
        "ventanas": os.path.join(output_dir, f"estadisticas_ventanas_{base}.csv"),
        "flujo": os.path.join(output_dir, f"estadisticas_flujo_{base}.csv"),
        "combinadas": os.path.join(output_dir, f"estadisticas_combinadas_{base}.csv"),
    }


def nprint_output_path(pcap_file, output_dir):
    return os.path.join(output_dir, os.path.basename(pcap_file) + ".csv")


def output_key(mode, pcap_file):
    """Identifier that is unique per output set: two captures with the same key would overwrite each other."""
    if mode == "classic":
        return output_base_name(pcap_file)
    return os.path.basename(pcap_file)
