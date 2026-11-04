#!/usr/bin/env bash
# Measure the memory and time tshark needs when several consecutive capture files are merged first.
#
#   tools/measure_batch_merge.sh [-m LIMIT_GB] [-s "1 2 4"] file1.pcap file2.pcap ...
#
# For every batch size N in -s, the first N files (in the order given: use recording order) are appended with
# `mergecap -a` (no sorting, streaming) and piped into the same tshark fields the tool uses. The CSV is discarded.
# Peak memory (resident set) and wall time come from GNU time (/usr/bin/time -v).
#
# tshark's memory grows with the packets and conversations it has seen, so start small and raise the sizes only
# while the previous peak is well below your RAM. -m stops a run that exceeds LIMIT_GB (systemd-run if available,
# otherwise ulimit -v) instead of letting the PC freeze; the table then says "stopped" and the script ends.
set -uo pipefail

LIMIT_GB=""; SIZES="1 2 4"
while getopts "m:s:" opt; do
  case $opt in m) LIMIT_GB=$OPTARG ;; s) SIZES=$OPTARG ;; *) exit 2 ;; esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { echo "usage: $0 [-m LIMIT_GB] [-s \"1 2 4\"] files..." >&2; exit 2; }
for tool in mergecap tshark /usr/bin/time; do
  command -v "$tool" >/dev/null || { echo "$tool not found (mergecap/tshark: wireshark-common, tshark; time: time)" >&2; exit 1; }
done

# same fields, same order as run_tshark() in preprocessing_tool.py
merge_and_dissect() {
  mergecap -a -F pcap -w - "$@" | tshark -r - -T fields \
    -e ip.src -e ip.dst -e ip.proto -e frame.len -e tcp.flags -e tcp.srcport -e tcp.dstport -e tcp.len -e udp.length \
    -e tcp.hdr_len -e udp.srcport -e udp.dstport -e eth.type -e llc.control -e frame.time_epoch -e ip.ttl -e ip.hdr_len \
    -e tcp.analysis.initial_rtt -e tcp.connection.fin -e tcp.connection.syn -e tcp.flags.cwr -e tcp.flags.ece \
    -e tcp.urgent_pointer -e ip.frag_offset -e eth.src_not_group \
    -E header=y -E separator=, -E quote=d -E occurrence=f > /dev/null
}
export -f merge_and_dissect

run_limited() {
  if [ -z "$LIMIT_GB" ]; then "$@"
  elif command -v systemd-run >/dev/null && systemd-run --user --scope -q true 2>/dev/null; then
    systemd-run --user --scope -q -p MemoryMax="${LIMIT_GB}G" -p MemorySwapMax=0 "$@"
  else
    ( ulimit -v $((LIMIT_GB * 1024 * 1024)); "$@" )
  fi
}

printf "%-7s %-13s %-9s %s\n" files peak_RSS_GB seconds result
for n in $SIZES; do
  if [ "$n" -gt $# ]; then echo "skipping $n: only $# files given" >&2; continue; fi
  log=$(mktemp); start=$(date +%s)
  run_limited /usr/bin/time -v -o "$log" bash -c 'merge_and_dissect "$@"' _ "${@:1:$n}" 2>/dev/null
  rc=$?
  kb=$(awk '/Maximum resident set size/ {print $NF}' "$log"); rm -f "$log"
  printf "%-7s %-13s %-9s %s\n" "$n" "$(awk -v k="${kb:-0}" 'BEGIN{printf "%.2f", k/1048576}')" "$(( $(date +%s) - start ))" \
         "$([ $rc -eq 0 ] && echo ok || echo "stopped (exit $rc: memory limit or error)")"
  [ $rc -eq 0 ] || break
done
