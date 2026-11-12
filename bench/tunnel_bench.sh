#!/usr/bin/env bash
# Measures what the tunnel costs, on one machine, without touching the network.
#
# The traffic goes through the tunnel, the rules and a proxy node, and comes
# back to the same machine: the client, the core and the target all live
# here, so the number is the core's own capacity and nothing else. That is
# the same shape as the measurement the Clash kernel publishes, and it is
# the only shape that can be compared across machines.
#
# Two modes:
#
#   --mode tun     the client's packets go through the tunnel device, so the
#                  user space stack (mips, the go stack) is measured. Needs
#                  a core binary and, on macOS and Linux, root: the tunnel
#                  device and its routes are the system's.
#   --mode proxy   the client's packets go straight into the core's inbound.
#                  Measures the relay path (splice, copy blocks, buffers)
#                  without the tunnel device.
#
# The core binary is not built here. Get one from CI or from a release, and
# point --core at it.
#
# Usage:
#   bench/tunnel_bench.sh --core /path/to/SkywardCore [--mode tun|proxy]
#                          [--stack legacy|go] [--size 256] [--runs 9]
#                          [--warmup 1]
#
# The median of the measured runs is the verdict, not the best one. The
# first transfer warms caches and the congestion window and is discarded.
# cv and spread are printed so a noisy run cannot be mistaken for a result.

set -euo pipefail

mode=tun
stack=legacy
size_mib=256
runs=9
warmup=1
core_bin=""
target_port=18080
mixed_port=17890
proxy_port=17891
file_name="payload.bin"
# The client asks for this address. In tunnel mode it is routed into the
# tunnel, and the local proxy node reaches the target from there, so the
# traffic never leaves the machine.
client_address="198.18.0.2"

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --core) core_bin="$2"; shift 2 ;;
    --mode) mode="$2"; shift 2 ;;
    --stack) stack="$2"; shift 2 ;;
    --size) size_mib="$2"; shift 2 ;;
    --runs) runs="$2"; shift 2 ;;
    --warmup) warmup="$2"; shift 2 ;;
    --help|-h) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

if [[ -z "$core_bin" ]]; then
  echo "--core is required" >&2
  usage 1
fi
if [[ ! -x "$core_bin" ]]; then
  echo "the core binary is not executable: $core_bin" >&2
  exit 1
fi
if ! command -v curl >/dev/null; then
  echo "curl is required" >&2
  exit 1
fi
if ! command -v python3 >/dev/null; then
  echo "python3 is required (it serves the target and the proxy node)" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/skyward-bench.XXXXXX")"
core_pid=""
target_pid=""
proxy_pid=""
route_added=false
cleanup() {
  [[ -n "$core_pid" ]] && kill "$core_pid" 2>/dev/null || true
  [[ -n "$target_pid" ]] && kill "$target_pid" 2>/dev/null || true
  [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
  if [[ "$route_added" == true ]]; then
    $SUDO ip route del 198.18.0.0/16 dev skyward-bench 2>/dev/null || true
  fi
  # The core writes until it is gone, and a directory that is still being
  # written cannot be removed.
  sleep 0.5
  rm -rf "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT

# The target serves a file big enough that the transfer lasts longer than the
# sampling interval, so the CPU and memory numbers describe the transfer and
# not the setup.
head -c "$((size_mib * 1024 * 1024))" /dev/urandom > "$work_dir/$file_name"

# The proxy node. It answers every request by reaching the target, whatever
# address it was asked for: that is what keeps the traffic on this machine.
# A second core would do the same job; this is smaller.
start_proxy() {
  python3 - "$proxy_port" "$target_port" <<'PY' &
import socket
import sys
import threading

proxy_port, target_port = int(sys.argv[1]), int(sys.argv[2])
target = ("127.0.0.1", target_port)


def pipe(left, right):
    try:
        while True:
            data = left.recv(65536)
            if not data:
                break
            right.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (left, right):
            try:
                sock.close()
            except OSError:
                pass


def handle(client):
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                return
            data += chunk
        upstream = socket.create_connection(target)
    except OSError:
        client.close()
        return
    if data.upper().startswith(b"CONNECT"):
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    else:
        upstream.sendall(data)
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    pipe(upstream, client)


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", proxy_port))
server.listen(128)
while True:
    connection, _ = server.accept()
    threading.Thread(target=handle, args=(connection,), daemon=True).start()
PY
  proxy_pid=$!
  sleep 1
}

if [[ "$mode" == "tun" ]]; then
  tun_enable=true
  outbound=local
  # "legacy" is the stack the kernel runs today. The configuration has to
  # name a stack, so the name is spelled out here.
  tun_stack=mips
else
  tun_enable=false
  outbound=DIRECT
  tun_stack=mips
fi
if [[ "$stack" != "legacy" ]]; then
  tun_stack="$stack"
fi

cat > "$work_dir/config.yaml" <<EOF
mixed-port: $mixed_port
allow-lan: false
mode: rule
log-level: warning
ipv6: false
dns:
  enable: false
proxies:
  - name: local
    type: http
    server: 127.0.0.1
    port: $proxy_port
rules:
  - MATCH,$outbound
tun:
  enable: $tun_enable
  stack: $tun_stack
  device: skyward-bench
  auto-route: false
  auto-detect-interface: false
  inet4-address:
    - 172.31.0.1/30
EOF

python3 - "$work_dir" "$target_port" <<'PY' &
import http.server
import os
import sys

directory, port = sys.argv[1], int(sys.argv[2])
os.chdir(directory)


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
target_pid=$!
sleep 1

if ! curl --silent --fail --max-time 5 -o /dev/null "http://127.0.0.1:$target_port/$file_name"; then
  echo "the target server did not come up on 127.0.0.1:$target_port" >&2
  exit 1
fi

# The tunnel device and its routes are the system's, so the core needs root
# on macOS and Linux. On Windows the driver asks for the privilege itself.
SUDO=""
if [[ $EUID -ne 0 ]]; then
  SUDO="sudo -n"
fi

run_core() {
  # -inbound is what opens the ports the configuration names. The core is
  # built to be driven by the app, which starts the listeners itself after
  # its tunnel is up; a core run from here has no app behind it, so it has
  # to be told to open them, or the mixed port would be read and ignored.
  $SUDO "$core_bin" -d "$work_dir" -f "$work_dir/config.yaml" -inbound &
  core_pid=$!
  sleep 3
  if ! kill -0 "$core_pid" 2>/dev/null; then
    echo "the core did not stay up; its log is in $work_dir" >&2
    exit 1
  fi
}

if [[ "$mode" == "tun" ]]; then
  start_proxy
  run_core
  # Only the address the client asks for is routed into the tunnel, so the
  # machine's own traffic is left alone.
  for _ in $(seq 1 50); do
    if $SUDO ip link show skyward-bench >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
  if ! $SUDO ip link show skyward-bench >/dev/null 2>&1; then
    echo "the tunnel device did not come up; the links are:" >&2
    $SUDO ip -brief link show >&2
    exit 1
  fi
  $SUDO ip route add 198.18.0.0/16 dev skyward-bench
  route_added=true
else
  run_core
fi

# In tunnel mode the client asks for an address the tunnel owns; the local
# proxy node reaches the target from there. In proxy mode the client talks
# to the inbound directly.
if [[ "$mode" == "tun" ]]; then
  url="http://$client_address:$target_port/$file_name"
  proxy_arg=()
else
  url="http://127.0.0.1:$target_port/$file_name"
  proxy_arg=(--proxy "http://127.0.0.1:$mixed_port")
fi

sample_rss() {
  # ps prints the same column on macOS and Linux.
  ps -o rss= -p "$core_pid" 2>/dev/null | tr -d ' '
}

core_cpu_seconds() {
  # The CPU the core has spent so far, in seconds.
  #
  # On Linux the kernel's own counter is read: ps prints the time as a
  # clock, whole seconds only, and a transfer that costs a tenth of a second
  # would print as no cost at all. Anywhere else ps is the only source, and
  # the clock it prints is read back into seconds before two reads can be
  # subtracted. %cpu is not used: it is the average over the core's whole
  # life, and a three second life with a second of work averages to a third
  # of the answer.
  if [[ -r "/proc/$core_pid/stat" ]]; then
    awk -v ticks="$(getconf CLK_TCK 2>/dev/null || echo 100)" \
      '{ sub(/^[0-9]+ \([^)]*\) /, ""); print ($12 + $13) / ticks }' \
      "/proc/$core_pid/stat" 2>/dev/null
  else
    ps -o cputime= -p "$core_pid" 2>/dev/null | tr -d ' ' |
      awk -F: '{ seconds = 0; for (field = 1; field <= NF; field++) seconds = seconds * 60 + $field; print seconds }'
  fi
}

echo "mode=$mode stack=$stack size=${size_mib}MiB runs=$runs warmup=$warmup"
echo "core pid $core_pid, target 127.0.0.1:$target_port"

results=()
# The first transfer warms caches and the sender's congestion window. It is
# measured and printed, but never enters the statistics: on the legacy stack
# the first three runs rose monotonically, which made best-of-three a measure
# of warm-up rather than of the stack.
for run in $(seq 1 "$((runs + warmup))"); do
  peak_rss=0

  (
    while kill -0 "$core_pid" 2>/dev/null; do
      rss=$(sample_rss)
      [[ -n "$rss" ]] && echo "$rss" >> "$work_dir/samples"
      sleep 0.1
    done
  ) &
  sampler=$!

  cpu_before=$(core_cpu_seconds)
  # curl measures the transfer itself, so the window the CPU is divided by
  # is the transfer and not the setup around it.
  read -r speed total < <(curl --silent --output /dev/null \
    --write-out '%{speed_download} %{time_total}\n' \
    --max-time 600 "${proxy_arg[@]}" "$url")
  cpu_after=$(core_cpu_seconds)
  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true

  if [[ -s "$work_dir/samples" ]]; then
    peak_rss=$(awk '{ if ($1 > max) max = $1 } END { print max + 0 }' "$work_dir/samples")
  fi
  : > "$work_dir/samples"

  mib_s=$(awk -v s="$speed" 'BEGIN { printf "%.1f", s / 1048576 }')
  cpu_avg=$(awk -v before="$cpu_before" -v after="$cpu_after" -v elapsed="$total" \
    'BEGIN { printf "%.0f", (elapsed > 0 ? (after - before) * 100 / elapsed : 0) }')
  rss_mib=$(awk -v r="$peak_rss" 'BEGIN { printf "%.1f", r / 1024 }')
  if (( run <= warmup )); then
    echo "warmup $run: ${mib_s} MiB/s  cpu ${cpu_avg}%  peak rss ${rss_mib} MiB"
    continue
  fi
  echo "run $((run - warmup)): ${mib_s} MiB/s  cpu ${cpu_avg}%  peak rss ${rss_mib} MiB"
  results+=("$mib_s")
done

printf '%s\n' "${results[@]}" | sort -n | awk '
  { values[NR] = $1; sum += $1 }
  END {
    n = NR
    mid = int((n + 1) / 2)
    median = (n % 2 == 0) ? (values[mid] + values[mid + 1]) / 2 : values[mid]
    mean = sum / n
    for (i = 1; i <= n; i++) sq += (values[i] - mean) ^ 2
    sd = (n > 1) ? sqrt(sq / (n - 1)) : 0
    cv = (mean > 0) ? sd / mean * 100 : 0
    low = values[1]; high = values[n]
    spread = (low > 0) ? (high / low - 1) * 100 : 0
    printf "median: %.1f MiB/s\n", median
    printf "mean:   %.1f MiB/s\n", mean
    printf "stdev:  %.1f MiB/s (cv %.1f%%)\n", sd, cv
    printf "min:    %.1f MiB/s\n", low
    printf "max:    %.1f MiB/s\n", high
    printf "spread: %.1f%% (max/min - 1)\n", spread
    # Kept only so existing parsers keep working; it is not the verdict.
    printf "best:   %.1f MiB/s\n", high
    if (cv <= 5 && spread <= 10)
      print "stable: yes (cv <= 5% and spread <= 10%)"
    else
      print "stable: no (cv > 5% or spread > 10%; re-run on a quiet runner)"
  }'
