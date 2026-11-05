#!/usr/bin/env python3
"""
perftest_capture.py

Run the full perftest bandwidth/latency matrix over Soft-RoCE (rdma_rxe)
between two Linux hosts, capturing one pcap per test on the server side.

Test matrix: SEND / WRITE / READ / ATOMIC, bandwidth and latency, each in
two connection modes:
  - RDMA-CM      (-R)       control channel: RDMA CM (TCP 7471)
  - explicit GID (-x <idx>) control channel: perftest socket (TCP 18515)

Dependencies: pip install paramiko

Usage:
    export PERFTEST_SSH_PASS=xxx        # or enter it when prompted
    python3 perftest_capture.py

For sudo-less packet capture, run once on both hosts:
    sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
and then set USE_SUDO_TCPDUMP = False below.
"""

import csv
import getpass
import os
import time
from datetime import datetime

import paramiko

# ------------------------------ configuration ------------------------------
SERVER_IP = "192.168.128.128"
CLIENT_IP = "192.168.128.129"
SSH_USER = "username"
SSH_PASS = os.environ.get("PERFTEST_SSH_PASS") or getpass.getpass("SSH password: ")
SUDO_PASS = os.environ.get("PERFTEST_SUDO_PASS", SSH_PASS)

IFACE = "ens33"         # NIC that rdma_rxe is bound to
RDMA_DEV = "rxe_0"
RDMA_PORT = 1           # rdma links are referenced as DEV/PORT, e.g. rxe_0/1
GID_IDX = 1             # GID index verified to work; see docs/soft-roce-setup.md
CAPTURE_DIR = f"/home/{SSH_USER}/perftest_captures"

USE_SUDO_TCPDUMP = True  # set False after granting tcpdump cap_net_raw via setcap
BW_ITERS = "-n 2000"     # bandwidth iterations; "-D 5" (timed run) also works
TCPDUMP_MAX_PKTS = 2000  # tcpdump -c: cap packets per test to keep pcaps small
RUN_DIR = os.path.join(
    os.getcwd(), "perftest_run_" + datetime.now().strftime("%Y%m%d_%H%M%S")
)

IB_TOOLS = r"ib_(send|write|read|atomic)_(bw|lat)"

# (name, tool, extra args, connection mode)
tests = [
    ("send_bw",    "ib_send_bw",    BW_ITERS,                   "cm"),
    ("send_bw",    "ib_send_bw",    BW_ITERS,                   "gid"),
    ("send_lat",   "ib_send_lat",   "",                         "cm"),
    ("send_lat",   "ib_send_lat",   "",                         "gid"),
    ("write_bw",   "ib_write_bw",   BW_ITERS,                   "cm"),
    ("write_bw",   "ib_write_bw",   BW_ITERS,                   "gid"),
    ("write_lat",  "ib_write_lat",  "",                         "cm"),
    ("write_lat",  "ib_write_lat",  "",                         "gid"),
    ("read_bw",    "ib_read_bw",    BW_ITERS,                   "cm"),
    ("read_bw",    "ib_read_bw",    BW_ITERS,                   "gid"),
    ("read_lat",   "ib_read_lat",   "",                         "cm"),
    ("read_lat",   "ib_read_lat",   "",                         "gid"),
    ("atomic_bw",  "ib_atomic_bw",  f"{BW_ITERS} -A FETCH_AND_ADD", "cm"),
    ("atomic_bw",  "ib_atomic_bw",  f"{BW_ITERS} -A FETCH_AND_ADD", "gid"),
    ("atomic_lat", "ib_atomic_lat", "-A CMP_AND_SWAP",          "cm"),
    ("atomic_lat", "ib_atomic_lat", "-A CMP_AND_SWAP",          "gid"),
]


# ------------------------------ ssh helpers --------------------------------
def ssh_connect(ip):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ip, username=SSH_USER, password=SSH_PASS, timeout=10)
    return c


def run_cmd(client, cmd, timeout=60):
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    rc = stdout.channel.recv_exit_status()
    return rc, stdout.read().decode(errors="ignore"), stderr.read().decode(errors="ignore")


def sudo_prefix():
    return f"echo '{SUDO_PASS}' | sudo -S -p '' " if USE_SUDO_TCPDUMP else ""


# ------------------------------ preflight ----------------------------------
def preflight(name, client, peer_ip):
    """Fail-fast environment checks; return an error message on any failure."""
    checks = [
        # An rdma link is referenced as DEV/PORT (e.g. rxe_0/1), not the
        # bare device name.
        (f"rdma link show {RDMA_DEV}/{RDMA_PORT} | grep -q 'state ACTIVE'",
         f"{RDMA_DEV}/{RDMA_PORT} missing or not ACTIVE"),
        ("command -v ib_send_bw > /dev/null", "perftest not installed"),
        (f"ping -c1 -W2 {peer_ip} > /dev/null", f"no route to {peer_ip}"),
    ]
    if name == "server":
        # `ibv_devinfo -v` prints "GID[  1]:\t::ffff:192.168.128.129, RoCE v2":
        # the index sits inside the brackets with padding, and the all-zero
        # GID must be ruled out.
        checks.append(
            (f"ibv_devinfo -v -d {RDMA_DEV} | "
             f"grep -E 'GID\\[\\s*{GID_IDX}\\]:' | grep -qvE ':\\s*::\\s*(,|$)'",
             f"GID index {GID_IDX} missing or all-zero"))
    for cmd, errmsg in checks:
        rc, _, _ = run_cmd(client, cmd)
        if rc != 0:
            return f"[{name}] preflight failed: {errmsg}"
    return None


def cleanup_leftovers(client):
    run_cmd(client, f"pkill -f '{IB_TOOLS}' 2>/dev/null; true")


# ------------------------------ capture ------------------------------------
def start_tcpdump(client, pcap_path, filter_expr):
    run_cmd(client, f"mkdir -p {CAPTURE_DIR}")
    run_cmd(client, f"{sudo_prefix()}rm -f {pcap_path} {pcap_path}.err")
    # nohup must wrap tcpdump itself (i.e. sit after sudo): putting it at the
    # left end of a pipeline (nohup echo | sudo ...) only protects echo.
    # setsid detaches tcpdump from the SSH session so it is not killed by
    # SIGHUP when the exec channel closes.
    # -c caps the packet count: full captures of bw tests can reach hundreds
    # of MB, and the handshake happens before the data phase, so the first N
    # packets cover the connection setup plus the start of the data stream.
    # tcpdump exits by itself once the count is reached; the pkill in
    # stop_tcpdump is idempotent in that case.
    cmd = (f"{sudo_prefix()}setsid nohup tcpdump -i {IFACE} -s 0 -c {TCPDUMP_MAX_PKTS} "
           f"-w {pcap_path} '{filter_expr}' > /dev/null 2> {pcap_path}.err &")
    client.exec_command(cmd)
    # Readiness == process alive. Do not probe the pcap size with test -s:
    # libpcap buffers the file header, so the file may stay 0 bytes for a
    # long time under low traffic and trigger a false negative.
    for _ in range(20):
        _, out, _ = run_cmd(client, "pgrep -x tcpdump > /dev/null; echo $?")
        if out.strip() == "0":
            return True
        time.sleep(0.5)
    _, log, _ = run_cmd(client, f"cat {pcap_path}.err 2>/dev/null")
    if log.strip():
        print(f"tcpdump stderr:\n{log}")
    return False


def stop_tcpdump(client):
    run_cmd(client, f"{sudo_prefix()}pkill -INT tcpdump; true")
    for _ in range(20):
        _, out, _ = run_cmd(client, "pgrep -x tcpdump > /dev/null; echo $?")
        if out.strip() != "0":
            return
        time.sleep(0.5)


# --------------------------- report parsing --------------------------------
def parse_report(out):
    """Extract the perftest report header line and the first data line."""
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("#bytes"):
            for data in lines[i + 1:]:
                if data.strip() and data.strip()[0].isdigit():
                    return line.strip(), data.strip()
    return None, None


# perftest report columns (fixed layout in 6.24). Header fields such as
# "BW peak[MB/sec]" contain spaces, so they cannot be aligned with the data
# columns by whitespace splitting; use fixed field names instead of parsing
# the "#bytes ..." header line.
BW_FIELDS = ["bytes", "iterations", "bw_peak_MBps", "bw_avg_MBps", "msg_rate_Mpps"]
LAT_FIELDS = ["bytes", "iterations", "t_min_us", "t_max_us", "t_typical_us",
              "t_avg_us", "t_stdev_us", "p99_us", "p999_us"]
# Single wide table: bw and lat share bytes/iterations; the remaining metric
# columns do not overlap, so unused ones stay empty.
CSV_FIELDS = ["test", "conn_mode"] + BW_FIELDS + LAT_FIELDS[2:]

# ------------------------------ main flow ----------------------------------
os.makedirs(RUN_DIR, exist_ok=True)
server = ssh_connect(SERVER_IP)
client = ssh_connect(CLIENT_IP)

for name, c, peer in (("server", server, CLIENT_IP), ("client", client, SERVER_IP)):
    err = preflight(name, c, peer)
    if err:
        raise SystemExit(err)

results = []
csv_rows = []

for name, tool, extra, mode in tests:
    pcap_base = f"{name}_{mode}"
    remote_pcap = f"{CAPTURE_DIR}/{pcap_base}.pcap"
    local_pcap = os.path.join(RUN_DIR, f"{pcap_base}.pcap")
    srv_log = f"/tmp/{pcap_base}_srv.log"

    if mode == "cm":
        conn_args = "-R"
        filter_expr = "(udp port 4791) or (tcp port 7471)"
    else:
        conn_args = f"-x {GID_IDX}"
        filter_expr = "(udp port 4791) or (tcp port 18515)"

    print(f"\n===== {pcap_base}: {tool} {extra} {conn_args} =====")
    status = "OK"

    # 0. kill perftest processes left over from a previous run
    cleanup_leftovers(server)
    cleanup_leftovers(client)

    # 1. start the capture
    if not start_tcpdump(server, remote_pcap, filter_expr):
        results.append((pcap_base, "FAIL: tcpdump did not start"))
        continue

    # 2. start the server in the background and wait until it is up
    run_cmd(server, f"nohup {tool} -d {RDMA_DEV} -i {RDMA_PORT} {conn_args} -F {extra} "
                    f"> {srv_log} 2>&1 &")
    _, out, _ = run_cmd(server, f"pgrep -f '^{tool} ' > /dev/null; echo $?")
    ready = out.strip() == "0"
    time.sleep(1)  # give listen() a moment after the process appears

    if not ready:
        _, log, _ = run_cmd(server, f"cat {srv_log}")
        print(f"server failed to start:\n{log}")
        stop_tcpdump(server)
        results.append((pcap_base, "FAIL: server failed to start"))
        continue

    # 3. run the client in the foreground and read its stdout directly
    cli_cmd = f"{tool} -d {RDMA_DEV} -i {RDMA_PORT} {conn_args} -F {extra} {SERVER_IP}"
    rc, out, err = run_cmd(client, cli_cmd, timeout=180)
    if rc != 0:
        status = f"FAIL: client rc={rc}"
        print(out + err)
        # on failure, pull the server log for inspection
        _, slog, _ = run_cmd(server, f"cat {srv_log}")
        with open(os.path.join(RUN_DIR, f"{pcap_base}_srv.log"), "w") as f:
            f.write(slog)
    else:
        header, data_line = parse_report(out)
        if data_line:
            print(data_line)
            fields = BW_FIELDS if "_bw" in tool else LAT_FIELDS
            values = data_line.split()
            if len(values) != len(fields):
                print(f"warning: {pcap_base} report has {len(values)} columns, "
                      f"expected {len(fields)}; raw values: {values}")
            row = dict(zip(fields, values))
            row.update(test=pcap_base, conn_mode=mode)
            csv_rows.append(row)
        else:
            status = "FAIL: could not parse test report"

    # 4. stop the capture and verify the pcap is non-empty
    stop_tcpdump(server)
    rc, out, _ = run_cmd(server, f"stat -c%s {remote_pcap} 2>/dev/null || echo 0")
    if int(out.strip() or 0) <= 24:
        status = "FAIL: empty pcap (capture filter may not match the traffic)"
    else:
        sftp = server.open_sftp()
        try:
            sftp.get(remote_pcap, local_pcap)
            print(f"saved: {local_pcap}")
        finally:
            sftp.close()
        run_cmd(server, f"rm -f {remote_pcap}")

    results.append((pcap_base, status))

server.close()
client.close()

if csv_rows:
    with open(os.path.join(RUN_DIR, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(csv_rows)

print("\n===== Summary =====")
for r in results:
    print(f"{r[0]:<20} {r[1]}")
failed = [r for r in results if r[1] != "OK"]
print(f"\n{len(results)} tests, {len(failed)} failed, output dir: {RUN_DIR}")
