# perftest-capture-toolkit

Automated [perftest](https://github.com/linux-rdma/perftest) runs over **Soft-RoCE (RXE)** with per-test packet capture, and a **Wireshark Lua dissector** that decodes the perftest TCP control channel (default port 18515).

This toolkit was built while exploring RDMA/Soft-RoCE without dedicated hardware. It targets two common lab setups:

- Two independent Linux VMs (e.g. VMware Workstation) with `rdma_rxe` bound to the physical NIC.
- A single Linux host using a `veth` pair to simulate two endpoints (convenient for WSL2, though data-plane capture is limited — see below).

## What's inside

| Path | Purpose                                                                                                                                                                                             |
|------|---------|
| `scripts/perftest_capture.py` | Runs SEND / WRITE / READ bandwidth & latency, plus ATOMIC, in both RDMA-CM (`-R`) and explicit-GID (`-x`) modes. Captures a separate pcap per test on the server side.                              |
| `wireshark/perftest_tcp.lua` | Wireshark dissector for the perftest TCP control channel. Decodes the `KEY_PRINT_FMT*` handshake strings, the version / sys-data / MTU exchanges, and the KV negotiation payload (perftest ≥ 6.28). |
| `docs/` | Notes on the control-channel wire format, Soft-RoCE setup (two VMs, or one host with a veth pair), GID selection.                                                                                   |

## Test matrix

Each operation is run in two connection modes:

| Mode | Flag | Control channel | Capture filter |
|------|------|-----------------|----------------|
| RDMA-CM | `-R` | RDMA CM (TCP 7471) | `(udp port 4791) or (tcp port 7471)` |
| Explicit GID | `-x <idx>` | perftest socket (TCP 18515) | `(udp port 4791) or (tcp port 18515)` |

Operations covered: `ib_send_bw/lat`, `ib_write_bw/lat`, `ib_read_bw/lat`, `ib_atomic_bw/lat` — 16 runs in total, one pcap each.

## Quick start

### 1. Prepare both nodes

```bash
sudo apt install rdma-core ibverbs-utils perftest tcpdump
sudo modprobe rdma_rxe
sudo rdma link add rxe_0 type rxe netdev <your-nic>
```

Verify the link, then pick the GID index to use with `-x`:

```console
$ rdma link show rxe_0/1        # note the DEV/PORT syntax, not the bare device name
link rxe_0/1 state ACTIVE physical_state LINK_UP netdev ens33

$ ibv_devinfo -v -d rxe_0 | grep GID
    GID[  0]:   fe80::20c:29ff:feaf:254f, RoCE v2
    GID[  1]:   ::ffff:192.168.128.129, RoCE v2
```

Index 0 is the link-local address; use the index of the IPv4-mapped
`::ffff:<ip>` entry (typically 1). Details and the single-host veth variant:
[docs/soft-roce-setup.md](docs/soft-roce-setup.md).

### 2. Optional: sudo-less capture

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
```

then set `USE_SUDO_TCPDUMP = False` in `scripts/perftest_capture.py`.

### 3. Run the test matrix

```bash
pip install -r requirements.txt
export PERFTEST_SSH_PASS=<ssh-password>   # also PERFTEST_SUDO_PASS if it differs
# edit SERVER_IP / CLIENT_IP / SSH_USER / IFACE at the top of scripts/perftest_capture.py
python3 scripts/perftest_capture.py
```

Each run creates `perftest_run_<timestamp>/` with one pcap per test
(`send_bw_cm.pcap`, `send_bw_gid.pcap`, …) plus `results.csv`.
Captures are capped at `TCPDUMP_MAX_PKTS` packets per test (default 2000),
which covers the handshake and the start of the data stream without
producing hundred-MB pcaps on bandwidth tests.

### 4. Decode the capture in Wireshark

Copy `wireshark/perftest_tcp.lua` into your personal plugin directory
(*Help → About Wireshark → Folders → Personal Plugins*):

| OS | Plugin directory |
|----|------------------|
| Linux / macOS | `~/.local/lib/wireshark/plugins/` |
| Windows | `%APPDATA%\Wireshark\plugins\` |

Then restart Wireshark (or press `Ctrl+Shift+L` to reload Lua plugins).
The dissector registers on `tcp.port == 18515` and also installs a
conservative heuristic so it still fires when perftest uses a custom port
(`-p <port>`).

Useful display filters: `perftest_tcp.msg_type`, `perftest_tcp.version`,
`perftest_tcp.qpn`, `perftest_tcp.vaddr`, `perftest_tcp.gid`,
`perftest_tcp.kv.pair`.

## Output: results.csv

A single wide table; bandwidth rows fill the bandwidth columns, latency
rows fill the latency columns, and the rest stay empty.

| Column | Meaning |
|--------|---------|
| `test` | Test name + connection mode, e.g. `send_bw_cm` |
| `conn_mode` | `cm` (RDMA-CM, `-R`) or `gid` (`-x <idx>`) |
| `bytes` | Message size |
| `iterations` | Measured iterations |
| `bw_peak_MBps`, `bw_avg_MBps` | Peak / average bandwidth |
| `msg_rate_Mpps` | Message rate |
| `t_min_us`, `t_max_us`, `t_typical_us`, `t_avg_us`, `t_stdev_us` | Latency statistics |
| `p99_us`, `p999_us` | 99th / 99.9th percentile latency |

## What the dissector decodes

The perftest socket control channel (`ethernet_client/server_connect` path,
i.e. `-x <gid>` without RDMA CM) carries, in order:

| Message | Wire format |
|---------|-------------|
| Version exchange | NUL-terminated `"x.y.z"` in a fixed-size char buffer (8/16 bytes) |
| Sys-data check | Two 4-byte big-endian ints (cycle buffer, cache line size) |
| MTU exchange | 2 bytes: ASCII digit + NUL |
| Parameter negotiation | 4-byte BE version + 4-byte BE length + `name=hexbytes;…` KV string (perftest ≥ 6.28) |
| Key exchange | ASCII `KEY_PRINT_FMT*` string; exact sizes 59 / 76 / 108 / 125 bytes including the trailing NUL |
| BW report exchange | 8-byte big-endian longs / doubles |
| Close | Another round of the key handshake |

The full message reference, including the key-message token layouts
(`lid:out:qpn:psn:rkey:vaddr:gid[0..15]:srqn`), is in
[docs/control-channel-protocol.md](docs/control-channel-protocol.md).

## Limitations

- In `-R` (RDMA-CM) mode the connection is established by RDMA CM (visible
  as TCP 7471 traffic); the perftest ASCII key strings never hit a TCP
  socket, so the dissector only decodes the explicit-GID (`-x`) channel.
- The legacy fixed-struct negotiation path (remote version ≤ 6.29) is shown
  as raw bytes; its layout lives in `perftest_negotiation.h`.
- perftest < 6.28 (e.g. 6.24) performs no KV negotiation, so that message
  only appears with newer builds.
- Control messages have no framing; classification is heuristic and the
  accepted ambiguities are documented in the Lua source.
- Single-host veth captures may show GRO-aggregated frames instead of
  per-packet RoCEv2 traffic; disable offloads if you need exact packets
  (see [docs/soft-roce-setup.md](docs/soft-roce-setup.md)).

## References

- perftest source (wire format): <https://github.com/linux-rdma/perftest> —
  `perftest_communication.c`, `perftest_communication.h`, `perftest_negotiation.c`
- rdma-core / Soft-RoCE (RXE): <https://github.com/linux-rdma/rdma-core>
- Wireshark Lua API reference: <https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html>
