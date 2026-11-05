# The perftest TCP control channel

When perftest runs **without** RDMA CM (the `ethernet_client_connect` /
`ethernet_server_connect` path, i.e. explicit GID via `-x <idx>`), the two
sides exchange QP information over a plain TCP socket — default port
**18515**, override with `-p`. This document describes what is on the wire,
in the order the messages appear, as implemented in
`perftest_communication.c` / `perftest_communication.h` /
`perftest_negotiation.c` of [perftest](https://github.com/linux-rdma/perftest).

> With `-R` (RDMA CM), none of this exists on a TCP socket: connection
> establishment is carried by RDMA CM (visible as TCP 7471 traffic) and the
> keys travel inside CM private data / RDMA SENDs. The Lua dissector
> therefore only decodes the explicit-GID channel.

## Message sequence

### 1. Version exchange — `exchange_versions()`

Each side sends its version string (e.g. `"6.24"`, `"25.07.0"`) in a
**fixed-size char buffer** (`sizeof(rem_version)`), NUL-terminated and
zero-padded. The buffer size varies between builds (observed 8 and 16
bytes), which is why the dissector consumes padding only up to the next
plausible boundary (8/16/32).

```
36 2e 32 34 00 00 00 00 00 00 00 00 00 00 00 00   "6.24\0..........."
```

### 2. Sys-data check — `check_sys_data()`

Two 4-byte big-endian integers: `cycle_buffer` size and `cache_line_size`.
A mismatch only produces a warning.

### 3. MTU exchange — `check_mtu()`

Two bytes: one ASCII digit (`'1'`–`'5'`, the `ibv_mtu` enum) plus NUL —
`sizeof(char[2])`. Example: `33 00` = `"3\0"` = enum 3 = 1024-byte MTU.

### 4. Parameter negotiation — `negotiate_params()`

- perftest **≥ 6.28**: 4-byte BE negotiation version, then a 4-byte BE
  length followed by a KV string `"name=hexbytes;name=hexbytes;…"`, sent in
  chunks of ≤ 2048 bytes. Each value is the raw field bytes (network byte
  order) hex-encoded. Enum-like fields (`connection_type`, `verb`, `tst`,
  `test_method`, `atomicType`, `test_type`, `report_fmt`) and booleans are
  decoded to symbolic names by the dissector.
- perftest **< 6.28** (e.g. 6.24): the function returns immediately — no KV
  negotiation appears on the wire at all.
- The legacy path (remote version ≤ 6.29) exchanges a fixed binary struct
  whose layout lives in `perftest_negotiation.h`; the dissector shows it as
  raw bytes.

### 5. Key exchange — `ctx_hand_shake()`

An ASCII, colon-separated, NUL-terminated string built with one of the
`KEY_PRINT_FMT*` format strings. The wire sizes are **exact** (including
the trailing NUL), which makes them reliable classifiers:

| Size | Format | Token layout |
|------|--------|--------------|
| 59  | `KEY_PRINT_FMT`        | `lid:out:qpn:psn:rkey:vaddr:srqn` (7 tokens) |
| 76  | `KEY_PRINT_FMT_DV`     | + `tail_markers_vaddr` after `vaddr` (8 tokens) |
| 108 | `KEY_PRINT_FMT_GID`    | `lid:out:qpn:psn:rkey:vaddr:gid[0..15]:srqn` (23 tokens) |
| 125 | `KEY_PRINT_FMT_GID_DV` | + `tail_markers_vaddr` before the GID (24 tokens) |

All values are hex. The GID variant carries 16 one-byte hex tokens — the
raw 128-bit GID — and appears whenever `-x` (GID index) or `-R` decides a
GID is needed. `_DV` variants appear with data validation (`-D` conflicts
with the duration flag name; it is the check-data option in perftest).

`vaddr` (and `tail_markers_vaddr`) are 64-bit host pointers as text —
e.g. `55e1c2a00010` — which exceed 2^53. The dissector converts them with
`UInt64.new(hi, lo)` instead of Lua numbers to avoid precision loss.

### 6. Bandwidth report exchange — `xchg_bw_reports()`

After a bw run, each side sends its results as 8-byte big-endian longs /
doubles so both ends can print the same table.

### 7. Close — `ctx_close_connection()`

Another round of the key handshake, then the socket closes.

## Why the dissector is heuristic

The channel has **no framing**: message boundaries must be inferred from
content. Additionally, perftest issues several small writes back to back,
so TCP (Nagle) frequently **coalesces** two or more messages into one
segment — the dissector iterates over a segment and requests desegmentation
when a message straddles a boundary.

Accepted ambiguities (documented in the Lua source):

- A standalone 8-byte binary blob is reported as "report u64/double"; a
  coalesced pair of 4-byte control values in one 8-byte packet is
  indistinguishable without conversation state.
- A lone 4-byte BE value is labeled generically
  (`version / sys-data / length prefix`) for the same reason.

Both could be eliminated by tracking per-direction conversation state
(expected message sequence); patches welcome.

## Wireshark Lua gotcha discovered while developing this

`TvbRange:string()` is backed by `tvb_get_string_enc()`, a **NUL-terminated
C string**: on some builds (observed on Wireshark 4.6.2) it truncates at
the first embedded zero byte. The version message (`"6.24"` + zero padding)
parsed as `msg_type` matched but the `version` field never matched because
the NUL find operated on a truncated Lua string. Fix: use
`TvbRange:raw()` (backed by `lua_pushlstring`, full bytes) everywhere in
this dissector.
