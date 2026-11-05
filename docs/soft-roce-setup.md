# Soft-RoCE (RXE) lab setup

RXE (`rdma_rxe`) is a software RDMA transport that implements RoCEv2 on top
of any Ethernet NIC. It needs no RDMA hardware, which makes it the standard
way to learn verbs programming and perftest on plain VMs.

## Two VMs (VMware Workstation, VirtualBox, KVM, …)

Give both VMs a NIC on the same virtual network (host-only or NAT both
work), e.g. `192.168.128.128` (server) and `192.168.128.129` (client),
interface `ens33`. On **both** VMs:

```bash
sudo apt install rdma-core ibverbs-utils perftest tcpdump
sudo modprobe rdma_rxe
sudo rdma link add rxe_0 type rxe netdev ens33
```

Verify:

```console
$ rdma link show rxe_0/1        # DEV/PORT syntax — "rxe_0" alone is rejected
link rxe_0/1 state ACTIVE physical_state LINK_UP netdev ens33

$ ibv_devinfo -v -d rxe_0 | grep GID
    GID[  0]:   fe80::20c:29ff:feaf:254f, RoCE v2
    GID[  1]:   ::ffff:192.168.128.129, RoCE v2
```

### Picking the GID index for `-x`

- `GID[0]` is the IPv6 link-local address (`fe80::…`). It only works for
  same-subnet IPv6-style addressing and is usually **not** what you want.
- `GID[1]` is the IPv4-mapped address (`::ffff:<ipv4>`), RoCE v2. This is
  the index to pass to perftest: `-x 1`.

RXE links are **not persistent across reboots**. To restore them:

```bash
echo rdma_rxe | sudo tee -a /etc/modules
sudo rdma link add rxe_0 type rxe netdev ens33   # re-add after every boot
```

(or wrap the `rdma link add` in a systemd unit / rc.local).

### Smoke test

```bash
# server (192.168.128.128)
ib_send_bw -d rxe_0 -x 1 -F

# client (192.168.128.129)
ib_send_bw -d rxe_0 -x 1 -F 192.168.128.128
```

Replace `-x 1` with `-R` to exercise the RDMA-CM path instead.

## Single host with a veth pair (also the WSL2 option)

One machine can simulate both endpoints. RXE devices bound to the two ends
of a veth pair talk to each other through the kernel:

```bash
sudo modprobe rdma_rxe
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 192.168.100.1/24 dev veth0
sudo ip addr add 192.168.100.2/24 dev veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo rdma link add rxe_0 type rxe netdev veth0
sudo rdma link add rxe_1 type rxe netdev veth1
```

Server on `rxe_0` (192.168.100.1), client on `rxe_1` (192.168.100.2):

```bash
ib_send_bw -d rxe_0 -x 1 -F &
ib_send_bw -d rxe_1 -x 1 -F 192.168.100.1
```

Caveats:

- **WSL2**: the stock WSL2 kernel does not ship `rdma_rxe`; you need a
  custom WSL2 kernel built with `CONFIG_RDMA_RXE=m`. Everything else works
  the same.
- **Capture fidelity**: on a single host the traffic never hits a wire, and
  GRO/TSO can hand tcpdump large aggregated frames instead of the original
  per-packet RoCEv2 stream. If you need exact packets, disable offloads:

  ```bash
  sudo ethtool -K veth0 gro off tso off
  sudo ethtool -K veth1 gro off tso off
  ```

- **Timing**: latency numbers on veth/loopback-style paths are not
  comparable to a two-host setup — scheduling on one CPU skews
  `ib_*_lat` results. Use this topology for functional testing and protocol
  analysis, not for benchmarking.

## VMware-specific notes

- NAT and host-only networks both work; the VMs just need L2 reachability.
  There is no lossless-Ethernet requirement — RXE does not need PFC.
- Promiscuous-mode capture works out of the box on the VM's own NIC, since
  the traffic of interest is addressed to the VM itself.
- If `rdma link add` fails with `RTNETLINK answers: File exists`, a stale
  rxe link survived; remove it with `sudo rdma link del rxe_0` and re-add.
