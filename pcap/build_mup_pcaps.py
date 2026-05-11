#!/usr/bin/env python3
# Build SRv6 Mobile User Plane (RFC 9433) pcap templates for SRPerf.
#
# Output filenames follow the existing SRPerf convention
#   {type}-{experiment}-{size}.pcap   under trex-pcap-files/
# e.g. srv6-h_m_gtp4_d-64.pcap.
#
# The L2 destination MAC must match the SUT_rcv NIC in the testbed.
# Adjust DST_MAC below (or use --dst-mac at run time) before deploying.
# Source MAC and frame padding are placeholders -- T-Rex replays the
# raw bytes verbatim.
#
# Address plan mirrors sut/linux/forwarding-behaviour.cfg:
#   SUT_rcv         12:1::2 / 10.10.1.2
#   SUT_snd         12:2::2 / 10.10.2.2
#   TG_tx (TG -> SUT_rcv)   12:1::1 / 10.10.1.1
#   TG_rcv (SUT_snd -> TG)  12:2::1 / 10.10.2.1
#   mup_v4_locator  2001:db8::/32
#   mup_v6_locator  2001:db8:f::/64
#   mup_gtp4_match  10.99.0.0/24
import argparse
import os
import sys

from scapy.all import (
    Ether, IP, IPv6, UDP, ICMP, ICMPv6EchoRequest, Raw, wrpcap,
    IPv6ExtHdrSegmentRouting,
)

DEFAULT_SRC_MAC = "aa:bb:cc:00:00:01"
DEFAULT_DST_MAC = "aa:bb:cc:00:00:02"
TG_TX_V4   = "10.10.1.1"   # TG egress, hits SUT_rcv on the wire
TG_RCV_V4  = "10.10.2.1"   # TG side that receives SUT-forwarded packets
TG_TX_V6   = "12:1::1"
TG_RCV_V6  = "12:2::1"

# Outer IPv4 dst used by H.M.GTP4.D ingress: anywhere in
# mup_gtp4_match/24.  Pick .2 to match scripts/perf in the harness repo.
H_M_GTP4_D_OUTER_V4_DST = "10.99.0.2"

# QFI=5, TEID=0x123 (same as kernel selftests / scripts/perf).
TEID = 0x123
QFI  = 5

# Frame pad target: SRPerf uses min=64B and max=1300B.  We size to 64B
# Ethernet (post-FCS), padding with zeros where the payload would not
# otherwise reach.  scapy emits exact bytes; wrpcap stores them as-is.
MIN_FRAME = 64


def pad_to(pkt, length):
    raw = bytes(pkt)
    if len(raw) < length:
        return pkt / Raw(load=b"\x00" * (length - len(raw)))
    return pkt


def gtpu_pdusession(teid=TEID, qfi=QFI, inner=b""):
    length = 8 + len(inner)
    return (
        bytes([0x34, 0xff])
        + length.to_bytes(2, "big")
        + teid.to_bytes(4, "big")
        + bytes([0x00, 0x00, 0x00, 0x85])
        + bytes([0x01, 0x00, (qfi << 2) & 0xff, 0x00])
        + inner
    )


def pkt_h_m_gtp4_d(src_mac, dst_mac):
    inner = bytes(IP(src=TG_TX_V4, dst=TG_RCV_V4) / ICMP())
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=TG_TX_V4, dst=H_M_GTP4_D_OUTER_V4_DST)
        / UDP(sport=2152, dport=2152)
        / Raw(gtpu_pdusession(inner=inner))
    )


def _sid_v4_locator(v4_dst, teid=TEID, qfi=QFI):
    # locator 2001:db8::/32 (bytes 0..3) + v4 dst (bytes 4..7)
    #  + Args.Mob.Session (5 bytes: QFI<<2 then 4-byte TEID big-endian)
    #  + 3 bytes zero pad.
    locator = bytes([0x20, 0x01, 0x0d, 0xb8])
    v4 = bytes(map(int, v4_dst.split(".")))
    args = bytes([(qfi << 2) & 0xff]) + teid.to_bytes(4, "big")
    raw = locator + v4 + args + bytes(3)
    return ":".join(f"{int.from_bytes(raw[i:i+2],'big'):x}" for i in range(0, 16, 2))


def pkt_end_m_gtp4_e(src_mac, dst_mac):
    sid = _sid_v4_locator(TG_RCV_V4)
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=sid, nh=4)
        / IP(src=TG_TX_V4, dst=TG_RCV_V4)
        / ICMP()
    )


def pkt_end_m_gtp6_d(src_mac, dst_mac):
    inner = bytes(IPv6(src=TG_TX_V6, dst=TG_RCV_V6) / ICMPv6EchoRequest())
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst="2001:db8:f::1")
        / UDP(sport=2152, dport=2152)
        / Raw(gtpu_pdusession(inner=inner))
    )


def pkt_end_m_gtp6_d_di(src_mac, dst_mac):
    inner = bytes(IPv6(src=TG_TX_V6, dst=TG_RCV_V6) / ICMPv6EchoRequest())
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst="2001:db8:f::1")
        / UDP(sport=2152, dport=2152)
        / Raw(gtpu_pdusession(inner=inner))
    )


def _sid_v6_locator(teid=TEID, qfi=QFI):
    # locator 2001:db8:f::/64 (bytes 0..7) + Args.Mob.Session (bytes 8..12)
    # + 3 bytes zero pad.
    locator = bytes([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0f, 0x00, 0x00])
    args = bytes([(qfi << 2) & 0xff]) + teid.to_bytes(4, "big")
    raw = locator + args + bytes(3)
    return ":".join(f"{int.from_bytes(raw[i:i+2],'big'):x}" for i in range(0, 16, 2))


def pkt_end_m_gtp6_e(src_mac, dst_mac):
    sid = _sid_v6_locator()
    srh = IPv6ExtHdrSegmentRouting(
        addresses=[TG_RCV_V6, sid], segleft=1, lastentry=1, nh=58,
    )
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=sid)
        / srh
        / ICMPv6EchoRequest()
    )


def pkt_plain_ipv4(src_mac, dst_mac):
    # Tester sends min-size IPv4 to TG_RCV_V4; SUT plain-forwards it back.
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=TG_TX_V4, dst=TG_RCV_V4)
        / UDP(sport=1000, dport=5001)
        / Raw(load=b"\x00" * 18)
    )


BUILDERS = {
    "plain-ipv4":            pkt_plain_ipv4,
    "srv6-h_m_gtp4_d":       pkt_h_m_gtp4_d,
    "srv6-end_m_gtp4_e":     pkt_end_m_gtp4_e,
    "srv6-end_m_gtp6_d":     pkt_end_m_gtp6_d,
    "srv6-end_m_gtp6_d_di":  pkt_end_m_gtp6_d_di,
    "srv6-end_m_gtp6_e":     pkt_end_m_gtp6_e,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-mac", default=DEFAULT_SRC_MAC)
    ap.add_argument("--dst-mac", default=DEFAULT_DST_MAC)
    ap.add_argument("--out-dir", default=os.path.join(os.path.dirname(__file__),
                                                      "trex-pcap-files"))
    ap.add_argument("--size", type=int, default=64,
                    help="frame size in bytes (default 64)")
    ap.add_argument("--only", default=None,
                    help="generate only the named pcap (e.g. srv6-h_m_gtp4_d)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    for name, builder in BUILDERS.items():
        if args.only and args.only != name:
            continue
        pkt = pad_to(builder(args.src_mac, args.dst_mac), args.size)
        out = os.path.join(args.out_dir, f"{name}-{args.size}.pcap")
        wrpcap(out, [pkt])
        print(f"wrote {out}: {len(bytes(pkt))} bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
