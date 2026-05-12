#!/usr/bin/env python3
# Single source of truth for SRPerf trex-pcap-files.  Replaces the
# previously hard-coded pcaps (which baked the original CNIT/Rome
# testbed MAC addresses into the wire bytes) and the MUP-only
# build_mup_pcaps.py.
#
# Run once per testbed:
#
#   python3 pcap/build_pcaps.py --dst-mac <SUT_rcv NIC MAC>
#
# and all behaviour pcaps under pcap/trex-pcap-files/ are
# regenerated.  Defaults match the address plan in
# sut/linux/forwarding-behaviour.cfg.
#
# Behaviour list mirrors orchestrator/config_parser.py LINE_RATES;
# adding a new behaviour means (1) registering a builder here,
# (2) appending its case in forwarding-behaviour.cfg, and (3) adding
# the LINE_RATES / generate_*() entry on the orchestrator side.
import argparse
import os
import sys

from scapy.all import (
    Ether, IP, IPv6, UDP, ICMP, ICMPv6EchoRequest, Raw, wrpcap,
    IPv6ExtHdrSegmentRouting,
)

# Defaults aligned with sut/linux/forwarding-behaviour.cfg.
DEFAULT_SRC_MAC = "aa:bb:cc:00:00:01"   # tester TX
DEFAULT_DST_MAC = "aa:bb:cc:00:00:02"   # SUT_rcv NIC

# Address plan, IPv4 leg.  TG_RCV = TG_TX for single-NIC loopback
# testbeds (one VPC on Vultr): the SUT bounces its egress back over
# the same NIC, with T-Rex RX on port 0.
TG_TX_V4   = "10.10.1.1"
TG_RCV_V4  = "10.10.1.1"
PKT_V4_DST = "48.0.0.2"      # matches pkt_ipv4_dst_addr/24 in cfg

# Address plan, IPv6 leg.
TG_TX_V6   = "1:2:1::1"      # historical SRPerf "upstream user" addr
TG_RCV_V6  = "12:1::1"       # SUT_rcv-side gateway under single-NIC loopback
PKT_V6_DST = "b::2"          # matches pkt_ipv6_dst_addr in cfg

# Classic SRv6 SIDs from forwarding-behaviour.cfg.
SRV6_SID1  = "f1::"          # srv6_1st_sid
SRV6_SID2  = "f2::"          # srv6_2nd_sid

# MUP locators (RFC 9433).
MUP_V4_LOCATOR_PREFIX_BYTES = bytes([0x20, 0x01, 0x0d, 0xb8])                       # 2001:db8::/32
MUP_V6_LOCATOR_PREFIX_BYTES = bytes([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x0f, 0, 0])     # 2001:db8:f::/64
MUP_GTP4_OUTER_DST = "10.99.0.2"   # in mup_gtp4_match/24 -> triggers H.M.GTP4.D

TEID = 0x123
QFI  = 5


# ---------- common building blocks -------------------------------------------

def args_mob_session(teid=TEID, qfi=QFI):
    """5-byte Args.Mob.Session field per RFC 9433: QFI(6) + 00 + TEID(32)."""
    return bytes([(qfi << 2) & 0xff]) + teid.to_bytes(4, "big")


def gtpu_pdusession(teid=TEID, qfi=QFI, inner=b""):
    """GTP-U(long, ext PDU Session Container) header + inner payload."""
    length = 8 + len(inner)
    return (
        bytes([0x34, 0xff])
        + length.to_bytes(2, "big")
        + teid.to_bytes(4, "big")
        + bytes([0x00, 0x00, 0x00, 0x85])
        + bytes([0x01, 0x00, (qfi << 2) & 0xff, 0x00])
        + inner
    )


def sid_v4_locator(v4_dst, teid=TEID, qfi=QFI):
    v4 = bytes(map(int, v4_dst.split(".")))
    raw = MUP_V4_LOCATOR_PREFIX_BYTES + v4 + args_mob_session(teid, qfi) + bytes(3)
    return ":".join(f"{int.from_bytes(raw[i:i+2], 'big'):x}" for i in range(0, 16, 2))


def sid_v6_locator(teid=TEID, qfi=QFI):
    raw = MUP_V6_LOCATOR_PREFIX_BYTES + args_mob_session(teid, qfi) + bytes(3)
    return ":".join(f"{int.from_bytes(raw[i:i+2], 'big'):x}" for i in range(0, 16, 2))


def pad_to(pkt, length):
    raw = bytes(pkt)
    if len(raw) < length:
        return pkt / Raw(load=b"\x00" * (length - len(raw)))
    return pkt


def transport_payload():
    """UDP/5001 with 14 bytes of zero payload -- matches the original SRPerf
    pcap layout sufficiently for SUT routing decisions."""
    return UDP(sport=39892, dport=5001) / Raw(load=b"\x00" * 14)


# ---------- baseline ---------------------------------------------------------

def pkt_plain_ipv4(src_mac, dst_mac):
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=TG_TX_V4, dst=PKT_V4_DST)
        / UDP(sport=39892, dport=5001)
        / Raw(load=b"\x00" * 18)
    )


def pkt_plain_ipv6(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac) / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()


# ---------- SRv6 transit -----------------------------------------------------

def _t_payload():
    """Inner packet that the SUT-side transit behaviours wrap: plain v6 to b::2."""
    return IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()


def pkt_t_encaps_v6(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac) / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()


def pkt_t_encaps_l2(src_mac, dst_mac):
    # T.Encaps.L2 wraps any L2 frame.  We give it a plain v6/UDP packet
    # to be encapsulated -- the SUT will prepend Eth+IPv6+SRH at wire.
    return Ether(src=src_mac, dst=dst_mac) / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()


def pkt_t_insert_v6(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac) / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()


# ---------- SRv6 endpoint behaviours -----------------------------------------

def _end_family(src_mac, dst_mac, hlim=64, segleft=1):
    """Common scaffold for End / End.X / End.T: SRv6 inside which the SRH
    addresses are [SID2, SID1] (scapy ordering), outer dst = SID1, with an
    inner IPv6/UDP payload toward b::2."""
    srh = IPv6ExtHdrSegmentRouting(
        addresses=[SRV6_SID2, SRV6_SID1], segleft=segleft, lastentry=1, nh=41,
    )
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=SRV6_SID1, hlim=hlim)
        / srh
        / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()
    )


def pkt_end(src_mac, dst_mac):
    return _end_family(src_mac, dst_mac, hlim=64, segleft=1)


def pkt_end_x(src_mac, dst_mac):
    return _end_family(src_mac, dst_mac, hlim=64, segleft=1)


def pkt_end_t(src_mac, dst_mac):
    return _end_family(src_mac, dst_mac, hlim=64, segleft=1)


def pkt_end_dt6(src_mac, dst_mac):
    """End.DT6: SRH active at the End.DT6 SID (segleft=0 -- "consumed"),
    inner is an IPv6/UDP frame to be decapsulated and FIB-looked-up."""
    srh = IPv6ExtHdrSegmentRouting(
        addresses=[SRV6_SID2, SRV6_SID1], segleft=0, lastentry=1, nh=41,
    )
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=SRV6_SID2, hlim=64)
        / srh
        / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()
    )


def pkt_end_dx6(src_mac, dst_mac):
    """End.DX6: like End.DT6 but cross-connects directly to a nh."""
    srh = IPv6ExtHdrSegmentRouting(
        addresses=[SRV6_SID2, SRV6_SID1], segleft=0, lastentry=1, nh=41,
    )
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=SRV6_SID2, hlim=64)
        / srh
        / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()
    )


def pkt_end_dx2(src_mac, dst_mac):
    """End.DX2: L2VPN -- inner is a full Ethernet frame.  SRH nh=NoNextHeader
    (=59).  We give it a v6/UDP-wrapped L2 frame as payload."""
    inner_eth = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=PKT_V6_DST) / transport_payload()
    )
    srh = IPv6ExtHdrSegmentRouting(
        addresses=[SRV6_SID2, SRV6_SID1], segleft=0, lastentry=1, nh=59,
    )
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=SRV6_SID2, hlim=64)
        / srh
        / Raw(load=bytes(inner_eth))
    )


# ---------- SRv6 Mobile User Plane (RFC 9433) --------------------------------

def pkt_h_m_gtp4_d(src_mac, dst_mac):
    inner = bytes(IP(src=TG_TX_V4, dst=TG_RCV_V4) / ICMP())
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=TG_TX_V4, dst=MUP_GTP4_OUTER_DST)
        / UDP(sport=2152, dport=2152)
        / Raw(load=gtpu_pdusession(inner=inner))
    )


def pkt_end_m_gtp4_e(src_mac, dst_mac):
    sid = sid_v4_locator(TG_RCV_V4)
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=sid, nh=4)
        / IP(src=TG_TX_V4, dst=TG_RCV_V4) / ICMP()
    )


def _gtp6_packet(src_mac, dst_mac):
    inner = bytes(IPv6(src=TG_TX_V6, dst=TG_RCV_V6) / ICMPv6EchoRequest())
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst="2001:db8:f::1")
        / UDP(sport=2152, dport=2152)
        / Raw(load=gtpu_pdusession(inner=inner))
    )


def pkt_end_m_gtp6_d(src_mac, dst_mac):
    return _gtp6_packet(src_mac, dst_mac)


def pkt_end_m_gtp6_d_di(src_mac, dst_mac):
    return _gtp6_packet(src_mac, dst_mac)


def pkt_end_m_gtp6_e(src_mac, dst_mac):
    sid = sid_v6_locator()
    srh = IPv6ExtHdrSegmentRouting(
        addresses=[TG_RCV_V6, sid], segleft=1, lastentry=1, nh=58,
    )
    return (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=TG_TX_V6, dst=sid)
        / srh
        / ICMPv6EchoRequest()
    )


# ---------- registry ---------------------------------------------------------

BUILDERS = {
    "plain-ipv4":            pkt_plain_ipv4,
    "plain-ipv6":            pkt_plain_ipv6,
    "srv6-t_encaps_v6":      pkt_t_encaps_v6,
    "srv6-t_encaps_l2":      pkt_t_encaps_l2,
    "srv6-t_insert_v6":      pkt_t_insert_v6,
    "srv6-end":              pkt_end,
    "srv6-end_x":            pkt_end_x,
    "srv6-end_t":            pkt_end_t,
    "srv6-end_dt6":          pkt_end_dt6,
    "srv6-end_dx6":          pkt_end_dx6,
    "srv6-end_dx2":          pkt_end_dx2,
    # SRv6 Mobile User Plane (RFC 9433)
    "srv6-h_m_gtp4_d":       pkt_h_m_gtp4_d,
    "srv6-end_m_gtp4_e":     pkt_end_m_gtp4_e,
    "srv6-end_m_gtp6_d":     pkt_end_m_gtp6_d,
    "srv6-end_m_gtp6_d_di":  pkt_end_m_gtp6_d_di,
    "srv6-end_m_gtp6_e":     pkt_end_m_gtp6_e,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-mac", default=DEFAULT_SRC_MAC,
                    help=f"tester TX MAC (default {DEFAULT_SRC_MAC})")
    ap.add_argument("--dst-mac", default=DEFAULT_DST_MAC,
                    help=f"SUT_rcv MAC (default {DEFAULT_DST_MAC})")
    ap.add_argument("--out-dir", default=os.path.join(os.path.dirname(__file__),
                                                      "trex-pcap-files"))
    ap.add_argument("--size", type=int, default=64,
                    help="filename size tag (default 64)")
    ap.add_argument("--only", default=None,
                    help="generate only the named pcap (e.g. srv6-end_m_gtp4_e)")
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
