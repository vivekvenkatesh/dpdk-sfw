"""
test_sfw.py — TAP-based end-to-end tests for the DPDK stateful firewall.

Each test injects packets onto the appropriate kernel TAP interface using
scapy's sendp() and sniffs for forwarded packets using AsyncSniffer.

Because the DPDK app is a single long-lived process (started by conftest.py),
packet timing is fully under test control:
  - sendp() on sfw_lan → DPDK receives it on Port 1 (LAN/TAP side)
  - sendp() on sfw_nic → DPDK receives it on Port 0 (WAN/NIC side)
  - AsyncSniffer on sfw_nic → captures packets forwarded out of Port 0
  - AsyncSniffer on sfw_lan → captures packets forwarded out of Port 1

Interface ↔ DPDK port mapping (set in conftest.py):
  sfw_nic  ↔  Port 0  (WAN / NIC side)
  sfw_lan  ↔  Port 1  (LAN / Virtual TAP side)
"""

import time
import pytest
from scapy.all import Ether, IP, ICMP, sendp, AsyncSniffer

from conftest import NIC_IFACE, LAN_IFACE

# ---------------------------------------------------------------------------
# Well-known addresses used consistently across all tests
# ---------------------------------------------------------------------------
LAN_MAC = "00:11:22:33:44:55"   # host on the LAN (inside the firewall)
LAN_IP  = "192.168.1.10"

WAN_MAC = "aa:bb:cc:dd:ee:ff"   # remote internet host (outside the firewall)
WAN_IP  = "8.8.8.8"

# How long to wait for the DPDK app to forward a packet
SNIFF_TIMEOUT = 1.0   # seconds

# Unique ICMP IDs per test to prevent cross-test packet leakage
ICMP_ID_OUTBOUND            = 2001
ICMP_ID_STATEFUL            = 2002
ICMP_ID_UNSOLICITED         = 2003
ICMP_ID_LEGITIMATE_SESSION  = 2004   # Test 4: the established session
ICMP_ID_UNSOLICITED_REPLY   = 2005   # Test 4: the spoofed/unsolicited reply


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _sniff_icmp(iface: str, icmp_id: int, timeout: float = SNIFF_TIMEOUT):
    """
    Non-blocking sniff on `iface`.  Returns a list of ICMP packets
    whose id field matches `icmp_id`, captured within `timeout` seconds.

    Using lfilter (kernel-side BPF is unavailable on TAP without root
    socket opts) to avoid capturing unrelated traffic.
    """
    sniffer = AsyncSniffer(
        iface=iface,
        lfilter=lambda p: ICMP in p and p[ICMP].id == icmp_id,
        store=True,
    )
    sniffer.start()
    time.sleep(timeout)
    sniffer.stop()
    return sniffer.results or []


# ---------------------------------------------------------------------------
# Test 1 — Outbound traffic is forwarded (LAN → WAN)
# ---------------------------------------------------------------------------
def test_outbound_icmp_echo_request_allowed(dpdk_app):
    """
    An ICMP Echo Request originating from the LAN side must be forwarded
    out to the WAN side.  The firewall also inserts a CT entry for the session.

    Flow:  sendp → sfw_lan (Port 1)
                         ↓ DPDK forwards
           sniff  ← sfw_nic (Port 0)
    """
    req = (Ether(src=LAN_MAC, dst=WAN_MAC) /
           IP(src=LAN_IP, dst=WAN_IP) /
           ICMP(type=8, id=ICMP_ID_OUTBOUND, seq=1))

    # Start sniffing BEFORE injecting so we don't miss a fast forward
    sniffer = AsyncSniffer(
        iface=NIC_IFACE,
        lfilter=lambda p: ICMP in p and p[ICMP].id == ICMP_ID_OUTBOUND,
        store=True,
    )
    sniffer.start()

    sendp(req, iface=LAN_IFACE, verbose=False)
    time.sleep(SNIFF_TIMEOUT)
    sniffer.stop()

    pkts = sniffer.results or []
    assert len(pkts) >= 1, \
        "Outbound ICMP Echo Request was not forwarded from LAN to WAN"
    assert pkts[0][ICMP].type == 8, \
        "Forwarded packet has unexpected ICMP type"


# ---------------------------------------------------------------------------
# Test 2 — Stateful reply is allowed back (WAN → LAN, session established)
# ---------------------------------------------------------------------------
def test_stateful_icmp_reply_allowed(dpdk_app):
    """
    When a LAN host has sent an ICMP Echo Request (establishing a CT entry),
    the matching ICMP Echo Reply arriving on the WAN side must be forwarded
    back to the LAN.

    Flow:
      Step 1: sendp → sfw_lan  (outbound request → creates CT entry)
              wait 100 ms for DPDK lcore to process and insert CT entry
      Step 2: sendp → sfw_nic  (reply from WAN)
              sniff ← sfw_lan  (reply should be forwarded to LAN)
    """
    req = (Ether(src=LAN_MAC, dst=WAN_MAC) /
           IP(src=LAN_IP, dst=WAN_IP) /
           ICMP(type=8, id=ICMP_ID_STATEFUL, seq=1))

    reply = (Ether(src=WAN_MAC, dst=LAN_MAC) /
             IP(src=WAN_IP, dst=LAN_IP) /
             ICMP(type=0, id=ICMP_ID_STATEFUL, seq=1))

    # Step 1: establish the session
    sendp(req, iface=LAN_IFACE, verbose=False)

    # Wait for the DPDK lcore to process the outbound packet and insert the
    # CT entry.  100 ms is generous — a tight polling loop processes packets
    # within microseconds, but we allow margin for scheduling jitter.
    time.sleep(0.1)

    # Step 2: send the reply and check it arrives on the LAN side
    sniffer = AsyncSniffer(
        iface=LAN_IFACE,
        lfilter=lambda p: ICMP in p and p[ICMP].id == ICMP_ID_STATEFUL,
        store=True,
    )
    sniffer.start()

    sendp(reply, iface=NIC_IFACE, verbose=False)
    time.sleep(SNIFF_TIMEOUT)
    sniffer.stop()

    pkts = sniffer.results or []
    assert len(pkts) >= 1, \
        "ICMP reply for an established session was not forwarded to LAN"
    assert pkts[0][ICMP].type == 0, \
        "Forwarded reply packet has unexpected ICMP type"


# ---------------------------------------------------------------------------
# Test 3 — Unsolicited inbound is dropped (WAN → LAN, no CT entry)
# ---------------------------------------------------------------------------
def test_unsolicited_inbound_icmp_dropped(dpdk_app):
    """
    An ICMP Echo Request arriving from the WAN with no prior outbound session
    must be silently dropped — it must NOT reach the LAN side.

    Flow:  sendp → sfw_nic (Port 0, WAN side)
                         ↓ DPDK should DROP (no CT entry)
           sniff ← sfw_lan (Port 1) — expect empty
    """
    pkt = (Ether(src=WAN_MAC, dst=LAN_MAC) /
           IP(src=WAN_IP, dst=LAN_IP) /
           ICMP(type=8, id=ICMP_ID_UNSOLICITED, seq=1))

    sniffer = AsyncSniffer(
        iface=LAN_IFACE,
        lfilter=lambda p: ICMP in p and p[ICMP].id == ICMP_ID_UNSOLICITED,
        store=True,
    )
    sniffer.start()

    sendp(pkt, iface=NIC_IFACE, verbose=False)
    time.sleep(SNIFF_TIMEOUT)
    sniffer.stop()

    pkts = sniffer.results or []
    assert len(pkts) == 0, \
        f"Unsolicited inbound ICMP was incorrectly forwarded to LAN! " \
        f"({len(pkts)} packet(s) captured)"


# ---------------------------------------------------------------------------
# Test 4 — CT lookup is session-specific
#
# Even when a valid CT entry exists for one session, the firewall must drop
# a reply for a *different* ICMP session that was never established.
# ---------------------------------------------------------------------------
def test_unsolicited_reply_dropped_while_legitimate_session_exists(dpdk_app):
    """
    Scenario:
      1. LAN sends an ICMP Echo Request  (id=LEGITIMATE)  → CT entry created.
      2. WAN sends the matching reply    (id=LEGITIMATE)  → forwarded to LAN ✓
      3. WAN sends an unsolicited reply  (id=UNSOLICITED) → must be DROPPED  ✗

    This validates that the CT lookup is keyed on the specific session
    (ICMP id / seq), not just on the existence of *any* CT entry.
    """
    req = (Ether(src=LAN_MAC, dst=WAN_MAC) /
           IP(src=LAN_IP, dst=WAN_IP) /
           ICMP(type=8, id=ICMP_ID_LEGITIMATE_SESSION, seq=1))

    legitimate_reply = (Ether(src=WAN_MAC, dst=LAN_MAC) /
                        IP(src=WAN_IP, dst=LAN_IP) /
                        ICMP(type=0, id=ICMP_ID_LEGITIMATE_SESSION, seq=1))

    # A reply for a *different* ICMP session that was never requested
    unsolicited_reply = (Ether(src=WAN_MAC, dst=LAN_MAC) /
                         IP(src=WAN_IP, dst=LAN_IP) /
                         ICMP(type=0, id=ICMP_ID_UNSOLICITED_REPLY, seq=1))

    # --- Step 1: establish the session ---
    sendp(req, iface=LAN_IFACE, verbose=False)
    time.sleep(0.1)  # allow lcore to process and insert CT entry

    # --- Step 2: send the legitimate reply and verify it is forwarded ---
    legit_sniffer = AsyncSniffer(
        iface=LAN_IFACE,
        lfilter=lambda p: ICMP in p and p[ICMP].id == ICMP_ID_LEGITIMATE_SESSION,
        store=True,
    )
    legit_sniffer.start()
    sendp(legitimate_reply, iface=NIC_IFACE, verbose=False)
    time.sleep(SNIFF_TIMEOUT)
    legit_sniffer.stop()

    legit_pkts = legit_sniffer.results or []
    assert len(legit_pkts) >= 1, \
        "Legitimate ICMP reply for established session was not forwarded to LAN"

    # --- Step 3: send the unsolicited reply and verify it is DROPPED ---
    unsol_sniffer = AsyncSniffer(
        iface=LAN_IFACE,
        lfilter=lambda p: ICMP in p and p[ICMP].id == ICMP_ID_UNSOLICITED_REPLY,
        store=True,
    )
    unsol_sniffer.start()
    sendp(unsolicited_reply, iface=NIC_IFACE, verbose=False)
    time.sleep(SNIFF_TIMEOUT)
    unsol_sniffer.stop()

    unsol_pkts = unsol_sniffer.results or []
    assert len(unsol_pkts) == 0, \
        f"Unsolicited ICMP reply (id={ICMP_ID_UNSOLICITED_REPLY}) was " \
        f"incorrectly forwarded to LAN despite no matching CT entry! " \
        f"({len(unsol_pkts)} packet(s) captured)"
