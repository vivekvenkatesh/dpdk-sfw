"""
conftest.py — Session-level fixtures for the SFW TAP-based test suite.

How the TAP interfaces are created:
  We do NOT pre-create them with `ip tuntap add`.  DPDK's net_tap driver
  creates sfw_nic and sfw_lan itself when the app starts up via:
    --vdev net_tap0,iface=sfw_nic
    --vdev net_tap1,iface=sfw_lan
  We just need to clean up any stale interfaces from a previous crashed run
  before launching the app.

Interface ↔ DPDK port mapping:
  sfw_nic  ↔  Port 0  (WAN / external / "NIC" side)
  sfw_lan  ↔  Port 1  (LAN / internal / "Virtual TAP" side)
"""

import os
import subprocess
import time
import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SFW_BIN = os.environ.get("SFW_BIN", "./sfw")
if not os.path.exists(SFW_BIN):
    if os.path.exists("./bazel-bin/sfw"):
        SFW_BIN = "./bazel-bin/sfw"

NIC_IFACE = "sfw_nic"   # Port 0: WAN / external side
LAN_IFACE = "sfw_lan"   # Port 1: LAN / internal side

# Seconds to wait for DPDK to create the TAP interfaces and reach steady state
APP_STARTUP_WAIT = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _run_silent(cmd):
    """Run a command, ignoring errors (used for idempotent cleanup)."""
    subprocess.run(cmd, check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _iface_exists(iface):
    """Return True if a network interface with this name exists in the kernel."""
    result = subprocess.run(["ip", "link", "show", iface],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def dpdk_app():
    """
    Start the DPDK SFW application as a long-lived background process.

    DPDK's net_tap driver creates sfw_nic and sfw_lan during port init.
    We poll until both interfaces appear before yielding to the tests.
    Teardown kills the process and removes the interfaces.
    """
    # Clean up stale interfaces from a previous crashed run so DPDK can
    # create them fresh.
    for iface in [NIC_IFACE, LAN_IFACE]:
        _run_silent(["ip", "link", "set", iface, "down"])
        _run_silent(["ip", "tuntap", "del", "dev", iface, "mode", "tap"])

    cmd = [
        SFW_BIN,
        "-l", "1-3", "-n", "4",
        "--no-huge", "-m", "512", "--no-shconf", "--no-pci",
        "--vdev", f"net_tap0,iface={NIC_IFACE}",
        "--vdev", f"net_tap1,iface={LAN_IFACE}",
    ]

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    # Poll until DPDK has created both TAP interfaces (or the process exits)
    deadline = time.time() + APP_STARTUP_WAIT
    while time.time() < deadline:
        if proc.poll() is not None:
            # Process exited early — collect output and fail immediately
            _, stderr = proc.communicate()
            pytest.fail(
                f"DPDK SFW app exited during startup (rc={proc.returncode}):\n"
                f"{stderr.decode()}"
            )

        if _iface_exists(NIC_IFACE) and _iface_exists(LAN_IFACE):
            break

        time.sleep(0.2)
    else:
        proc.kill()
        _, stderr = proc.communicate()
        pytest.fail(
            f"DPDK TAP interfaces ({NIC_IFACE}, {LAN_IFACE}) did not appear "
            f"within {APP_STARTUP_WAIT}s.\n{stderr.decode()}"
        )

    # Brief additional settle time for port link-up and lcore poll loops
    time.sleep(0.5)

    yield proc

    # Teardown: stop the DPDK app
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    # Remove the TAP interfaces DPDK created
    for iface in [NIC_IFACE, LAN_IFACE]:
        _run_silent(["ip", "link", "set", iface, "down"])
        _run_silent(["ip", "tuntap", "del", "dev", iface, "mode", "tap"])
