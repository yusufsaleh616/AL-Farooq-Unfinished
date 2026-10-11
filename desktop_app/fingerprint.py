"""Builds the device fingerprint: UUID, MAC address and Windows serial number (WSN),
joined together and hashed with SHA-256 on this PC. The raw values never leave
the machine, only the hash does.

Heads up: these values can be faked, so the fingerprint is only a helper. The
real proof of "this is the approved PC" is the private key in device_key.py.
"""
import hashlib
import platform
import subprocess
import uuid


def _powershell(command: str) -> str:
    out = subprocess.check_output(["powershell", "-NoProfile", "-Command", command],
                                  text=True, timeout=15)
    return out.strip()


def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def _real_mac() -> str:
    """The MAC address, or "" if this PC does not expose one.

    When Python can't find a MAC it makes up a random one on every run and sets
    the multicast bit (bit 40) to mark it as fake. A random value would change
    the fingerprint each time and lock the admin out, so we skip it.
    """
    node = uuid.getnode()
    if (node >> 40) & 1:
        return ""
    return f"{node:012x}"


def raw_parts() -> tuple[str, str, str]:
    """Returns (uuid, mac, serial)."""
    mac = _real_mac()
    system = platform.system()
    if system == "Windows":
        hw_uuid = _powershell("(Get-CimInstance Win32_ComputerSystemProduct).UUID")
        serial = _powershell("(Get-CimInstance Win32_BIOS).SerialNumber")   # the WSN
    elif system == "Linux":
        # handy for testing on a Linux box, the serial is often not readable
        hw_uuid = _read("/etc/machine-id")
        serial = _read("/sys/class/dmi/id/product_serial")
    else:
        hw_uuid, serial = "", ""
    return hw_uuid, mac, serial


def fingerprint_hash() -> str:
    parts = raw_parts()
    if not any(parts):
        # hashing three empty strings would give every PC the same fingerprint
        raise RuntimeError("Could not read any hardware identifier on this PC")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
