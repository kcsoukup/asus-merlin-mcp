"""
Input validation and normalization utilities.

Pure functions with no external dependencies.
"""

from config.constants import MAC_ADDRESS_PATTERN, IPV4_ADDRESS_PATTERN
from core.ssh_client import RouterSSHClient


def is_valid_mac(mac: str) -> bool:
    """
    Validate MAC address format.

    Args:
        mac: MAC address string to validate

    Returns:
        True if valid MAC address format, False otherwise

    Examples:
        >>> is_valid_mac("AA:BB:CC:DD:EE:FF")
        True
        >>> is_valid_mac("invalid")
        False
    """
    return bool(MAC_ADDRESS_PATTERN.match(mac))


def is_valid_ip(ip: str) -> bool:
    """
    Validate IPv4 address format.

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv4 address format, False otherwise

    Examples:
        >>> is_valid_ip("192.168.1.1")
        True
        >>> is_valid_ip("999.999.999.999")
        False
    """
    return bool(IPV4_ADDRESS_PATTERN.match(ip))


def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to consistent uppercase, colon-separated format.

    Args:
        mac: MAC address in any common format

    Returns:
        Normalized MAC address (uppercase with colons)

    Examples:
        >>> normalize_mac("aa:bb:cc:dd:ee:ff")
        'AA:BB:CC:DD:EE:FF'
        >>> normalize_mac("aa-bb-cc-dd-ee-ff")
        'AA:BB:CC:DD:EE:FF'
    """
    # Remove common separators and convert to uppercase
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    # Add colons every 2 characters
    return ":".join(mac_clean[i : i + 2] for i in range(0, 12, 2))


def is_merlin_firmware(router: RouterSSHClient) -> bool:
    """
    Detect if router is running Asuswrt-Merlin firmware.

    Checks the uname output for "ASUSWRT-Merlin" string which is present
    in all Merlin firmware builds.

    Args:
        router: RouterSSHClient instance for executing commands

    Returns:
        True if Merlin firmware detected, False otherwise

    Examples:
        >>> is_merlin_firmware(router)  # On Merlin firmware
        True
        >>> is_merlin_firmware(router)  # On stock ASUS firmware
        False
    """
    output, _, code = router.execute_command("uname -a")
    if code != 0:
        return False
    return "ASUSWRT-Merlin" in output
