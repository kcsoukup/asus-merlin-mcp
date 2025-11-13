"""
Internet access control tools (parental controls).

Uses MULTIFILTER system with parallel arrays synchronized by index.
"""

from typing import Any

from mcp.types import TextContent

from config.constants import (
    NVRAM_MULTIFILTER_ALL,
    NVRAM_MULTIFILTER_DEVICENAME,
    NVRAM_MULTIFILTER_ENABLE,
    NVRAM_MULTIFILTER_MAC,
)
from core.ssh_client import RouterSSHClient
from utils.nvram_parser import build_multifilter_list, parse_multifilter_list
from utils.validators import is_valid_mac, normalize_mac


def handle_block_device_internet(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Block or unblock a device from internet access using parental controls.

    Args:
        router: SSH client for router communication
        arguments: Dict with 'mac_address', 'enabled', and optional 'description'

    Returns:
        List containing TextContent with operation result
    """
    mac_address = arguments.get("mac_address")
    enabled = arguments.get("enabled")
    description = arguments.get("description", "")

    # Validate MAC address
    if not is_valid_mac(mac_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid MAC address format: {mac_address}",
            )
        ]

    # Normalize MAC
    mac_normalized = normalize_mac(mac_address)

    # Get current MULTIFILTER parallel arrays
    mac_output, error, mac_code = router.execute_command(
        f"nvram get {NVRAM_MULTIFILTER_MAC}"
    )
    name_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_MULTIFILTER_DEVICENAME}"
    )
    enable_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_MULTIFILTER_ENABLE}"
    )

    if mac_code != 0:
        return [
            TextContent(
                type="text",
                text=f"Error reading parental control settings: {error}",
            )
        ]

    # Parse parallel arrays using MULTIFILTER-specific parser
    mac_list = parse_multifilter_list(mac_output.strip())
    name_list = parse_multifilter_list(name_output.strip())
    enable_list = parse_multifilter_list(enable_output.strip())

    if enabled:
        # Add to block list
        if mac_normalized in mac_list:
            return [
                TextContent(
                    type="text",
                    text=f"Device {mac_normalized} is already blocked",
                )
            ]

        mac_list.append(mac_normalized)
        name_list.append(description or mac_normalized)
        enable_list.append("1")  # Enable blocking for this device
        action = "blocked"
    else:
        # Remove from block list
        if mac_normalized not in mac_list:
            return [
                TextContent(
                    type="text",
                    text=f"Device {mac_normalized} is not currently blocked",
                )
            ]

        # Remove from all parallel arrays to maintain sync
        index = mac_list.index(mac_normalized)
        mac_list.pop(index)
        if index < len(name_list):
            name_list.pop(index)
        if index < len(enable_list):
            enable_list.pop(index)
        action = "unblocked"

    # Build new lists using MULTIFILTER-specific builder
    new_mac_list = build_multifilter_list(mac_list)
    new_name_list = build_multifilter_list(name_list)
    new_enable_list = build_multifilter_list(enable_list)

    # Set all parallel arrays and enable MULTIFILTER system
    router.execute_command(f"nvram set {NVRAM_MULTIFILTER_MAC}='{new_mac_list}'")
    router.execute_command(
        f"nvram set {NVRAM_MULTIFILTER_DEVICENAME}='{new_name_list}'"
    )
    router.execute_command(f"nvram set {NVRAM_MULTIFILTER_ENABLE}='{new_enable_list}'")
    router.execute_command(
        f"nvram set {NVRAM_MULTIFILTER_ALL}=1"
    )  # Enable parental control system
    output, error, code = router.execute_command("nvram commit")

    if code != 0:
        return [
            TextContent(type="text", text=f"Error setting parental controls: {error}")
        ]

    # Restart firewall to apply changes
    output, error, code = router.execute_command("service restart_firewall")

    result = f"✓ Device {action}: {mac_normalized}\n"
    if description:
        result = f"Device: {description}\n{result}"

    if code == 0:
        result += "✓ Firewall restarted"
    else:
        result += f"⚠ Firewall restart failed: {error}"

    return [TextContent(type="text", text=result)]


def handle_list_blocked_devices(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    List all devices currently blocked from internet access.

    Shows device names and individual enable status from parallel arrays.

    Args:
        router: SSH client for router communication
        _arguments: Dict (unused, but required for handler signature)

    Returns:
        List containing TextContent with blocked devices and status
    """
    # Get MULTIFILTER parallel arrays
    all_output, _, _ = router.execute_command(f"nvram get {NVRAM_MULTIFILTER_ALL}")
    mac_output, error, mac_code = router.execute_command(
        f"nvram get {NVRAM_MULTIFILTER_MAC}"
    )
    name_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_MULTIFILTER_DEVICENAME}"
    )
    enable_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_MULTIFILTER_ENABLE}"
    )

    if mac_code != 0:
        return [
            TextContent(
                type="text",
                text=f"Error reading parental control settings: {error}",
            )
        ]

    # Parse using MULTIFILTER-specific parser
    is_system_enabled = all_output.strip() == "1"
    mac_list = parse_multifilter_list(mac_output.strip())
    name_list = parse_multifilter_list(name_output.strip())
    enable_list = parse_multifilter_list(enable_output.strip())

    result = ""
    if not is_system_enabled and mac_list:
        result = "⚠ Parental controls are DISABLED (devices not actively blocked)\n\n"
    elif is_system_enabled:
        result = "✓ Parental controls are ENABLED\n\n"

    if not mac_list:
        result += "No devices are configured for blocking"
    else:
        result += f"Blocked Devices ({len(mac_list)}):\n"
        for i, mac in enumerate(mac_list):
            name = name_list[i] if i < len(name_list) else "(unknown)"
            status = enable_list[i] if i < len(enable_list) else "0"
            status_str = "✓ Active" if status == "1" else "✗ Inactive"
            result += f"{i + 1}. {name} - {mac} [{status_str}]\n"

    return [TextContent(type="text", text=result)]
