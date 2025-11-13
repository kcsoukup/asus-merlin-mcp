"""
MAC filtering tools for WiFi access control.
"""

from typing import Any

from mcp.types import TextContent

from core.ssh_client import RouterSSHClient
from utils.nvram_parser import build_nvram_list, parse_nvram_list
from utils.validators import is_valid_mac, normalize_mac


def handle_add_mac_filter(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """Add device to MAC filter (whitelist or blacklist) for WiFi access control."""
    mac_address = arguments.get("mac_address")
    filter_type = arguments.get("filter_type", "blacklist")
    radio = arguments.get("radio", "both")
    description = arguments.get("description", "")

    # Validate MAC address
    if not is_valid_mac(mac_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid MAC address format: {mac_address}",
            )
        ]

    # Normalize MAC address
    mac_normalized = normalize_mac(mac_address)

    # Determine which radios to update
    radios = []
    if radio in ["2.4ghz", "both"]:
        radios.append(("wl0", "2.4GHz"))
    if radio in ["5ghz", "both"]:
        radios.append(("wl1", "5GHz"))

    # Determine MAC mode (allow = whitelist, deny = blacklist)
    mac_mode = "allow" if filter_type == "whitelist" else "deny"

    results = []
    for radio_prefix, radio_name in radios:
        # Get current MAC list
        output, error, code = router.execute_command(
            f"nvram get {radio_prefix}_maclist"
        )
        if code != 0:
            results.append(f"Error reading {radio_name} MAC list: {error}")
            continue

        current_list = parse_nvram_list(output.strip())
        was_empty = len(current_list) == 0

        # Check if MAC already exists
        if mac_normalized in current_list:
            results.append(f"{radio_name}: MAC {mac_normalized} already in filter list")
            continue

        # Add MAC to list
        current_list.append(mac_normalized)
        new_list_str = build_nvram_list(current_list)

        # Set MAC list and mode (both _maclist and _maclist_x are needed)
        # Only set macmode if list was previously empty (enabling filtering)
        if was_empty:
            set_cmd = (
                f"nvram set {radio_prefix}_maclist='{new_list_str}' && "
                f"nvram set {radio_prefix}_maclist_x='{new_list_str}' && "
                f"nvram set {radio_prefix}_macmode={mac_mode} && "
                f"nvram commit"
            )
        else:
            # List had entries - don't change the mode
            set_cmd = (
                f"nvram set {radio_prefix}_maclist='{new_list_str}' && "
                f"nvram set {radio_prefix}_maclist_x='{new_list_str}' && "
                f"nvram commit"
            )
        output, error, code = router.execute_command(set_cmd)

        if code == 0:
            results.append(f"✓ {radio_name}: Added {mac_normalized} to {filter_type}")
        else:
            results.append(f"✗ {radio_name}: Failed to add MAC: {error}")

    # Restart wireless service to apply changes
    output, error, code = router.execute_command("service restart_wireless")
    if code == 0:
        results.append("✓ Wireless service restarted")
    else:
        results.append(f"⚠ Wireless service restart failed: {error}")

    result_text = "\n".join(results)
    if description:
        result_text = f"Device: {description}\n{result_text}"

    return [TextContent(type="text", text=result_text)]


def handle_remove_mac_filter(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """Remove device from MAC filter."""
    mac_address = arguments.get("mac_address")
    radio = arguments.get("radio", "both")

    # Validate MAC address
    if not is_valid_mac(mac_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid MAC address format: {mac_address}",
            )
        ]

    # Normalize MAC address
    mac_normalized = normalize_mac(mac_address)

    # Determine which radios to update
    radios = []
    if radio in ["2.4ghz", "both"]:
        radios.append(("wl0", "2.4GHz"))
    if radio in ["5ghz", "both"]:
        radios.append(("wl1", "5GHz"))

    results = []
    for radio_prefix, radio_name in radios:
        # Get current MAC list
        output, error, code = router.execute_command(
            f"nvram get {radio_prefix}_maclist"
        )
        if code != 0:
            results.append(f"Error reading {radio_name} MAC list: {error}")
            continue

        current_list = parse_nvram_list(output.strip())

        # Check if MAC exists
        if mac_normalized not in current_list:
            results.append(
                f"{radio_name}: MAC {mac_normalized} not found in filter list"
            )
            continue

        # Remove MAC from list
        current_list.remove(mac_normalized)
        new_list_str = build_nvram_list(current_list)

        # If list is empty, disable MAC filtering; otherwise keep current mode
        if not current_list:
            # Empty list - disable MAC filtering
            set_cmd = (
                f"nvram set {radio_prefix}_maclist='{new_list_str}' && "
                f"nvram set {radio_prefix}_maclist_x='{new_list_str}' && "
                f"nvram set {radio_prefix}_macmode=disabled && "
                f"nvram commit"
            )
        else:
            # List still has MACs - keep filtering enabled
            set_cmd = (
                f"nvram set {radio_prefix}_maclist='{new_list_str}' && "
                f"nvram set {radio_prefix}_maclist_x='{new_list_str}' && "
                f"nvram commit"
            )
        output, error, code = router.execute_command(set_cmd)

        if code == 0:
            results.append(f"✓ {radio_name}: Removed {mac_normalized}")
        else:
            results.append(f"✗ {radio_name}: Failed to remove MAC: {error}")

    # Restart wireless service to apply changes
    output, error, code = router.execute_command("service restart_wireless")
    if code == 0:
        results.append("✓ Wireless service restarted")
    else:
        results.append(f"⚠ Wireless service restart failed: {error}")

    return [TextContent(type="text", text="\n".join(results))]


def handle_list_mac_filters(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """Show current MAC filters with friendly formatting."""
    results = []

    for radio_prefix, radio_name in [("wl0", "2.4GHz"), ("wl1", "5GHz")]:
        # Get MAC list and mode
        list_output, _, list_code = router.execute_command(
            f"nvram get {radio_prefix}_maclist"
        )
        mode_output, _, mode_code = router.execute_command(
            f"nvram get {radio_prefix}_macmode"
        )

        if list_code != 0 or mode_code != 0:
            results.append(f"{radio_name}: Error reading configuration")
            continue

        mac_list = parse_nvram_list(list_output.strip())
        mac_mode = mode_output.strip()

        # Convert mode to friendly name
        filter_type = (
            "whitelist (allow only)" if mac_mode == "allow" else "blacklist (deny only)"
        )

        results.append(f"\n{radio_name} - Mode: {filter_type}")
        if mac_list:
            results.append(f"  Filtered MACs ({len(mac_list)}):")
            for mac in mac_list:
                results.append(f"    • {mac}")
        else:
            results.append("  No MAC filters configured")

    return [TextContent(type="text", text="\n".join(results))]
