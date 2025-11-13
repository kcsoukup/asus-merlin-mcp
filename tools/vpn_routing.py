"""
VPN Director routing tools for Asuswrt-Merlin firmware.

VPN Director is Merlin's implementation of policy-based routing for OpenVPN clients.
It replaces the stock ASUS "VPN Fusion" feature with more powerful routing capabilities.

Uses /jffs/openvpn/vpndirector_rulelist file with format:
<enable>description>localIP>remoteIP>interface>

IMPORTANT: These tools only work with Asuswrt-Merlin firmware.
Stock ASUS firmware uses VPN Fusion (different file and format).
"""

from typing import Any

from mcp.types import TextContent

from config.constants import VPN_DIRECTOR_RULELIST_FILE
from core.ssh_client import RouterSSHClient
from utils.nvram_parser import build_vpn_director_rules, parse_vpn_director_rules
from utils.validators import is_merlin_firmware, is_valid_mac, normalize_mac


def _get_device_ip_by_mac(router: RouterSSHClient, mac: str) -> str | None:
    """
    Look up device IP address by MAC address from DHCP leases.

    Args:
        router: RouterSSHClient instance
        mac: MAC address (normalized format)

    Returns:
        IP address string if found, None otherwise
    """
    # Get DHCP leases
    output, _, code = router.execute_command(
        "cat /var/lib/misc/dnsmasq.leases 2>/dev/null"
    )

    if code != 0:
        return None

    # Parse DHCP leases format: timestamp MAC IP hostname client-id
    for line in output.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            lease_mac = parts[1].upper()
            lease_ip = parts[2]
            if lease_mac == mac:
                return lease_ip

    return None


def _vpn_client_to_interface(vpn_client_number: int) -> str:
    """
    Convert VPN client number (1-5) to VPN Director interface name (OVPN1-5).

    Args:
        vpn_client_number: VPN client number (1-5)

    Returns:
        Interface name (OVPN1, OVPN2, etc.)
    """
    return f"OVPN{vpn_client_number}"


def _interface_to_vpn_client(interface: str) -> int | None:
    """
    Convert VPN Director interface name to VPN client number.

    Args:
        interface: Interface name (OVPN1-5, WGC1-2, WAN)

    Returns:
        VPN client number (1-5) for OVPN interfaces, None for others
    """
    if interface.startswith("OVPN") and len(interface) == 5:
        try:
            return int(interface[4])
        except ValueError:
            return None
    return None


def _check_merlin_firmware(router: RouterSSHClient) -> TextContent | None:
    """
    Check if router is running Merlin firmware.

    Returns error message if not Merlin, None if Merlin detected.
    """
    if not is_merlin_firmware(router):
        error_msg = (
            "ERROR: VPN routing tools require Asuswrt-Merlin firmware\n\n"
            "Your router is running stock ASUS firmware, which is not currently supported.\n\n"
            "Why: Merlin firmware uses VPN Director (vpndirector_rulelist) while stock ASUS\n"
            "     uses VPN Fusion (vpnc_dev_policy_list) - different features entirely.\n\n"
            "Options:\n"
            "  1. Install Asuswrt-Merlin firmware (recommended): https://www.asuswrt-merlin.net/\n"
            "  2. Request stock ASUS firmware support via GitHub:\n"
            "     https://github.com/kcsoukup/mcp-asus-merlin/issues\n\n"
            "Note: The primary user base for this MCP server uses Merlin firmware.\n"
            "      Stock ASUS support may be added in future releases if there's demand."
        )
        return TextContent(type="text", text=error_msg)
    return None


def handle_add_vpn_routing_policy(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Add device to VPN Director routing (Asuswrt-Merlin only).

    Creates a VPN Director rule to route a specific device through a VPN client.
    Requires Asuswrt-Merlin firmware - stock ASUS firmware is not supported.

    Args:
        router: RouterSSHClient instance for executing commands
        arguments: Dict containing:
            - mac_address: Device MAC address (required)
            - vpn_client_number: VPN client to route through (1-5, required)
            - description: Optional rule description/hostname

    Returns:
        List containing TextContent with operation result
    """
    # Check Merlin firmware first
    firmware_check = _check_merlin_firmware(router)
    if firmware_check:
        return [firmware_check]

    mac_address = arguments.get("mac_address")
    vpn_client_number = arguments.get("vpn_client_number")
    description = arguments.get("description", "")

    # Validate inputs
    if not is_valid_mac(mac_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid MAC address format: {mac_address}",
            )
        ]

    if not isinstance(vpn_client_number, int) or not 1 <= vpn_client_number <= 5:
        return [
            TextContent(
                type="text",
                text=f"Error: VPN client number must be 1-5, got {vpn_client_number}",
            )
        ]

    # Normalize MAC and look up IP
    mac_normalized = normalize_mac(mac_address)
    device_ip = _get_device_ip_by_mac(router, mac_normalized)

    if not device_ip:
        return [
            TextContent(
                type="text",
                text=f"Error: Cannot find IP address for MAC {mac_normalized}\n"
                f"Device must be connected and have a DHCP lease.\n"
                f"Try connecting the device first, or create a DHCP reservation.",
            )
        ]

    # Get current VPN Director rules from file
    success, content, error = router.read_file_content(VPN_DIRECTOR_RULELIST_FILE)

    # If file doesn't exist, start with empty rules
    if not success:
        rules = []
    else:
        # Parse existing rules
        rules = parse_vpn_director_rules(content.strip())

    # Check if device IP already has a rule
    for rule in rules:
        if rule["local_ip"] == device_ip:
            existing_vpn = _interface_to_vpn_client(rule["interface"])
            return [
                TextContent(
                    type="text",
                    text=f"Error: Device IP {device_ip} already has a VPN routing rule\n"
                    f"Currently routing through: {rule['interface']}"
                    + (f" (VPN Client {existing_vpn})" if existing_vpn else "")
                    + "\nRemove existing rule first or use different device",
                )
            ]

    # Add new rule
    interface = _vpn_client_to_interface(vpn_client_number)
    rule_description = description if description else f"Device-{device_ip}"

    new_rule = {
        "enable": "1",  # Enabled by default
        "description": rule_description,
        "local_ip": device_ip,
        "remote_ip": "",  # Empty = route all destinations
        "interface": interface,
    }
    rules.append(new_rule)

    # Build new rulelist
    new_list_str = build_vpn_director_rules(rules)

    # Write to VPN Director file with MD5 verification
    success, error = router.write_file_content(VPN_DIRECTOR_RULELIST_FILE, new_list_str)

    if not success:
        return [
            TextContent(type="text", text=f"Error writing VPN Director rule: {error}")
        ]

    # Format result
    result = "✓ Device added to VPN Director routing:\n"
    result += f"  MAC: {mac_normalized}\n"
    result += f"  IP: {device_ip}\n"
    result += f"  VPN Client: {vpn_client_number} ({interface})\n"
    result += f"  Description: {rule_description}\n"
    result += "  Status: Enabled\n"
    result += "  Destination: All (routes all traffic)\n"
    result += "\n⚠ Note: Changes take effect immediately. Check VPN Director page in router UI."

    return [TextContent(type="text", text=result)]


def handle_remove_vpn_routing_policy(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Remove device from VPN Director routing (Asuswrt-Merlin only).

    Removes the device's routing rule from VPN Director, returning it to normal routing.
    Requires Asuswrt-Merlin firmware - stock ASUS firmware is not supported.

    Args:
        router: RouterSSHClient instance for executing commands
        arguments: Dict containing:
            - mac_address: Device MAC address to remove

    Returns:
        List containing TextContent with operation result
    """
    # Check Merlin firmware first
    firmware_check = _check_merlin_firmware(router)
    if firmware_check:
        return [firmware_check]

    mac_address = arguments.get("mac_address")

    # Validate MAC
    if not is_valid_mac(mac_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid MAC address format: {mac_address}",
            )
        ]

    # Normalize MAC and look up IP
    mac_normalized = normalize_mac(mac_address)
    device_ip = _get_device_ip_by_mac(router, mac_normalized)

    if not device_ip:
        return [
            TextContent(
                type="text",
                text=f"Error: Cannot find IP address for MAC {mac_normalized}\n"
                f"Unable to remove rule without knowing device IP.\n"
                f"Device may be offline or rule may already be removed.",
            )
        ]

    # Get current VPN Director rules from file
    success, content, error = router.read_file_content(VPN_DIRECTOR_RULELIST_FILE)

    if not success:
        return [
            TextContent(
                type="text",
                text=f"Error: No VPN Director rules file found\n"
                f"File {VPN_DIRECTOR_RULELIST_FILE} does not exist or cannot be read.",
            )
        ]

    # Parse rules
    rules = parse_vpn_director_rules(content.strip())

    # Find and remove matching rule by IP
    removed = None
    new_rules = []
    for rule in rules:
        if rule["local_ip"] == device_ip:
            removed = rule
        else:
            new_rules.append(rule)

    if not removed:
        return [
            TextContent(
                type="text",
                text=f"Error: No VPN routing rule found for IP {device_ip} (MAC: {mac_normalized})",
            )
        ]

    # Build new rulelist
    new_list_str = build_vpn_director_rules(new_rules)

    # Write to VPN Director file (or remove file if no rules left)
    if new_list_str:
        success, error = router.write_file_content(
            VPN_DIRECTOR_RULELIST_FILE, new_list_str
        )
        if not success:
            return [
                TextContent(
                    type="text", text=f"Error removing VPN Director rule: {error}"
                )
            ]
    else:
        # Remove file if no rules remain
        _, error, code = router.execute_command(f"rm -f {VPN_DIRECTOR_RULELIST_FILE}")
        if code != 0:
            return [
                TextContent(
                    type="text", text=f"Error removing VPN Director file: {error}"
                )
            ]

    # Format result
    vpn_client = _interface_to_vpn_client(removed["interface"])
    result = "✓ Device removed from VPN Director routing:\n"
    result += f"  MAC: {mac_normalized}\n"
    result += f"  IP: {device_ip}\n"
    result += f"  Was routing through: {removed['interface']}"
    if vpn_client:
        result += f" (VPN Client {vpn_client})"
    result += "\n"
    if removed.get("description"):
        result += f"  Description: {removed['description']}\n"
    result += "\n⚠ Note: Changes take effect immediately"

    return [TextContent(type="text", text=result)]


def handle_list_vpn_policies(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    List all VPN Director routing rules (Asuswrt-Merlin only).

    Shows all devices configured to route through VPN clients via VPN Director.
    Requires Asuswrt-Merlin firmware - stock ASUS firmware is not supported.

    Args:
        router: RouterSSHClient instance for executing commands
        _arguments: Unused (no parameters required)

    Returns:
        List containing TextContent with formatted VPN Director rules table
    """
    # Check Merlin firmware first
    firmware_check = _check_merlin_firmware(router)
    if firmware_check:
        return [firmware_check]

    # Get VPN Director rulelist from file
    success, content, error = router.read_file_content(VPN_DIRECTOR_RULELIST_FILE)

    # If file doesn't exist or is empty, no rules configured
    if not success:
        rules = []
    else:
        # Parse rules
        rules = parse_vpn_director_rules(content.strip())

    if not rules:
        return [
            TextContent(
                type="text",
                text="No VPN Director routing rules configured\n\n"
                "VPN Director is Merlin's policy-based routing system.\n"
                "Use 'add_vpn_routing_policy' to route devices through VPN clients.",
            )
        ]

    # Format as table
    result = f"VPN Director Routing Rules ({len(rules)} total)\n"
    result += "Firmware: Asuswrt-Merlin\n\n"
    result += "Source IP       Interface  VPN Client  Status    Description\n"
    result += "─" * 75 + "\n"

    for rule in rules:
        local_ip = rule.get("local_ip", "Unknown")
        interface = rule.get("interface", "?")
        status = "Enabled" if rule.get("enable") == "1" else "Disabled"
        description = rule.get("description", "")
        remote_ip = rule.get("remote_ip", "")

        # Try to extract VPN client number from interface
        vpn_client = _interface_to_vpn_client(interface)
        vpn_display = f"Client {vpn_client}" if vpn_client else "N/A"

        result += f"{local_ip:<15} {interface:<10} {vpn_display:<11} {status:<9} {description}\n"

        if remote_ip:
            result += (
                f"                                              → Dest: {remote_ip}\n"
            )

    result += (
        "\n💡 Tip: Use 'add_vpn_routing_policy' to route devices through VPN clients"
    )
    result += "\n💡 Check VPN client status with 'get_vpn_status'"
    result += "\n💡 View rules in router UI: VPN → VPN Director"

    return [TextContent(type="text", text=result)]
