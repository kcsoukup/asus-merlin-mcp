"""
DHCP management tools for static IP reservations.
"""

from typing import Any

from mcp.types import TextContent

from core.ssh_client import RouterSSHClient
from utils.nvram_parser import build_dhcp_reservation_list, parse_dhcp_reservation_list
from utils.validators import is_valid_ip, is_valid_mac, normalize_mac


def handle_add_dhcp_reservation(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Add a DHCP static IP reservation for a device.

    Args:
        router: SSH client for router operations
        arguments: Dict with mac_address, ip_address, dns (optional), hostname (optional)

    Returns:
        List containing TextContent with result message
    """
    mac_address = arguments.get("mac_address")
    ip_address = arguments.get("ip_address")
    dns = arguments.get("dns", "")
    hostname = arguments.get("hostname", "")

    # Validate inputs
    if not is_valid_mac(mac_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid MAC address format: {mac_address}",
            )
        ]

    if not is_valid_ip(ip_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid IP address format: {ip_address}",
            )
        ]

    # Normalize MAC
    mac_normalized = normalize_mac(mac_address)

    # Get current DHCP reservations (try both possible NVRAM variables)
    output, error, code = router.execute_command(
        "nvram get dhcp_staticlist 2>/dev/null || nvram get dhcp_reservelist 2>/dev/null"
    )

    # Determine which variable to use
    var_check, _, _ = router.execute_command(
        "nvram show | grep -E 'dhcp_(staticlist|reservelist)=' | head -1"
    )
    if "dhcp_staticlist" in var_check:
        dhcp_var = "dhcp_staticlist"
    elif "dhcp_reservelist" in var_check:
        dhcp_var = "dhcp_reservelist"
    else:
        # Default to dhcp_staticlist if neither exists
        dhcp_var = "dhcp_staticlist"

    current_reservations = parse_dhcp_reservation_list(output.strip())

    # Check for duplicates
    for res in current_reservations:
        if res["mac"] == mac_normalized:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Reservation already exists for MAC {mac_normalized} with IP {res['ip']}",
                )
            ]
        if res["ip"] == ip_address:
            return [
                TextContent(
                    type="text",
                    text=f"Error: IP {ip_address} already reserved for MAC {res['mac']}",
                )
            ]

    # Add new reservation
    current_reservations.append(
        {
            "mac": mac_normalized,
            "ip": ip_address,
            "dns": dns,
            "hostname": hostname,
        }
    )
    new_list_str = build_dhcp_reservation_list(current_reservations)

    # Set DHCP reservation list
    set_cmd = f"nvram set {dhcp_var}='{new_list_str}'"
    output, error, code = router.execute_command(set_cmd)

    if code != 0:
        return [
            TextContent(type="text", text=f"Error setting DHCP reservation: {error}")
        ]

    # Restart dnsmasq service
    output, error, code = router.execute_command("service restart_dnsmasq")

    result = "✓ DHCP reservation added:\n"
    result += f"  MAC: {mac_normalized}\n"
    result += f"  IP: {ip_address}\n"
    result += f"  Hostname: {hostname}\n"

    if code == 0:
        result += "✓ DNSMASQ service restarted"
    else:
        result += f"⚠ DNSMASQ service restart failed: {error}"

    return [TextContent(type="text", text=result)]


def handle_remove_dhcp_reservation(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Remove a DHCP static IP reservation for a device.

    Args:
        router: SSH client for router operations
        arguments: Dict with mac_address (optional) and/or ip_address (optional)

    Returns:
        List containing TextContent with result message
    """
    mac_address = arguments.get("mac_address")
    ip_address = arguments.get("ip_address")

    # Must provide at least one
    if not mac_address and not ip_address:
        return [
            TextContent(
                type="text",
                text="Error: Must provide either mac_address or ip_address",
            )
        ]

    # Normalize MAC if provided
    if mac_address:
        if not is_valid_mac(mac_address):
            return [
                TextContent(
                    type="text",
                    text=f"Error: Invalid MAC address format: {mac_address}",
                )
            ]
        mac_address = normalize_mac(mac_address)

    # Validate IP if provided
    if ip_address and not is_valid_ip(ip_address):
        return [
            TextContent(
                type="text",
                text=f"Error: Invalid IP address format: {ip_address}",
            )
        ]

    # Get current DHCP reservations
    output, error, code = router.execute_command(
        "nvram get dhcp_staticlist 2>/dev/null || nvram get dhcp_reservelist 2>/dev/null"
    )

    # Determine which variable to use
    var_check, _, _ = router.execute_command(
        "nvram show | grep -E 'dhcp_(staticlist|reservelist)=' | head -1"
    )
    if "dhcp_staticlist" in var_check:
        dhcp_var = "dhcp_staticlist"
    elif "dhcp_reservelist" in var_check:
        dhcp_var = "dhcp_reservelist"
    else:
        dhcp_var = "dhcp_staticlist"

    current_reservations = parse_dhcp_reservation_list(output.strip())

    # Find and remove matching reservation
    removed = None
    new_reservations = []
    for res in current_reservations:
        if (mac_address and res["mac"] == mac_address) or (
            ip_address and res["ip"] == ip_address
        ):
            removed = res
        else:
            new_reservations.append(res)

    if not removed:
        search_str = f"MAC {mac_address}" if mac_address else f"IP {ip_address}"
        return [
            TextContent(
                type="text",
                text=f"Error: No DHCP reservation found for {search_str}",
            )
        ]

    # Build new list
    new_list_str = build_dhcp_reservation_list(new_reservations)

    # Set DHCP reservation list
    set_cmd = f"nvram set {dhcp_var}='{new_list_str}'"
    output, error, code = router.execute_command(set_cmd)

    if code != 0:
        return [
            TextContent(type="text", text=f"Error removing DHCP reservation: {error}")
        ]

    # Restart dnsmasq service
    output, error, code = router.execute_command("service restart_dnsmasq")

    result = "✓ DHCP reservation removed:\n"
    result += f"  MAC: {removed['mac']}\n"
    result += f"  IP: {removed['ip']}\n"
    result += f"  Hostname: {removed['hostname']}\n"

    if code == 0:
        result += "✓ DNSMASQ service restarted"
    else:
        result += f"⚠ DNSMASQ service restart failed: {error}"

    return [TextContent(type="text", text=result)]


def handle_list_dhcp_reservations(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    List all DHCP static IP reservations configured on the router.

    Args:
        router: SSH client for router operations
        arguments: Dict (unused for this operation)

    Returns:
        List containing TextContent with formatted reservation list
    """
    # Get current DHCP reservations
    output, error, code = router.execute_command(
        "nvram get dhcp_staticlist 2>/dev/null || nvram get dhcp_reservelist 2>/dev/null"
    )

    if code != 0:
        return [
            TextContent(type="text", text=f"Error reading DHCP reservations: {error}")
        ]

    reservations = parse_dhcp_reservation_list(output.strip())

    if not reservations:
        return [TextContent(type="text", text="No DHCP reservations configured")]

    result = f"DHCP Reservations ({len(reservations)}):\n\n"
    for i, res in enumerate(reservations, 1):
        hostname_display = res.get("hostname", "") or "(no hostname)"
        dns_display = res.get("dns", "") or "Default"
        result += f"{i}. {hostname_display}\n"
        result += f"   MAC: {res['mac']}\n"
        result += f"   IP:  {res['ip']}\n"
        result += f"   DNS: {dns_display}\n\n"

    return [TextContent(type="text", text=result.strip())]
