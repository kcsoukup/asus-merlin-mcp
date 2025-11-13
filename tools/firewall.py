"""
Firewall management tool handlers for ASUS Merlin MCP server.

This module provides tools for viewing and configuring firewall settings including:
- Main firewall enable/disable
- DoS protection
- Firewall logging
- WAN ping response
- VPN passthrough protocols (PPTP, L2TP, IPSec, RTSP, H.323, SIP)
- IPv6 firewall
"""

from typing import Any

from mcp.types import TextContent

from core.ssh_client import RouterSSHClient


def handle_get_firewall_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    Get comprehensive firewall status and configuration.

    Returns current status of:
    - Main firewall (enabled/disabled)
    - DoS protection
    - Firewall logging mode
    - WAN ping response
    - VPN passthrough settings (PPTP, L2TP, IPSec, RTSP, H.323, SIP, PPPoE)
    - LAN/WAN filtering
    - IPv6 firewall

    Args:
        router: RouterSSHClient instance for executing commands
        _arguments: Not used (underscore prefix indicates intentionally unused)

    Returns:
        list[TextContent]: Formatted firewall status information
    """
    # Get all firewall-related NVRAM variables
    variables = [
        "fw_enable_x",
        "fw_dos_x",
        "fw_log_x",
        "misc_ping_x",
        "fw_pt_pptp",
        "fw_pt_l2tp",
        "fw_pt_ipsec",
        "fw_pt_rtsp",
        "fw_pt_h323",
        "fw_pt_sip",
        "fw_pt_pppoerelay",
        "fw_lw_enable_x",
        "fw_wl_enable_x",
        "ipv6_fw_enable",
    ]

    values = {}
    for var in variables:
        output, error, code = router.execute_command(f"nvram get {var}")
        if code == 0:
            values[var] = output.strip()
        else:
            values[var] = "unknown"

    # Format output
    result = "🛡️  FIREWALL STATUS\n\n"

    # Main firewall status
    fw_enabled = values["fw_enable_x"] == "1"
    result += f"Main Firewall: {'✓ ENABLED' if fw_enabled else '✗ DISABLED'}\n"

    dos_enabled = values["fw_dos_x"] == "1"
    result += f"DoS Protection: {'✓ ENABLED' if dos_enabled else '✗ DISABLED'}\n"

    # Logging
    log_mode = values["fw_log_x"]
    log_display = {
        "none": "Disabled",
        "drop": "Dropped packets only",
        "accept": "Accepted packets only",
        "both": "All packets",
    }.get(log_mode, log_mode)
    result += f"Firewall Logging: {log_display}\n"

    # WAN ping response
    ping_enabled = values["misc_ping_x"] == "1"
    result += (
        f"Respond to WAN Ping: {'✓ YES' if ping_enabled else '✗ NO (Stealthed)'}\n"
    )

    # IPv6 firewall
    ipv6_fw_enabled = values["ipv6_fw_enable"] == "1"
    result += f"IPv6 Firewall: {'✓ ENABLED' if ipv6_fw_enabled else '✗ DISABLED'}\n"

    # VPN Passthrough
    result += "\n📡 VPN PASSTHROUGH\n"
    passthrough = {
        "PPTP": values["fw_pt_pptp"] == "1",
        "L2TP": values["fw_pt_l2tp"] == "1",
        "IPSec": values["fw_pt_ipsec"] == "1",
        "RTSP": values["fw_pt_rtsp"] == "1",
        "H.323": values["fw_pt_h323"] == "1",
        "SIP": values["fw_pt_sip"] == "1",
        "PPPoE Relay": values["fw_pt_pppoerelay"] == "1",
    }

    for protocol, enabled in passthrough.items():
        result += f"  {protocol}: {'✓ Enabled' if enabled else '✗ Disabled'}\n"

    # LAN/WAN filtering
    result += "\n🔒 PACKET FILTERING\n"
    lw_filter = values["fw_lw_enable_x"] == "1"
    result += f"  LAN → WAN Filter: {'✓ Enabled' if lw_filter else '✗ Disabled'}\n"
    wl_filter = values["fw_wl_enable_x"] == "1"
    result += f"  WAN → LAN Filter: {'✓ Enabled' if wl_filter else '✗ Disabled'}\n"

    return [TextContent(type="text", text=result)]


def handle_set_firewall_config(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Configure firewall settings.

    Allows setting:
    - enable_firewall: Enable/disable main firewall (true/false)
    - enable_dos_protection: Enable/disable DoS protection (true/false)
    - log_mode: Firewall logging (none/drop/accept/both)
    - respond_to_wan_ping: Respond to WAN ping requests (true/false)
    - enable_ipv6_firewall: Enable/disable IPv6 firewall (true/false)
    - vpn_passthrough: Dict of protocol passthroughs to enable/disable
      - pptp: PPTP passthrough (true/false)
      - l2tp: L2TP passthrough (true/false)
      - ipsec: IPSec passthrough (true/false)
      - rtsp: RTSP passthrough (true/false)
      - h323: H.323 passthrough (true/false)
      - sip: SIP passthrough (true/false)
      - pppoe_relay: PPPoE relay (true/false)

    Args:
        router: RouterSSHClient instance for executing commands
        arguments: Configuration parameters (type: Any to match MCP protocol)

    Returns:
        list[TextContent]: Success message with applied changes
    """
    changes = []
    errors = []

    # Helper to set NVRAM value
    def set_nvram(var: str, value: str, description: str) -> None:
        output, error, code = router.execute_command(f"nvram set {var}={value}")
        if code == 0:
            changes.append(f"✓ {description}: {value}")
        else:
            errors.append(f"✗ Failed to set {description}: {error}")

    # Main firewall enable/disable
    if "enable_firewall" in arguments:
        value = "1" if arguments["enable_firewall"] else "0"
        set_nvram("fw_enable_x", value, "Main firewall")

    # DoS protection
    if "enable_dos_protection" in arguments:
        value = "1" if arguments["enable_dos_protection"] else "0"
        set_nvram("fw_dos_x", value, "DoS protection")

    # Firewall logging
    if "log_mode" in arguments:
        log_mode = arguments["log_mode"]
        if log_mode in ["none", "drop", "accept", "both"]:
            set_nvram("fw_log_x", log_mode, "Firewall logging")
        else:
            errors.append(
                f"✗ Invalid log_mode: {log_mode} (must be: none/drop/accept/both)"
            )

    # WAN ping response
    if "respond_to_wan_ping" in arguments:
        value = "1" if arguments["respond_to_wan_ping"] else "0"
        set_nvram("misc_ping_x", value, "Respond to WAN ping")

    # IPv6 firewall
    if "enable_ipv6_firewall" in arguments:
        value = "1" if arguments["enable_ipv6_firewall"] else "0"
        set_nvram("ipv6_fw_enable", value, "IPv6 firewall")

    # VPN passthrough settings
    if "vpn_passthrough" in arguments:
        pt = arguments["vpn_passthrough"]
        passthrough_map = {
            "pptp": ("fw_pt_pptp", "PPTP passthrough"),
            "l2tp": ("fw_pt_l2tp", "L2TP passthrough"),
            "ipsec": ("fw_pt_ipsec", "IPSec passthrough"),
            "rtsp": ("fw_pt_rtsp", "RTSP passthrough"),
            "h323": ("fw_pt_h323", "H.323 passthrough"),
            "sip": ("fw_pt_sip", "SIP passthrough"),
            "pppoe_relay": ("fw_pt_pppoerelay", "PPPoE relay"),
        }

        for key, (nvram_var, description) in passthrough_map.items():
            if key in pt:
                value = "1" if pt[key] else "0"
                set_nvram(nvram_var, value, description)

    # Commit changes if any were made
    if changes:
        output, error, code = router.execute_command("nvram commit")
        if code != 0:
            errors.append(f"✗ Warning: Failed to commit changes to NVRAM: {error}")

        # Restart firewall service to apply changes
        output, error, code = router.execute_command("service restart_firewall")
        if code == 0:
            changes.append("✓ Firewall service restarted (changes applied)")
        else:
            errors.append(f"✗ Warning: Failed to restart firewall: {error}")

    # Format result
    if not changes and not errors:
        return [
            TextContent(
                type="text", text="No firewall configuration changes were requested."
            )
        ]

    result = "🛡️  FIREWALL CONFIGURATION UPDATE\n\n"

    if changes:
        result += "✅ CHANGES APPLIED:\n"
        for change in changes:
            result += f"  {change}\n"

    if errors:
        result += "\n⚠️  ERRORS:\n"
        for error in errors:
            result += f"  {error}\n"

    if changes and not errors:
        result += "\n✓ All firewall settings updated successfully."
    elif changes and errors:
        result += "\n⚠️  Some settings updated, but errors occurred."

    return [TextContent(type="text", text=result)]
