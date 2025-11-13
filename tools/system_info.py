"""System information and management tool handlers for ASUS router MCP server."""

import logging
from typing import Any

from mcp.types import TextContent

from core.ssh_client import RouterSSHClient
from utils.nvram_parser import parse_dhcp_reservation_list

logger = logging.getLogger("asus-merlin-mcp")


def handle_get_router_info(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """Get router system information (uptime, memory, CPU, firmware version)."""
    output, error, code = router.execute_command(
        "echo '=== Uptime ==='; uptime; "
        "echo '=== Memory ==='; free; "
        "echo '=== Firmware ==='; nvram get firmver; nvram get buildno"
    )
    return [TextContent(type="text", text=output if code == 0 else f"Error: {error}")]


def handle_get_connected_devices(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """List all devices connected to the router (via DHCP)."""
    output, error, code = router.execute_command(
        "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || arp -a"
    )
    return [TextContent(type="text", text=output if code == 0 else f"Error: {error}")]


def handle_get_all_network_devices(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """Get comprehensive list of all network devices (DHCP + static + ARP) with detailed info."""
    filter_type = arguments.get("filter_type", "all")

    # Get DHCP leases
    dhcp_output, _, dhcp_code = router.execute_command(
        "cat /var/lib/misc/dnsmasq.leases 2>/dev/null"
    )

    # Get ARP table
    arp_output, _, arp_code = router.execute_command("cat /proc/net/arp")

    # Get DHCP reservations
    dhcp_res_output, _, _ = router.execute_command(
        "nvram get dhcp_staticlist 2>/dev/null"
    )

    # Get hostnames from /etc/hosts
    hosts_output, _, _ = router.execute_command("cat /etc/hosts")

    # Parse data
    devices = {}  # Key: MAC address, Value: device info dict

    # Parse DHCP leases
    if dhcp_code == 0:
        for line in dhcp_output.strip().split("\n"):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                # Format: timestamp mac ip hostname client-id
                mac = parts[1].upper()
                ip = parts[2]
                hostname = parts[3] if parts[3] != "*" else ""
                devices[mac] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "type": "DHCP",
                    "status": "Active",
                }

    # Parse DHCP reservations
    reservations = parse_dhcp_reservation_list(dhcp_res_output.strip())
    for res in reservations:
        mac = res["mac"].upper()
        if mac in devices:
            devices[mac]["type"] = "DHCP Reservation"
        else:
            devices[mac] = {
                "ip": res["ip"],
                "mac": mac,
                "hostname": res["hostname"],
                "type": "DHCP Reservation",
                "status": "Configured",
            }

    # Parse ARP table and merge
    if arp_code == 0:
        for line in arp_output.strip().split("\n")[1:]:  # Skip header
            if not line or "incomplete" in line.lower():
                continue
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3].upper()

                if mac in devices:
                    # Update existing device with ARP status
                    devices[mac]["status"] = "Active"
                else:
                    # New device found only in ARP (static IP)
                    devices[mac] = {
                        "ip": ip,
                        "mac": mac,
                        "hostname": "",
                        "type": "Static/ARP Only",
                        "status": "Active",
                    }

    # Enhance hostnames from /etc/hosts
    if hosts_output:
        for line in hosts_output.strip().split("\n"):
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                hostname = parts[1]
                # Find device by IP and update hostname if better
                for mac, dev in devices.items():
                    if dev["ip"] == ip and (
                        not dev["hostname"] or dev["hostname"] == "*"
                    ):
                        dev["hostname"] = hostname

    # Apply filter
    filtered_devices = devices.values()
    if filter_type == "dhcp":
        filtered_devices = [d for d in devices.values() if d["type"] == "DHCP"]
    elif filter_type == "static":
        filtered_devices = [
            d for d in devices.values() if d["type"] == "Static/ARP Only"
        ]
    elif filter_type == "reservation":
        filtered_devices = [
            d for d in devices.values() if d["type"] == "DHCP Reservation"
        ]

    # Sort by IP address
    sorted_devices = sorted(
        filtered_devices, key=lambda x: tuple(map(int, x["ip"].split(".")))
    )

    # Format output
    filter_label = f" ({filter_type.upper()})" if filter_type != "all" else ""
    result = f"Network Devices Report{filter_label}\n"
    result += "=" * 70 + "\n\n"

    # Count device types
    dhcp_count = sum(1 for d in devices.values() if d["type"] == "DHCP")
    dhcp_res_count = sum(1 for d in devices.values() if d["type"] == "DHCP Reservation")
    static_count = sum(1 for d in devices.values() if d["type"] == "Static/ARP Only")
    active_count = sum(1 for d in devices.values() if d["status"] == "Active")

    if filter_type == "all":
        result += f"Total Devices: {len(devices)}\n"
        result += f"├─ DHCP Leases: {dhcp_count}\n"
        result += f"├─ DHCP Reservations: {dhcp_res_count}\n"
        result += f"├─ Static/ARP Only: {static_count}\n"
        result += f"└─ Currently Active: {active_count}\n\n"
    else:
        result += (
            f"Showing: {len(sorted_devices)} devices (filtered by {filter_type})\n"
        )
        result += f"Total Network Devices: {len(devices)}\n\n"

    # Device table
    result += f"{'IP Address':<16} {'MAC Address':<18} {'Hostname':<25} {'Type':<18}\n"
    result += "-" * 77 + "\n"

    for dev in sorted_devices:
        hostname = dev["hostname"] if dev["hostname"] else "(unknown)"
        result += f"{dev['ip']:<16} {dev['mac']:<18} {hostname:<25} {dev['type']:<18}\n"

    result += "\n" + "=" * 70 + "\n"
    result += "Legend:\n"
    result += "  • DHCP = Dynamic IP from DHCP server\n"
    result += "  • DHCP Reservation = Static assignment via DHCP\n"
    result += "  • Static/ARP Only = Manually configured static IP\n"

    return [TextContent(type="text", text=result)]


def handle_get_wifi_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """Get WiFi status for all radios (2.4GHz, 5GHz, etc.)."""
    # Get interface names dynamically for compatibility across router models
    wl0_if, _, _ = router.execute_command("nvram get wl0_ifname")
    wl1_if, _, _ = router.execute_command("nvram get wl1_ifname")

    wl0_if = wl0_if.strip()
    wl1_if = wl1_if.strip()

    # Get WiFi status for both radios
    result = "WiFi Status Report\n"
    result += "=" * 70 + "\n\n"

    # 2.4GHz Radio (wl0)
    if wl0_if:
        ssid_output, _, _ = router.execute_command("nvram get wl0_ssid")
        status_output, _, status_code = router.execute_command(
            f"wl -i {wl0_if} status 2>/dev/null"
        )

        result += "2.4GHz Radio (wl0)\n"
        result += "-" * 70 + "\n"
        result += f"Interface: {wl0_if}\n"
        result += f"SSID: {ssid_output.strip()}\n"

        if status_code == 0 and status_output:
            result += status_output + "\n"
        else:
            result += "Status: Unable to retrieve detailed status\n"
    else:
        result += "2.4GHz Radio: Not configured\n"

    result += "\n"

    # 5GHz Radio (wl1)
    if wl1_if:
        ssid_output, _, _ = router.execute_command("nvram get wl1_ssid")
        status_output, _, status_code = router.execute_command(
            f"wl -i {wl1_if} status 2>/dev/null"
        )

        result += "5GHz Radio (wl1)\n"
        result += "-" * 70 + "\n"
        result += f"Interface: {wl1_if}\n"
        result += f"SSID: {ssid_output.strip()}\n"

        if status_code == 0 and status_output:
            result += status_output + "\n"
        else:
            result += "Status: Unable to retrieve detailed status\n"
    else:
        result += "5GHz Radio: Not configured\n"

    result += "\n" + "=" * 70 + "\n"

    return [TextContent(type="text", text=result)]


def handle_restart_service(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """Restart a specific router service (e.g., wireless, vpnclient1, httpd)."""
    service = arguments.get("service_name")
    output, error, code = router.execute_command(f"service restart_{service}")
    result = f"Service '{service}' restart command executed.\n{output}"
    if error:
        result += f"\nErrors: {error}"
    return [TextContent(type="text", text=result)]


def handle_reboot_router(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """Reboot the router. WARNING: This will disconnect all clients."""
    if not arguments.get("confirm"):
        return [
            TextContent(
                type="text", text="Reboot not confirmed. Set 'confirm' to true."
            )
        ]
    output, error, code = router.execute_command("service reboot")
    return [
        TextContent(
            type="text",
            text="Router reboot initiated. Connection will be lost.",
        )
    ]


def handle_get_nvram_variable(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """Get the value of a specific NVRAM variable."""
    var = arguments.get("variable_name")
    output, error, code = router.execute_command(f"nvram get {var}")
    return [
        TextContent(
            type="text", text=output.strip() if code == 0 else f"Error: {error}"
        )
    ]


def handle_set_nvram_variable(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """Set a NVRAM variable value. WARNING: Incorrect values can break router configuration."""
    var = arguments.get("variable_name")
    val = arguments.get("value")
    commit = arguments.get("commit", False)

    cmd = f"nvram set {var}='{val}'"
    if commit:
        cmd += " && nvram commit"

    output, error, code = router.execute_command(cmd)
    result = f"NVRAM variable '{var}' set to '{val}'"
    if commit:
        result += " and committed to permanent storage"
    if error:
        result += f"\nErrors: {error}"
    return [TextContent(type="text", text=result)]


def handle_execute_command(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """Execute a custom command on the router via SSH."""
    cmd = arguments.get("command")
    output, error, code = router.execute_command(cmd)
    result = f"Command: {cmd}\n\nOutput:\n{output}"
    if error:
        result += f"\n\nErrors:\n{error}"
    result += f"\n\nExit code: {code}"
    return [TextContent(type="text", text=result)]


def handle_read_file(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """Read contents of a file on the router."""
    path = arguments.get("file_path")
    max_lines = arguments.get("max_lines", 100)
    output, error, code = router.execute_command(f"head -n {max_lines} {path}")
    return [TextContent(type="text", text=output if code == 0 else f"Error: {error}")]


def handle_upload_file(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """Upload a file to the router via SCP."""
    local = arguments.get("local_path")
    remote = arguments.get("remote_path")

    # Try SFTP first
    success, message = router.upload_file(local, remote)

    # If SFTP fails, try shell-based fallback
    if not success and "SFTP" in message:
        logger.info("SFTP unavailable, falling back to shell-based upload")
        success, message = router.upload_file_shell(local, remote)
        if success:
            result = f"✓ File uploaded successfully: {local} -> {remote}\n"
            result += "Note: Used shell commands (SFTP not available on router)\n"
            result += f"Details: {message}"
        else:
            result = f"✗ File upload failed: {local} -> {remote}\n"
            result += f"Error: {message}"
    elif success:
        result = f"✓ File uploaded successfully: {local} -> {remote}\n"
        result += "Method: SFTP\n"
        result += f"Details: {message}"
    else:
        result = f"✗ File upload failed: {local} -> {remote}\n"
        result += f"Error: {message}"

    return [TextContent(type="text", text=result)]


def handle_download_file(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """Download a file from the router via SCP."""
    remote = arguments.get("remote_path")
    local = arguments.get("local_path")

    # Try SFTP first
    success, message = router.download_file(remote, local)

    # If SFTP fails, try shell-based fallback
    if not success and "SFTP" in message:
        logger.info("SFTP unavailable, falling back to shell-based download")
        success, message = router.download_file_shell(remote, local)
        if success:
            result = f"✓ File downloaded successfully: {remote} -> {local}\n"
            result += "Note: Used shell commands (SFTP not available on router)\n"
            result += f"Details: {message}"
        else:
            result = f"✗ File download failed: {remote} -> {local}\n"
            result += f"Error: {message}"
    elif success:
        result = f"✓ File downloaded successfully: {remote} -> {local}\n"
        result += "Method: SFTP\n"
        result += f"Details: {message}"
    else:
        result = f"✗ File download failed: {remote} -> {local}\n"
        result += f"Error: {message}"

    return [TextContent(type="text", text=result)]


def handle_get_vpn_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """Get status of VPN clients and servers."""
    output, error, code = router.execute_command(
        "nvram get vpn_client1_state; nvram get vpn_client2_state; ps | grep vpn"
    )
    return [TextContent(type="text", text=output if code == 0 else f"Error: {error}")]


def handle_get_aiprotection_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    Get AiProtection (Trend Micro) security status.

    Returns status of:
    - AiProtection enabled/disabled
    - Malicious Sites Blocking
    - Two-Way IPS (Intrusion Prevention System)
    - Infected Device Prevention and Blocking
    """
    # Get all AiProtection NVRAM variables
    output, error, code = router.execute_command(
        "nvram get TM_EULA; "
        "nvram get wrs_protect_enable; "
        "nvram get wrs_mals_enable; "
        "nvram get wrs_vp_enable; "
        "nvram get wrs_cc_enable; "
        "nvram get wrs_mals_t; "
        "nvram get wrs_vp_t; "
        "nvram get wrs_cc_t; "
        "nvram get bwdpi_sig_ver"
    )

    if code != 0:
        return [
            TextContent(type="text", text=f"Error reading AiProtection status: {error}")
        ]

    # Parse the output
    lines = output.strip().split("\n")
    if len(lines) < 9:
        return [TextContent(type="text", text="Error: Unexpected NVRAM output format")]

    tm_eula = lines[0].strip()
    wrs_protect_enable = lines[1].strip()
    wrs_mals_enable = lines[2].strip()
    wrs_vp_enable = lines[3].strip()
    wrs_cc_enable = lines[4].strip()
    wrs_mals_t = lines[5].strip()
    wrs_vp_t = lines[6].strip()
    wrs_cc_t = lines[7].strip()
    sig_ver = lines[8].strip()

    # Format the output
    result = "AiProtection Status\n"
    result += "=" * 70 + "\n\n"

    # Overall status
    if tm_eula == "1":
        result += "✓ Trend Micro EULA: Accepted\n"
    else:
        result += "✗ Trend Micro EULA: Not Accepted\n"

    if wrs_protect_enable == "1":
        result += "✓ AiProtection: ENABLED\n"
    else:
        result += "✗ AiProtection: DISABLED\n"

    result += "\n" + "-" * 70 + "\n"
    result += "Protection Modules\n"
    result += "-" * 70 + "\n\n"

    # Malicious Sites Blocking
    status = "ON" if wrs_mals_enable == "1" else "OFF"
    result += f"1. Malicious Sites Blocking: {status}\n"
    if wrs_mals_t and wrs_mals_t != "0":
        import time

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(wrs_mals_t)))
        result += f"   Last update: {timestamp}\n"

    # Two-Way IPS
    status = "ON" if wrs_vp_enable == "1" else "OFF"
    result += f"\n2. Two-Way IPS (Intrusion Prevention): {status}\n"
    if wrs_vp_t and wrs_vp_t != "0":
        import time

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(wrs_vp_t)))
        result += f"   Last update: {timestamp}\n"

    # Infected Device Prevention
    status = "ON" if wrs_cc_enable == "1" else "OFF"
    result += f"\n3. Infected Device Prevention and Blocking: {status}\n"
    if wrs_cc_t and wrs_cc_t != "0":
        import time

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(wrs_cc_t)))
        result += f"   Last update: {timestamp}\n"

    # Signature version
    result += "\n" + "-" * 70 + "\n"
    result += "Threat Database\n"
    result += "-" * 70 + "\n"
    result += f"Signature Version: {sig_ver}\n"

    result += (
        "\nNote: Protection event counts are available through the router's web UI.\n"
    )
    result += "Event logs may be stored in /tmp/bwdpi/ or /jffs/ directories.\n"

    return [TextContent(type="text", text=result)]


def handle_get_system_log(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """
    Get system log entries from the router.

    Args:
        router: RouterSSHClient instance for executing commands
        arguments: Dict containing:
            - lines: Number of lines to retrieve (default: 100, max: 1000)
            - filter: Optional grep filter pattern

    Returns:
        List containing TextContent with log entries and configuration
    """
    lines = arguments.get("lines", 100)
    filter_pattern = arguments.get("filter", "")

    # Validate lines parameter
    if lines < 1:
        lines = 100
    elif lines > 1000:
        lines = 1000

    # Get log configuration settings
    config_output, _, config_code = router.execute_command(
        "nvram get message_loglevel; "
        "nvram get log_level; "
        "nvram get log_ipaddr; "
        "nvram get log_port"
    )

    # Build log retrieval command
    if filter_pattern:
        cmd = f"tail -n {lines} /tmp/syslog.log | grep '{filter_pattern}'"
    else:
        cmd = f"tail -n {lines} /tmp/syslog.log"

    output, error, code = router.execute_command(cmd)

    if code != 0:
        return [TextContent(type="text", text=f"Error reading system log: {error}")]

    # Build result with configuration header
    result = "System Log Configuration\n"
    result += "=" * 70 + "\n\n"

    # Parse log configuration
    if config_code == 0:
        config_lines = config_output.strip().split("\n")
        if len(config_lines) >= 4:
            message_loglevel = config_lines[0].strip()
            log_level = config_lines[1].strip()
            log_ipaddr = config_lines[2].strip()
            log_port = config_lines[3].strip()

            # Map message_loglevel to name
            loglevel_map = {
                "0": "emergency",
                "1": "alert",
                "2": "critical",
                "3": "error",
                "4": "warning",
                "5": "notice",
                "6": "info",
                "7": "debug",
            }
            loglevel_name = loglevel_map.get(message_loglevel, message_loglevel)

            # Map log_level to name
            urgency_map = {
                "0": "emergency",
                "1": "alert",
                "2": "critical",
                "3": "error",
                "4": "warning",
                "5": "notice",
                "6": "info",
                "7": "debug",
                "8": "all",
            }
            urgency_name = urgency_map.get(log_level, log_level)

            result += f"Message Log Level: {loglevel_name} ({message_loglevel})\n"
            result += f"Urgency Level: {urgency_name} ({log_level})\n"

            # Remote log server
            if log_ipaddr and log_ipaddr != "":
                result += f"\nRemote Log Server: {log_ipaddr}:{log_port}\n"
            else:
                result += "\nRemote Log Server: Not configured\n"

    result += "\n" + "=" * 70 + "\n"
    result += f"Log Entries (last {lines} lines"
    if filter_pattern:
        result += f", filtered by '{filter_pattern}'"
    result += ")\n"
    result += "=" * 70 + "\n\n"
    result += output

    return [TextContent(type="text", text=result)]


def handle_set_system_log_config(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Configure system log settings.

    Args:
        router: RouterSSHClient instance for executing commands
        arguments: Dict containing (all optional):
            - message_loglevel: Message log level (0-7 or name: emergency/alert/critical/error/warning/notice/info/debug)
            - log_level: Urgency level (0-8 or name: same as above plus 'all')
            - log_ipaddr: Remote syslog server IP (empty string to disable)
            - log_port: Remote syslog server port (default: 514)

    Returns:
        List containing TextContent with configuration result
    """
    # Level name to number mapping
    level_map = {
        "emergency": "0",
        "alert": "1",
        "critical": "2",
        "error": "3",
        "warning": "4",
        "notice": "5",
        "info": "6",
        "debug": "7",
        "all": "8",
    }

    changes = []
    nvram_commands = []

    # Process message_loglevel
    if "message_loglevel" in arguments:
        value = arguments["message_loglevel"]
        # Convert name to number if needed
        if isinstance(value, str) and value.lower() in level_map:
            value = level_map[value.lower()]
        # Validate range (0-7)
        try:
            num_value = int(value)
            if 0 <= num_value <= 7:
                nvram_commands.append(f"nvram set message_loglevel={num_value}")
                changes.append(f"Message Log Level: {value}")
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Error: message_loglevel must be 0-7, got {value}",
                    )
                ]
        except ValueError:
            return [
                TextContent(
                    type="text",
                    text=f"Error: Invalid message_loglevel value: {value}",
                )
            ]

    # Process log_level (urgency)
    if "log_level" in arguments:
        value = arguments["log_level"]
        # Convert name to number if needed
        if isinstance(value, str) and value.lower() in level_map:
            value = level_map[value.lower()]
        # Validate range (0-8)
        try:
            num_value = int(value)
            if 0 <= num_value <= 8:
                nvram_commands.append(f"nvram set log_level={num_value}")
                changes.append(f"Urgency Level: {value}")
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Error: log_level must be 0-8, got {value}",
                    )
                ]
        except ValueError:
            return [
                TextContent(
                    type="text", text=f"Error: Invalid log_level value: {value}"
                )
            ]

    # Process log_ipaddr
    if "log_ipaddr" in arguments:
        value = arguments["log_ipaddr"]
        nvram_commands.append(f"nvram set log_ipaddr='{value}'")
        if value:
            changes.append(f"Remote Log Server IP: {value}")
        else:
            changes.append("Remote Log Server: Disabled")

    # Process log_port
    if "log_port" in arguments:
        value = arguments["log_port"]
        try:
            port = int(value)
            if 1 <= port <= 65535:
                nvram_commands.append(f"nvram set log_port={port}")
                changes.append(f"Remote Log Server Port: {port}")
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Error: log_port must be 1-65535, got {value}",
                    )
                ]
        except ValueError:
            return [
                TextContent(type="text", text=f"Error: Invalid log_port value: {value}")
            ]

    # If no changes, return error
    if not changes:
        return [
            TextContent(
                type="text",
                text="Error: No configuration changes specified. Provide at least one of: message_loglevel, log_level, log_ipaddr, log_port",
            )
        ]

    # Execute NVRAM commands
    cmd = "; ".join(nvram_commands)
    output, error, code = router.execute_command(cmd)

    if code != 0:
        return [
            TextContent(type="text", text=f"Error setting log configuration: {error}")
        ]

    # Restart syslog to apply changes
    restart_output, restart_error, restart_code = router.execute_command(
        "service restart_logger"
    )

    result = "✓ System Log Configuration Updated\n"
    result += "=" * 70 + "\n\n"
    result += "Changes applied:\n"
    for change in changes:
        result += f"  • {change}\n"

    if restart_code == 0:
        result += "\n✓ Logger service restarted (changes applied)"
    else:
        result += f"\n⚠ Logger service restart failed: {restart_error}"
        result += "\nNote: You may need to manually restart the logger service"

    return [TextContent(type="text", text=result)]


def handle_list_processes(router: RouterSSHClient, arguments: Any) -> list[TextContent]:
    """List running processes on the router."""
    filter_name = arguments.get("filter", "")
    cmd = "ps" if not filter_name else f"ps | grep {filter_name}"
    output, error, code = router.execute_command(cmd)
    return [TextContent(type="text", text=output if code == 0 else f"Error: {error}")]
