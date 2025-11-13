"""
Network Service Filter tool handlers for ASUS Merlin MCP server.

This module provides tools for managing Network Service Filters (LAN-to-WAN packet filtering)
to restrict specific network services by source/destination IP and port.

Features:
- Deny List (Black List): Block specific services during scheduled times
- Allow List (White List): Allow only specific services during scheduled times
- Filter by source IP, destination IP, port, and protocol
- Scheduling support (days and time ranges)
"""

from typing import Any

from mcp.types import TextContent

from config.constants import (
    NVRAM_FILTER_LW_DATE,
    NVRAM_FILTER_LW_DEFAULT,
    NVRAM_FILTER_LW_ENABLE,
    NVRAM_FILTER_LW_LIST,
    NVRAM_FILTER_LW_TIME,
    NVRAM_FILTER_LW_TIME2,
    NVRAM_FILTER_WL_DATE,
    NVRAM_FILTER_WL_DEFAULT,
    NVRAM_FILTER_WL_ENABLE,
    NVRAM_FILTER_WL_LIST,
    NVRAM_FILTER_WL_TIME,
    NVRAM_FILTER_WL_TIME2,
    NETWORK_SERVICE_FILTER_MAX_RULES,
)
from core.ssh_client import RouterSSHClient
from utils.validators import is_valid_ip


def parse_service_filter_rules(rulelist_value: str) -> list[dict]:
    """
    Parse network service filter rulelist into list of rule dictionaries.

    Format: <source_ip>source_port>dest_ip>dest_port>protocol
    Multiple rules separated by '<'

    Args:
        rulelist_value: NVRAM filter_lwlist or filter_wllist value

    Returns:
        List of rule dictionaries with keys: source_ip, source_port, dest_ip, dest_port, protocol
    """
    if not rulelist_value or rulelist_value.strip() == "":
        return []

    rules = []
    # Split by '<' to get individual rules (filter out empty strings)
    rule_blocks = [block for block in rulelist_value.split("<") if block.strip()]

    for block in rule_blocks:
        # Each block is like: "192.168.0.7>80>8.8.8.4>80>TCP"
        parts = block.rstrip(">").split(">")

        if len(parts) >= 5:
            rules.append(
                {
                    "source_ip": parts[0].strip(),
                    "source_port": parts[1].strip(),
                    "dest_ip": parts[2].strip(),
                    "dest_port": parts[3].strip(),
                    "protocol": parts[4].strip().upper(),
                }
            )

    return rules


def build_service_filter_rules(rules: list[dict]) -> str:
    """
    Build network service filter rulelist from list of rule dictionaries.

    Args:
        rules: List of rule dicts with keys: source_ip, source_port, dest_ip, dest_port, protocol

    Returns:
        NVRAM-formatted filter_lwlist/filter_wllist string
    """
    if not rules:
        return ""

    # Each rule becomes: <source_ip>source_port>dest_ip>dest_port>protocol
    formatted_rules = []
    for rule in rules:
        formatted_rule = (
            f"<{rule['source_ip']}>{rule['source_port']}>"
            f"{rule['dest_ip']}>{rule['dest_port']}>{rule['protocol']}"
        )
        formatted_rules.append(formatted_rule)

    return "".join(formatted_rules)


def format_time_range(time_str: str, time2_str: str) -> str:
    """
    Format time range from NVRAM time values.

    Args:
        time_str: Weekday time (HHMM format, e.g., "00002359")
        time2_str: Weekend time (HHMM format)

    Returns:
        Human-readable time range string
    """
    if not time_str or len(time_str) < 8:
        return "Always active"

    # Parse weekday time: "00002359" -> "0000" to "2359"
    start_hour = time_str[0:2]
    start_min = time_str[2:4]
    end_hour = time_str[4:6]
    end_min = time_str[6:8]

    weekday_range = f"{start_hour}:{start_min}-{end_hour}:{end_min}"

    # Check if weekend time is different
    if time2_str and time2_str != time_str:
        start_hour2 = time2_str[0:2]
        start_min2 = time2_str[2:4]
        end_hour2 = time2_str[4:6]
        end_min2 = time2_str[6:8]
        weekend_range = f"{start_hour2}:{start_min2}-{end_hour2}:{end_min2}"
        return f"Mon-Fri: {weekday_range}, Sat-Sun: {weekend_range}"

    return f"All days: {weekday_range}"


def format_days(date_str: str) -> str:
    """
    Format active days from NVRAM date value.

    Args:
        date_str: 7-digit string (Sun-Sat, 1=active, 0=inactive)

    Returns:
        Human-readable days string
    """
    if not date_str or len(date_str) < 7:
        return "All days"

    days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    active_days = [days[i] for i in range(7) if date_str[i] == "1"]

    if len(active_days) == 7:
        return "All days"
    elif not active_days:
        return "No days"
    else:
        return ", ".join(active_days)


def handle_get_network_service_filter_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """
    Get network service filter status and configuration.

    Shows:
    - Deny list and allow list status
    - Number of rules configured
    - Schedule information
    - Default actions

    Args:
        router: RouterSSHClient instance
        _arguments: Not used

    Returns:
        list[TextContent]: Formatted status information
    """
    # Get deny list (LW) settings
    lw_enable_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_FILTER_LW_ENABLE}"
    )
    lw_list_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_LW_LIST}")
    lw_date_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_LW_DATE}")
    lw_time_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_LW_TIME}")
    lw_time2_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_LW_TIME2}")
    lw_default_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_FILTER_LW_DEFAULT}"
    )

    # Get allow list (WL) settings
    wl_enable_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_FILTER_WL_ENABLE}"
    )
    wl_list_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_WL_LIST}")
    wl_date_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_WL_DATE}")
    wl_time_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_WL_TIME}")
    wl_time2_output, _, _ = router.execute_command(f"nvram get {NVRAM_FILTER_WL_TIME2}")
    wl_default_output, _, _ = router.execute_command(
        f"nvram get {NVRAM_FILTER_WL_DEFAULT}"
    )

    lw_enabled = lw_enable_output.strip() == "1"
    wl_enabled = wl_enable_output.strip() == "1"

    lw_rules = parse_service_filter_rules(lw_list_output.strip())
    wl_rules = parse_service_filter_rules(wl_list_output.strip())

    result = "🚦 NETWORK SERVICE FILTER STATUS\n\n"

    # Deny List (Black List)
    result += "━━━ DENY LIST (Black List) ━━━\n"
    result += f"Status: {'✓ ENABLED' if lw_enabled else '✗ DISABLED'}\n"
    result += f"Rules: {len(lw_rules)}/{NETWORK_SERVICE_FILTER_MAX_RULES}\n"
    result += f"Default Action: {lw_default_output.strip()}\n"
    result += f"Active Days: {format_days(lw_date_output.strip())}\n"
    result += f"Time Range: {format_time_range(lw_time_output.strip(), lw_time2_output.strip())}\n"

    if lw_rules:
        result += "\nDENY LIST RULES:\n"
        for i, rule in enumerate(lw_rules, 1):
            src = (
                f"{rule['source_ip']}:{rule['source_port']}"
                if rule["source_ip"]
                else "ANY"
            )
            dst = f"{rule['dest_ip']}:{rule['dest_port']}"
            result += f"  {i}. {src} → {dst} ({rule['protocol']})\n"

    result += "\n━━━ ALLOW LIST (White List) ━━━\n"
    result += f"Status: {'✓ ENABLED' if wl_enabled else '✗ DISABLED'}\n"
    result += f"Rules: {len(wl_rules)}/{NETWORK_SERVICE_FILTER_MAX_RULES}\n"
    result += f"Default Action: {wl_default_output.strip()}\n"
    result += f"Active Days: {format_days(wl_date_output.strip())}\n"
    result += f"Time Range: {format_time_range(wl_time_output.strip(), wl_time2_output.strip())}\n"

    if wl_rules:
        result += "\nALLOW LIST RULES:\n"
        for i, rule in enumerate(wl_rules, 1):
            src = (
                f"{rule['source_ip']}:{rule['source_port']}"
                if rule["source_ip"]
                else "ANY"
            )
            dst = f"{rule['dest_ip']}:{rule['dest_port']}"
            result += f"  {i}. {src} → {dst} ({rule['protocol']})\n"

    result += "\n💡 INFO:\n"
    result += "  - Deny List: Blocks listed services during schedule\n"
    result += "  - Allow List: Only allows listed services during schedule\n"
    result += "  - Leave source IP blank to apply to all LAN devices\n"

    return [TextContent(type="text", text=result)]


def handle_list_network_service_filter_rules(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    List network service filter rules for specified list type.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with 'list_type' key ('deny' or 'allow')

    Returns:
        list[TextContent]: List of filter rules
    """
    list_type = arguments.get("list_type", "deny").strip().lower()

    if list_type not in ["deny", "allow"]:
        return [
            TextContent(type="text", text="Error: list_type must be 'deny' or 'allow'")
        ]

    # Select appropriate NVRAM variables based on list type
    if list_type == "deny":
        enable_var = NVRAM_FILTER_LW_ENABLE
        list_var = NVRAM_FILTER_LW_LIST
        title = "DENY LIST (Black List)"
        icon = "🚫"
    else:
        enable_var = NVRAM_FILTER_WL_ENABLE
        list_var = NVRAM_FILTER_WL_LIST
        title = "ALLOW LIST (White List)"
        icon = "✅"

    # Get settings
    enable_output, _, _ = router.execute_command(f"nvram get {enable_var}")
    list_output, _, _ = router.execute_command(f"nvram get {list_var}")

    enabled = enable_output.strip() == "1"
    rules = parse_service_filter_rules(list_output.strip())

    result = f"{icon} NETWORK SERVICE FILTER - {title}\n\n"
    result += f"Status: {'✓ ENABLED' if enabled else '✗ DISABLED'}\n"
    result += f"Total Rules: {len(rules)}/{NETWORK_SERVICE_FILTER_MAX_RULES}\n\n"

    if not rules:
        result += "No rules configured.\n"
    else:
        result += "CONFIGURED RULES:\n"
        for i, rule in enumerate(rules, 1):
            src = (
                f"{rule['source_ip']}:{rule['source_port']}"
                if rule["source_ip"]
                else "ANY"
            )
            dst = f"{rule['dest_ip']}:{rule['dest_port']}"
            result += f"  {i}. {src} → {dst} ({rule['protocol']})\n"

    return [TextContent(type="text", text=result)]


def handle_add_network_service_filter_rule(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Add network service filter rule to deny or allow list.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with keys:
            - list_type: 'deny' or 'allow'
            - source_ip: Source IP (optional, blank = all devices)
            - source_port: Source port or range (optional)
            - dest_ip: Destination IP (optional)
            - dest_port: Destination port or range
            - protocol: TCP, UDP, or specific TCP flags

    Returns:
        list[TextContent]: Success or error message
    """
    list_type = arguments.get("list_type", "deny").strip().lower()
    source_ip = arguments.get("source_ip", "").strip()
    source_port = arguments.get("source_port", "").strip()
    dest_ip = arguments.get("dest_ip", "").strip()
    dest_port = arguments.get("dest_port", "").strip()
    protocol = arguments.get("protocol", "TCP").strip().upper()

    # Validate list type
    if list_type not in ["deny", "allow"]:
        return [
            TextContent(type="text", text="Error: list_type must be 'deny' or 'allow'")
        ]

    # Validate required fields
    if not dest_port:
        return [TextContent(type="text", text="Error: dest_port is required")]

    # Validate protocol
    valid_protocols = [
        "TCP",
        "UDP",
        "TCPSYN",
        "TCPACK",
        "TCPFIN",
        "TCPRST",
        "TCPURG",
        "TCPPSH",
    ]
    if protocol not in valid_protocols:
        return [
            TextContent(
                type="text",
                text=f"Error: protocol must be one of {', '.join(valid_protocols)}",
            )
        ]

    # Validate IPs if provided
    if source_ip and not is_valid_ip(source_ip):
        return [TextContent(type="text", text=f"Error: Invalid source IP: {source_ip}")]

    if dest_ip and not is_valid_ip(dest_ip):
        return [
            TextContent(type="text", text=f"Error: Invalid destination IP: {dest_ip}")
        ]

    # Select appropriate NVRAM variables
    if list_type == "deny":
        enable_var = NVRAM_FILTER_LW_ENABLE
        list_var = NVRAM_FILTER_LW_LIST
    else:
        enable_var = NVRAM_FILTER_WL_ENABLE
        list_var = NVRAM_FILTER_WL_LIST

    # Get current rules
    list_output, _, _ = router.execute_command(f"nvram get {list_var}")
    current_rules = parse_service_filter_rules(list_output.strip())

    # Check limit
    if len(current_rules) >= NETWORK_SERVICE_FILTER_MAX_RULES:
        return [
            TextContent(
                type="text",
                text=f"Error: Maximum {NETWORK_SERVICE_FILTER_MAX_RULES} rules already configured",
            )
        ]

    # Create new rule
    new_rule = {
        "source_ip": source_ip,
        "source_port": source_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "protocol": protocol,
    }

    # Check for duplicates
    for rule in current_rules:
        if (
            rule["source_ip"] == source_ip
            and rule["source_port"] == source_port
            and rule["dest_ip"] == dest_ip
            and rule["dest_port"] == dest_port
            and rule["protocol"] == protocol
        ):
            return [
                TextContent(type="text", text="Error: Identical rule already exists")
            ]

    # Add new rule
    current_rules.append(new_rule)

    # Build new rulelist
    new_rulelist = build_service_filter_rules(current_rules)

    # Set new rulelist and enable filter
    router.execute_command(f'nvram set {list_var}="{new_rulelist}"')
    router.execute_command(f"nvram set {enable_var}=1")
    router.execute_command("nvram commit")

    # Restart firewall to apply changes
    router.execute_command("service restart_firewall")

    src_display = f"{source_ip}:{source_port}" if source_ip else "ANY"
    dst_display = f"{dest_ip}:{dest_port}" if dest_ip else f"ANY:{dest_port}"

    result = f"✓ Network Service Filter Rule Added ({list_type.upper()} LIST)\n\n"
    result += f"Rule: {src_display} → {dst_display} ({protocol})\n"
    result += f"Total rules: {len(current_rules)}/{NETWORK_SERVICE_FILTER_MAX_RULES}\n"
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


def handle_remove_network_service_filter_rule(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Remove network service filter rule from deny or allow list.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with keys matching rule to remove:
            - list_type: 'deny' or 'allow'
            - source_ip: Source IP (must match exactly)
            - source_port: Source port (must match exactly)
            - dest_ip: Destination IP (must match exactly)
            - dest_port: Destination port (must match exactly)
            - protocol: Protocol (must match exactly)

    Returns:
        list[TextContent]: Success or error message
    """
    list_type = arguments.get("list_type", "deny").strip().lower()
    source_ip = arguments.get("source_ip", "").strip()
    source_port = arguments.get("source_port", "").strip()
    dest_ip = arguments.get("dest_ip", "").strip()
    dest_port = arguments.get("dest_port", "").strip()
    protocol = arguments.get("protocol", "").strip().upper()

    # Validate list type
    if list_type not in ["deny", "allow"]:
        return [
            TextContent(type="text", text="Error: list_type must be 'deny' or 'allow'")
        ]

    # Select appropriate NVRAM variables
    if list_type == "deny":
        list_var = NVRAM_FILTER_LW_LIST
    else:
        list_var = NVRAM_FILTER_WL_LIST

    # Get current rules
    list_output, _, _ = router.execute_command(f"nvram get {list_var}")
    current_rules = parse_service_filter_rules(list_output.strip())

    # Find and remove matching rule
    found = False
    updated_rules = []
    for rule in current_rules:
        if (
            rule["source_ip"] == source_ip
            and rule["source_port"] == source_port
            and rule["dest_ip"] == dest_ip
            and rule["dest_port"] == dest_port
            and rule["protocol"] == protocol
        ):
            found = True
            continue
        updated_rules.append(rule)

    if not found:
        return [
            TextContent(type="text", text="Error: No matching rule found to remove")
        ]

    # Build new rulelist
    new_rulelist = build_service_filter_rules(updated_rules)

    # Set new rulelist
    router.execute_command(f'nvram set {list_var}="{new_rulelist}"')
    router.execute_command("nvram commit")

    # Restart firewall to apply changes
    router.execute_command("service restart_firewall")

    src_display = f"{source_ip}:{source_port}" if source_ip else "ANY"
    dst_display = f"{dest_ip}:{dest_port}" if dest_ip else f"ANY:{dest_port}"

    result = f"✓ Network Service Filter Rule Removed ({list_type.upper()} LIST)\n\n"
    result += f"Removed: {src_display} → {dst_display} ({protocol})\n"
    result += (
        f"Remaining rules: {len(updated_rules)}/{NETWORK_SERVICE_FILTER_MAX_RULES}\n"
    )
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


def handle_set_network_service_filter_mode(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Enable/disable network service filter deny or allow list.

    Args:
        router: RouterSSHClient instance
        arguments: Dict with keys:
            - list_type: 'deny' or 'allow'
            - enabled: True to enable, False to disable

    Returns:
        list[TextContent]: Success message
    """
    list_type = arguments.get("list_type", "deny").strip().lower()
    enabled = arguments.get("enabled", True)

    if list_type not in ["deny", "allow"]:
        return [
            TextContent(type="text", text="Error: list_type must be 'deny' or 'allow'")
        ]

    # Select appropriate NVRAM variable
    if list_type == "deny":
        enable_var = NVRAM_FILTER_LW_ENABLE
    else:
        enable_var = NVRAM_FILTER_WL_ENABLE

    # Set enable/disable
    value = "1" if enabled else "0"
    router.execute_command(f"nvram set {enable_var}={value}")
    router.execute_command("nvram commit")

    # Restart firewall
    router.execute_command("service restart_firewall")

    status = "ENABLED" if enabled else "DISABLED"
    result = f"✓ Network Service Filter {list_type.upper()} LIST {status}\n\n"
    result += "Firewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]


def handle_set_network_service_filter_schedule(
    router: RouterSSHClient, arguments: Any
) -> list[TextContent]:
    """
    Configure network service filter schedule (days and time ranges).

    Args:
        router: RouterSSHClient instance
        arguments: Dict with keys:
            - list_type: 'deny' or 'allow'
            - days: 7-character string (Sun-Sat, 1=active, 0=inactive) e.g., "1111111"
            - weekday_start: Start time for Mon-Fri in HHMM format, e.g., "0800"
            - weekday_end: End time for Mon-Fri in HHMM format, e.g., "1700"
            - weekend_start: Start time for Sat-Sun (optional, defaults to weekday)
            - weekend_end: End time for Sat-Sun (optional, defaults to weekday)

    Returns:
        list[TextContent]: Success message
    """
    list_type = arguments.get("list_type", "deny").strip().lower()
    days = arguments.get("days", "1111111").strip()
    weekday_start = arguments.get("weekday_start", "0000").strip()
    weekday_end = arguments.get("weekday_end", "2359").strip()
    weekend_start = arguments.get("weekend_start", weekday_start).strip()
    weekend_end = arguments.get("weekend_end", weekday_end).strip()

    # Validate list type
    if list_type not in ["deny", "allow"]:
        return [
            TextContent(type="text", text="Error: list_type must be 'deny' or 'allow'")
        ]

    # Validate days format
    if len(days) != 7 or not all(c in "01" for c in days):
        return [
            TextContent(
                type="text",
                text="Error: days must be 7-character string of 0s and 1s (Sun-Sat)",
            )
        ]

    # Validate time formats
    for time_val, name in [
        (weekday_start, "weekday_start"),
        (weekday_end, "weekday_end"),
        (weekend_start, "weekend_start"),
        (weekend_end, "weekend_end"),
    ]:
        if len(time_val) != 4 or not time_val.isdigit():
            return [
                TextContent(
                    type="text",
                    text=f"Error: {name} must be 4-digit HHMM format (e.g., 0800)",
                )
            ]

    # Select appropriate NVRAM variables
    if list_type == "deny":
        date_var = NVRAM_FILTER_LW_DATE
        time_var = NVRAM_FILTER_LW_TIME
        time2_var = NVRAM_FILTER_LW_TIME2
    else:
        date_var = NVRAM_FILTER_WL_DATE
        time_var = NVRAM_FILTER_WL_TIME
        time2_var = NVRAM_FILTER_WL_TIME2

    # Build time strings: SSSSEEEE (start hour/min + end hour/min)
    weekday_time = f"{weekday_start}{weekday_end}"
    weekend_time = f"{weekend_start}{weekend_end}"

    # Set schedule
    router.execute_command(f"nvram set {date_var}={days}")
    router.execute_command(f"nvram set {time_var}={weekday_time}")
    router.execute_command(f"nvram set {time2_var}={weekend_time}")
    router.execute_command("nvram commit")

    # Restart firewall
    router.execute_command("service restart_firewall")

    result = f"✓ Network Service Filter Schedule Updated ({list_type.upper()} LIST)\n\n"
    result += f"Active Days: {format_days(days)}\n"
    result += f"Weekday Time: {weekday_start[:2]}:{weekday_start[2:]}-{weekday_end[:2]}:{weekday_end[2:]}\n"
    result += f"Weekend Time: {weekend_start[:2]}:{weekend_start[2:]}-{weekend_end[:2]}:{weekend_end[2:]}\n"
    result += "\nFirewall service restarted - changes applied"

    return [TextContent(type="text", text=result)]
