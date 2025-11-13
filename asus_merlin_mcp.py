#!/usr/bin/env python3
r"""
___  ____  _____   ____  _____ ____ _ __ _____
\  \/ (__)/  ___)_/    \/  _  )    | |  | ____)
 \    |  |  |(_  _) () |     (  () | |  |___  \
  \   |__|____   |\____|__|\  \____|____|      )
   \_/        `--'          `--'         \____/
        P  R  o  G  R  A  M  M  i  N  G
<========================================[KCS]=>
  Developer: Ken C. Soukup
  Project  : MCP Server for ASUS Router
  Purpose  : Use AI Agents for managing ASUS routers running Asuswrt-Merlin firmware via SSH/SCP.
<=================================[10/08/2025]=>
  Home:  Asuswrt-Merlin Firmware  --  https://www.asuswrt-merlin.net/
  Help:  SNBForums ASUS WiFi      --  https://www.snbforums.com/forums/asus-wi-fi.37/
"""

__project__ = "MCP Server for ASUS Router"
__version__ = "3.0.1"
__author__ = "Ken C. Soukup"
__company__ = "Vigorous Programming"
__minted__ = "2025"

import asyncio
import logging
from typing import Any, Sequence

import mcp.server.stdio
from mcp.server import Server
from mcp.types import EmbeddedResource, ImageContent, TextContent, Tool

# Import configuration
from config.router_config import ROUTER_CONFIG

# Import core infrastructure
from core.ssh_client import RouterSSHClient

# Import all tool handlers
from tools import (
    handle_add_dhcp_reservation,
    handle_add_keyword_filter,
    handle_add_mac_filter,
    handle_add_network_service_filter_rule,
    handle_add_url_filter,
    handle_add_vpn_routing_policy,
    handle_block_device_internet,
    handle_download_file,
    handle_execute_command,
    handle_get_aiprotection_status,
    handle_get_all_network_devices,
    handle_get_connected_devices,
    handle_get_firewall_status,
    handle_get_keyword_filter_status,
    handle_get_network_service_filter_status,
    handle_get_nvram_variable,
    handle_get_router_info,
    handle_get_system_log,
    handle_get_url_filter_status,
    handle_get_vpn_server_status,
    handle_get_vpn_server_users,
    handle_get_vpn_status,
    handle_get_wifi_status,
    handle_list_blocked_devices,
    handle_list_dhcp_reservations,
    handle_list_keyword_filters,
    handle_list_mac_filters,
    handle_list_network_service_filter_rules,
    handle_list_processes,
    handle_list_url_filters,
    handle_list_vpn_policies,
    handle_read_file,
    handle_reboot_router,
    handle_remove_dhcp_reservation,
    handle_remove_keyword_filter,
    handle_remove_mac_filter,
    handle_remove_network_service_filter_rule,
    handle_remove_url_filter,
    handle_remove_vpn_routing_policy,
    handle_restart_service,
    handle_set_firewall_config,
    handle_set_network_service_filter_mode,
    handle_set_network_service_filter_schedule,
    handle_set_nvram_variable,
    handle_set_system_log_config,
    handle_set_url_filter_mode,
    handle_upload_file,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("asus-merlin-mcp")

# Initialize MCP server and router connection
app = Server("asus-merlin-router")
router = RouterSSHClient(ROUTER_CONFIG)


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools for router management"""
    return [
        Tool(
            name="get_router_info",
            description="Get router system information (uptime, memory, CPU, firmware version)",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="get_connected_devices",
            description="List all devices connected to the router (via DHCP)",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="get_all_network_devices",
            description="Get comprehensive list of all network devices (DHCP + static + ARP) with detailed info",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter_type": {
                        "type": "string",
                        "enum": ["all", "dhcp", "static", "reservation"],
                        "description": "Filter by device type: 'all' (default), 'dhcp', 'static', or 'reservation'",
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="get_wifi_status",
            description="Get WiFi status for all radios (2.4GHz, 5GHz, etc.)",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="restart_service",
            description="Restart a specific router service (e.g., wireless, vpnclient1, httpd)",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Service to restart (wireless, vpnclient1, wan, httpd, etc.)",
                    }
                },
                "required": ["service_name"],
            },
        ),
        Tool(
            name="reboot_router",
            description="Reboot the router. WARNING: This will disconnect all clients.",
            inputSchema={
                "type": "object",
                "properties": {
                    "confirm": {
                        "type": "boolean",
                        "description": "Must be true to confirm reboot",
                    }
                },
                "required": ["confirm"],
            },
        ),
        Tool(
            name="get_nvram_variable",
            description="Get the value of a specific NVRAM variable",
            inputSchema={
                "type": "object",
                "properties": {
                    "variable_name": {
                        "type": "string",
                        "description": "NVRAM variable name to retrieve",
                    }
                },
                "required": ["variable_name"],
            },
        ),
        Tool(
            name="set_nvram_variable",
            description="Set a NVRAM variable value. WARNING: Incorrect values can break router configuration.",
            inputSchema={
                "type": "object",
                "properties": {
                    "variable_name": {
                        "type": "string",
                        "description": "NVRAM variable name",
                    },
                    "value": {"type": "string", "description": "Value to set"},
                    "commit": {
                        "type": "boolean",
                        "description": "Commit changes to permanent storage (default: false)",
                        "default": False,
                    },
                },
                "required": ["variable_name", "value"],
            },
        ),
        Tool(
            name="execute_command",
            description="Execute a custom command on the router via SSH. WARNING: NEVER use this for file operations (reading, writing, editing files). ALWAYS use read_file, upload_file, or download_file tools for file operations. Do NOT use heredoc (cat << EOF) or echo for file writes - use upload_file instead.",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute",
                    }
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="read_file",
            description="Read contents of a file on the router",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to file on router",
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Maximum number of lines to read (default: 100)",
                        "default": 100,
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="upload_file",
            description="Upload a file to the router via SCP with MD5 verification. Use this for creating or editing router files. Workflow: 1) download_file to get current content, 2) edit locally, 3) upload_file to save changes. NEVER use execute_command with heredoc for file edits.",
            inputSchema={
                "type": "object",
                "properties": {
                    "local_path": {"type": "string", "description": "Local file path"},
                    "remote_path": {
                        "type": "string",
                        "description": "Destination path on router (e.g., /jffs/scripts/)",
                    },
                },
                "required": ["local_path", "remote_path"],
            },
        ),
        Tool(
            name="download_file",
            description="Download a file from the router via SCP",
            inputSchema={
                "type": "object",
                "properties": {
                    "remote_path": {
                        "type": "string",
                        "description": "File path on router",
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Local destination path",
                    },
                },
                "required": ["remote_path", "local_path"],
            },
        ),
        Tool(
            name="get_vpn_status",
            description="Get status of VPN clients and servers",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="get_aiprotection_status",
            description="Get AiProtection (Trend Micro) security status including malicious sites blocking, two-way IPS, and infected device prevention",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="get_vpn_server_status",
            description="Get detailed VPN server status including connected clients",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="get_vpn_server_users",
            description="Get list of users authorized to connect to VPN servers",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="get_system_log",
            description="Get system log entries from the router with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "lines": {
                        "type": "integer",
                        "description": "Number of lines to retrieve (default: 100, max: 1000)",
                    },
                    "filter": {
                        "type": "string",
                        "description": "Optional: grep filter pattern to match specific log entries",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="set_system_log_config",
            description="Configure system log settings (log levels, remote syslog server)",
            inputSchema={
                "type": "object",
                "properties": {
                    "message_loglevel": {
                        "type": "string",
                        "description": "Message log level: 0-7 or name (emergency/alert/critical/error/warning/notice/info/debug)",
                    },
                    "log_level": {
                        "type": "string",
                        "description": "Urgency level: 0-8 or name (emergency/alert/critical/error/warning/notice/info/debug/all)",
                    },
                    "log_ipaddr": {
                        "type": "string",
                        "description": "Remote syslog server IP address (empty string to disable)",
                    },
                    "log_port": {
                        "type": "integer",
                        "description": "Remote syslog server port (default: 514)",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="list_processes",
            description="List running processes on the router",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Optional: filter processes by name",
                    }
                },
                "required": [],
            },
        ),
        # Firewall Tools
        Tool(
            name="get_firewall_status",
            description="Get comprehensive firewall status and configuration including main firewall, DoS protection, logging, WAN ping response, VPN passthrough settings, and IPv6 firewall",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="set_firewall_config",
            description="Configure firewall settings including enable/disable main firewall, DoS protection, logging mode, WAN ping response, IPv6 firewall, and VPN passthrough protocols (PPTP, L2TP, IPSec, RTSP, H.323, SIP, PPPoE)",
            inputSchema={
                "type": "object",
                "properties": {
                    "enable_firewall": {
                        "type": "boolean",
                        "description": "Enable/disable main firewall",
                    },
                    "enable_dos_protection": {
                        "type": "boolean",
                        "description": "Enable/disable DoS protection",
                    },
                    "log_mode": {
                        "type": "string",
                        "enum": ["none", "drop", "accept", "both"],
                        "description": "Firewall logging mode: none (disabled), drop (dropped packets only), accept (accepted packets only), both (all packets)",
                    },
                    "respond_to_wan_ping": {
                        "type": "boolean",
                        "description": "Respond to WAN ping requests (true=visible, false=stealthed)",
                    },
                    "enable_ipv6_firewall": {
                        "type": "boolean",
                        "description": "Enable/disable IPv6 firewall",
                    },
                    "vpn_passthrough": {
                        "type": "object",
                        "description": "VPN passthrough protocol settings",
                        "properties": {
                            "pptp": {
                                "type": "boolean",
                                "description": "Enable/disable PPTP passthrough",
                            },
                            "l2tp": {
                                "type": "boolean",
                                "description": "Enable/disable L2TP passthrough",
                            },
                            "ipsec": {
                                "type": "boolean",
                                "description": "Enable/disable IPSec passthrough",
                            },
                            "rtsp": {
                                "type": "boolean",
                                "description": "Enable/disable RTSP passthrough",
                            },
                            "h323": {
                                "type": "boolean",
                                "description": "Enable/disable H.323 passthrough",
                            },
                            "sip": {
                                "type": "boolean",
                                "description": "Enable/disable SIP passthrough",
                            },
                            "pppoe_relay": {
                                "type": "boolean",
                                "description": "Enable/disable PPPoE relay",
                            },
                        },
                    },
                },
                "required": [],
            },
        ),
        # URL/Keyword Filtering Tools
        Tool(
            name="get_url_filter_status",
            description="Get global URL filter status including enabled state, filter mode (blacklist/whitelist), number of rules, and schedule",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="add_url_filter",
            description="Add URL pattern to global filter list (blacklist or whitelist depending on mode)",
            inputSchema={
                "type": "object",
                "properties": {
                    "url_pattern": {
                        "type": "string",
                        "description": "URL pattern/keyword to filter (e.g., 'facebook', 'gaming', 'youtube.com')",
                    }
                },
                "required": ["url_pattern"],
            },
        ),
        Tool(
            name="remove_url_filter",
            description="Remove URL pattern from global filter list",
            inputSchema={
                "type": "object",
                "properties": {
                    "url_pattern": {
                        "type": "string",
                        "description": "URL pattern to remove from filter list",
                    }
                },
                "required": ["url_pattern"],
            },
        ),
        Tool(
            name="list_url_filters",
            description="List all configured URL filter rules with status and mode",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="set_url_filter_mode",
            description="Set URL filter mode to blacklist (block listed URLs) or whitelist (allow only listed URLs)",
            inputSchema={
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["blacklist", "whitelist"],
                        "description": "Filter mode: 'blacklist' blocks listed URLs, 'whitelist' allows only listed URLs",
                    }
                },
                "required": ["mode"],
            },
        ),
        Tool(
            name="get_keyword_filter_status",
            description="Get keyword filter status including enabled state, number of rules, and schedule",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="add_keyword_filter",
            description="Add keyword to filter list (blocks URLs containing the keyword)",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to block in URLs (e.g., 'facebook', 'game', 'video')",
                    }
                },
                "required": ["keyword"],
            },
        ),
        Tool(
            name="remove_keyword_filter",
            description="Remove keyword from filter list",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to remove from filter list",
                    }
                },
                "required": ["keyword"],
            },
        ),
        Tool(
            name="list_keyword_filters",
            description="List all configured keyword filter rules",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        # Network Service Filtering Tools
        Tool(
            name="get_network_service_filter_status",
            description="Get network service filter status including deny list and allow list configuration, rules, and schedule",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="list_network_service_filter_rules",
            description="List network service filter rules for deny or allow list",
            inputSchema={
                "type": "object",
                "properties": {
                    "list_type": {
                        "type": "string",
                        "description": "Filter list type: 'deny' (black list) or 'allow' (white list)",
                        "enum": ["deny", "allow"],
                    }
                },
                "required": ["list_type"],
            },
        ),
        Tool(
            name="add_network_service_filter_rule",
            description="Add network service filter rule to block/allow specific services by IP and port. Deny list blocks services during schedule. Allow list only allows services during schedule. Leave source IP blank to apply to all devices.",
            inputSchema={
                "type": "object",
                "properties": {
                    "list_type": {
                        "type": "string",
                        "description": "Filter list type: 'deny' (black list) or 'allow' (white list)",
                        "enum": ["deny", "allow"],
                    },
                    "source_ip": {
                        "type": "string",
                        "description": "Source IP address (optional, blank = all LAN devices)",
                    },
                    "source_port": {
                        "type": "string",
                        "description": "Source port or range (optional)",
                    },
                    "dest_ip": {
                        "type": "string",
                        "description": "Destination IP address (optional)",
                    },
                    "dest_port": {
                        "type": "string",
                        "description": "Destination port or range (e.g., '80', '1:1024')",
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol: TCP, UDP, or specific TCP flags (TCPSYN, TCPACK, etc.)",
                        "enum": [
                            "TCP",
                            "UDP",
                            "TCPSYN",
                            "TCPACK",
                            "TCPFIN",
                            "TCPRST",
                            "TCPURG",
                            "TCPPSH",
                        ],
                    },
                },
                "required": ["list_type", "dest_port"],
            },
        ),
        Tool(
            name="remove_network_service_filter_rule",
            description="Remove network service filter rule by matching all criteria exactly",
            inputSchema={
                "type": "object",
                "properties": {
                    "list_type": {
                        "type": "string",
                        "description": "Filter list type: 'deny' or 'allow'",
                        "enum": ["deny", "allow"],
                    },
                    "source_ip": {
                        "type": "string",
                        "description": "Source IP (must match exactly)",
                    },
                    "source_port": {
                        "type": "string",
                        "description": "Source port (must match exactly)",
                    },
                    "dest_ip": {
                        "type": "string",
                        "description": "Destination IP (must match exactly)",
                    },
                    "dest_port": {
                        "type": "string",
                        "description": "Destination port (must match exactly)",
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol (must match exactly)",
                    },
                },
                "required": ["list_type", "dest_port", "protocol"],
            },
        ),
        Tool(
            name="set_network_service_filter_mode",
            description="Enable or disable network service filter deny/allow list",
            inputSchema={
                "type": "object",
                "properties": {
                    "list_type": {
                        "type": "string",
                        "description": "Filter list type: 'deny' or 'allow'",
                        "enum": ["deny", "allow"],
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "True to enable, False to disable",
                    },
                },
                "required": ["list_type", "enabled"],
            },
        ),
        Tool(
            name="set_network_service_filter_schedule",
            description="Configure network service filter schedule (active days and time ranges). Format: days as 7-digit string (Sun-Sat, 1=active), times in HHMM format (e.g., 0800 for 8:00 AM)",
            inputSchema={
                "type": "object",
                "properties": {
                    "list_type": {
                        "type": "string",
                        "description": "Filter list type: 'deny' or 'allow'",
                        "enum": ["deny", "allow"],
                    },
                    "days": {
                        "type": "string",
                        "description": "7-character string (Sun-Sat), '1'=active, '0'=inactive. Example: '1111111' for all days",
                    },
                    "weekday_start": {
                        "type": "string",
                        "description": "Weekday start time in HHMM format (e.g., '0800' for 8:00 AM)",
                    },
                    "weekday_end": {
                        "type": "string",
                        "description": "Weekday end time in HHMM format (e.g., '1700' for 5:00 PM)",
                    },
                    "weekend_start": {
                        "type": "string",
                        "description": "Weekend start time (optional, defaults to weekday_start)",
                    },
                    "weekend_end": {
                        "type": "string",
                        "description": "Weekend end time (optional, defaults to weekday_end)",
                    },
                },
                "required": ["list_type", "days", "weekday_start", "weekday_end"],
            },
        ),
        # MAC Filtering Tools
        Tool(
            name="add_mac_filter",
            description="Add device to MAC filter (whitelist or blacklist) for WiFi access control",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac_address": {
                        "type": "string",
                        "description": "Device MAC address (format: XX:XX:XX:XX:XX:XX)",
                    },
                    "filter_type": {
                        "type": "string",
                        "enum": ["whitelist", "blacklist"],
                        "description": "Filter type: 'whitelist' (allow only) or 'blacklist' (deny only)",
                        "default": "blacklist",
                    },
                    "radio": {
                        "type": "string",
                        "enum": ["2.4ghz", "5ghz", "both"],
                        "description": "Radio band to apply filter: '2.4ghz', '5ghz', or 'both'",
                        "default": "both",
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional human-readable device description",
                    },
                },
                "required": ["mac_address"],
            },
        ),
        Tool(
            name="remove_mac_filter",
            description="Remove device from MAC filter",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac_address": {
                        "type": "string",
                        "description": "Device MAC address to remove",
                    },
                    "radio": {
                        "type": "string",
                        "enum": ["2.4ghz", "5ghz", "both"],
                        "description": "Radio band to remove from: '2.4ghz', '5ghz', or 'both'",
                        "default": "both",
                    },
                },
                "required": ["mac_address"],
            },
        ),
        Tool(
            name="list_mac_filters",
            description="Show current MAC filters with friendly formatting",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        # DHCP Management Tools
        Tool(
            name="add_dhcp_reservation",
            description="Reserve IP address for specific MAC address (static DHCP lease)",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac_address": {
                        "type": "string",
                        "description": "Device MAC address",
                    },
                    "ip_address": {
                        "type": "string",
                        "description": "IP address to reserve",
                    },
                    "dns": {
                        "type": "string",
                        "description": "DNS server (optional)",
                    },
                    "hostname": {
                        "type": "string",
                        "description": "Device hostname (optional)",
                    },
                },
                "required": ["mac_address", "ip_address"],
            },
        ),
        Tool(
            name="remove_dhcp_reservation",
            description="Remove DHCP reservation by MAC or IP address",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac_address": {
                        "type": "string",
                        "description": "Device MAC address (optional if ip_address provided)",
                    },
                    "ip_address": {
                        "type": "string",
                        "description": "IP address (optional if mac_address provided)",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="list_dhcp_reservations",
            description="Show all current DHCP reservations",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        # Internet Access Control Tools
        Tool(
            name="block_device_internet",
            description="Block or unblock device from internet access (parental controls)",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac_address": {
                        "type": "string",
                        "description": "Device MAC address",
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "True to block internet access, False to unblock",
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional device description",
                    },
                },
                "required": ["mac_address", "enabled"],
            },
        ),
        Tool(
            name="list_blocked_devices",
            description="Show devices with internet access restrictions",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        # VPN Policy Routing Tools (Asuswrt-Merlin only)
        Tool(
            name="add_vpn_routing_policy",
            description="Route specific device through VPN client using VPN Director (Asuswrt-Merlin firmware only). Adds device to VPN Director routing to route all its traffic through selected VPN client (1-5). Requires Merlin firmware - stock ASUS firmware not supported.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac_address": {
                        "type": "string",
                        "description": "Device MAC address (format: XX:XX:XX:XX:XX:XX)",
                    },
                    "vpn_client_number": {
                        "type": "integer",
                        "description": "VPN client to route through (1-5)",
                        "minimum": 1,
                        "maximum": 5,
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional rule description/hostname",
                    },
                },
                "required": ["mac_address", "vpn_client_number"],
            },
        ),
        Tool(
            name="remove_vpn_routing_policy",
            description="Remove device from VPN Director routing (Asuswrt-Merlin firmware only). Device will return to normal routing (no VPN). Requires Merlin firmware - stock ASUS firmware not supported.",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac_address": {
                        "type": "string",
                        "description": "Device MAC address to remove from VPN routing",
                    },
                },
                "required": ["mac_address"],
            },
        ),
        Tool(
            name="list_vpn_policies",
            description="List all VPN Director routing rules (Asuswrt-Merlin firmware only). Shows which devices are configured to route through which VPN clients. Requires Merlin firmware - stock ASUS firmware not supported.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
    ]


@app.call_tool()
async def call_tool(
    name: str, arguments: Any
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Route tool calls to appropriate handler functions"""

    try:
        # System Info Tools
        if name == "get_router_info":
            return handle_get_router_info(router, arguments)
        elif name == "get_connected_devices":
            return handle_get_connected_devices(router, arguments)
        elif name == "get_all_network_devices":
            return handle_get_all_network_devices(router, arguments)
        elif name == "get_wifi_status":
            return handle_get_wifi_status(router, arguments)
        elif name == "restart_service":
            return handle_restart_service(router, arguments)
        elif name == "reboot_router":
            return handle_reboot_router(router, arguments)
        elif name == "get_vpn_status":
            return handle_get_vpn_status(router, arguments)
        elif name == "get_aiprotection_status":
            return handle_get_aiprotection_status(router, arguments)
        elif name == "get_system_log":
            return handle_get_system_log(router, arguments)
        elif name == "set_system_log_config":
            return handle_set_system_log_config(router, arguments)
        elif name == "list_processes":
            return handle_list_processes(router, arguments)
        elif name == "get_nvram_variable":
            return handle_get_nvram_variable(router, arguments)
        elif name == "set_nvram_variable":
            return handle_set_nvram_variable(router, arguments)
        elif name == "execute_command":
            return handle_execute_command(router, arguments)
        elif name == "read_file":
            return handle_read_file(router, arguments)
        elif name == "upload_file":
            return handle_upload_file(router, arguments)
        elif name == "download_file":
            return handle_download_file(router, arguments)

        # Firewall Tools
        elif name == "get_firewall_status":
            return handle_get_firewall_status(router, arguments)
        elif name == "set_firewall_config":
            return handle_set_firewall_config(router, arguments)

        # MAC Filtering Tools
        elif name == "add_mac_filter":
            return handle_add_mac_filter(router, arguments)
        elif name == "remove_mac_filter":
            return handle_remove_mac_filter(router, arguments)
        elif name == "list_mac_filters":
            return handle_list_mac_filters(router, arguments)

        # DHCP Management Tools
        elif name == "add_dhcp_reservation":
            return handle_add_dhcp_reservation(router, arguments)
        elif name == "remove_dhcp_reservation":
            return handle_remove_dhcp_reservation(router, arguments)
        elif name == "list_dhcp_reservations":
            return handle_list_dhcp_reservations(router, arguments)

        # Internet Control Tools
        elif name == "block_device_internet":
            return handle_block_device_internet(router, arguments)
        elif name == "list_blocked_devices":
            return handle_list_blocked_devices(router, arguments)

        # VPN Routing Tools
        elif name == "add_vpn_routing_policy":
            return handle_add_vpn_routing_policy(router, arguments)
        elif name == "remove_vpn_routing_policy":
            return handle_remove_vpn_routing_policy(router, arguments)
        elif name == "list_vpn_policies":
            return handle_list_vpn_policies(router, arguments)

        # VPN Server Tools
        elif name == "get_vpn_server_status":
            return handle_get_vpn_server_status(router, arguments)
        elif name == "get_vpn_server_users":
            return handle_get_vpn_server_users(router, arguments)

        # URL/Keyword Filtering Tools
        elif name == "get_url_filter_status":
            return handle_get_url_filter_status(router, arguments)
        elif name == "add_url_filter":
            return handle_add_url_filter(router, arguments)
        elif name == "remove_url_filter":
            return handle_remove_url_filter(router, arguments)
        elif name == "list_url_filters":
            return handle_list_url_filters(router, arguments)
        elif name == "set_url_filter_mode":
            return handle_set_url_filter_mode(router, arguments)
        elif name == "get_keyword_filter_status":
            return handle_get_keyword_filter_status(router, arguments)
        elif name == "add_keyword_filter":
            return handle_add_keyword_filter(router, arguments)
        elif name == "remove_keyword_filter":
            return handle_remove_keyword_filter(router, arguments)
        elif name == "list_keyword_filters":
            return handle_list_keyword_filters(router, arguments)
        # Network Service Filtering
        elif name == "get_network_service_filter_status":
            return handle_get_network_service_filter_status(router, arguments)
        elif name == "list_network_service_filter_rules":
            return handle_list_network_service_filter_rules(router, arguments)
        elif name == "add_network_service_filter_rule":
            return handle_add_network_service_filter_rule(router, arguments)
        elif name == "remove_network_service_filter_rule":
            return handle_remove_network_service_filter_rule(router, arguments)
        elif name == "set_network_service_filter_mode":
            return handle_set_network_service_filter_mode(router, arguments)
        elif name == "set_network_service_filter_schedule":
            return handle_set_network_service_filter_schedule(router, arguments)

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return [TextContent(type="text", text=f"Error executing tool: {str(e)}")]


async def main():
    """Run the MCP server"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
