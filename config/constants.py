"""
ASUS Router NVRAM variable names, service names, and constants.

This file centralizes all router-specific configuration strings.
Modify these if targeting different firmware versions.
"""

import re

# ============================================================================
# NVRAM Variable Names
# ============================================================================

# MAC Filtering (WiFi Access Control)
NVRAM_MAC_FILTER_2GHZ = "wl0_maclist"
NVRAM_MAC_FILTER_5GHZ = "wl1_maclist"
NVRAM_MAC_MODE_2GHZ = "wl0_macmode"
NVRAM_MAC_MODE_5GHZ = "wl1_macmode"

# DHCP
NVRAM_DHCP_STATIC_LIST = "dhcp_staticlist"
NVRAM_DHCP_RESERVE_LIST = "dhcp_reservelist"

# Parental Controls (Internet Access Blocking)
NVRAM_PARENTAL_CONTROL_ENABLE = "MULTIFILTER_ENABLE"
NVRAM_PARENTAL_CONTROL_MAC = "MULTIFILTER_MAC"

# VPN Clients
NVRAM_VPN_CLIENT_STATE_TEMPLATE = "vpn_client{}_state"  # Format with 1-5
NVRAM_VPN_CLIENT_LIST_TEMPLATE = "vpn_client{}_clientlist"  # Format with 1-5

# VPN Fusion (Device-Based Routing - Stock ASUS firmware only)
NVRAM_VPN_FUSION_POLICY_LIST = (
    "vpnc_dev_policy_list"  # Global device-to-VPN routing list
)

# VPN Director (Policy-Based Routing - Asuswrt-Merlin firmware)
NVRAM_VPN_DIRECTOR_RULELIST = "vpndirector_rulelist"  # VPN Director routing rules (Merlin replacement for VPN Fusion)

# VPN Servers
NVRAM_VPN_SERVER_STATE_TEMPLATE = "vpn_server{}_state"  # Format with 1-2

# Firewall
NVRAM_FW_ENABLE = "fw_enable_x"
NVRAM_FW_DOS = "fw_dos_x"
NVRAM_FW_LOG = "fw_log_x"
NVRAM_MISC_PING = "misc_ping_x"
NVRAM_FW_PT_PPTP = "fw_pt_pptp"
NVRAM_FW_PT_L2TP = "fw_pt_l2tp"
NVRAM_FW_PT_IPSEC = "fw_pt_ipsec"
NVRAM_FW_PT_RTSP = "fw_pt_rtsp"
NVRAM_FW_PT_H323 = "fw_pt_h323"
NVRAM_FW_PT_SIP = "fw_pt_sip"
NVRAM_FW_PT_PPPOE_RELAY = "fw_pt_pppoerelay"
NVRAM_FW_LW_ENABLE = "fw_lw_enable_x"
NVRAM_FW_WL_ENABLE = "fw_wl_enable_x"
NVRAM_IPV6_FW_ENABLE = "ipv6_fw_enable"

# URL Filtering
NVRAM_URL_ENABLE = "url_enable_x"
NVRAM_URL_MODE = "url_mode_x"
NVRAM_URL_RULELIST = "url_rulelist"
NVRAM_URL_SCHED = "url_sched"

# Keyword Filtering
NVRAM_KEYWORD_ENABLE = "keyword_enable_x"
NVRAM_KEYWORD_RULELIST = "keyword_rulelist"
NVRAM_KEYWORD_SCHED = "keyword_sched"

# Network Service Filtering (LAN-to-WAN packet filtering)
# Deny List (Black List) - blocks specified services during schedule
NVRAM_FILTER_LW_ENABLE = "fw_lw_enable_x"
NVRAM_FILTER_LW_LIST = "filter_lwlist"
NVRAM_FILTER_LW_DATE = "filter_lw_date_x"
NVRAM_FILTER_LW_TIME = "filter_lw_time_x"
NVRAM_FILTER_LW_TIME2 = "filter_lw_time2_x"
NVRAM_FILTER_LW_DEFAULT = "filter_lw_default_x"

# Allow List (White List) - allows only specified services during schedule
NVRAM_FILTER_WL_ENABLE = "fw_wl_enable_x"
NVRAM_FILTER_WL_LIST = "filter_wllist"
NVRAM_FILTER_WL_DATE = "filter_wl_date_x"
NVRAM_FILTER_WL_TIME = "filter_wl_time_x"
NVRAM_FILTER_WL_TIME2 = "filter_wl_time2_x"
NVRAM_FILTER_WL_DEFAULT = "filter_wl_default_x"

# Per-Device (Multi) Filtering - Parallel array system
NVRAM_MULTIFILTER_ALL = "MULTIFILTER_ALL"  # Master enable for parental control system
NVRAM_MULTIFILTER_ENABLE = (
    "MULTIFILTER_ENABLE"  # Per-device enable flags (parallel list)
)
NVRAM_MULTIFILTER_MAC = "MULTIFILTER_MAC"  # Device MAC addresses (parallel list)
NVRAM_MULTIFILTER_DEVICENAME = "MULTIFILTER_DEVICENAME"  # Device names (parallel list)
NVRAM_MULTIFILTER_URL = "MULTIFILTER_URL"  # Per-device URL patterns (parallel list)
NVRAM_MULTIFILTER_URL_ENABLE = (
    "MULTIFILTER_URL_ENABLE"  # Per-device URL enable (parallel list)
)

# ============================================================================
# Service Names (for restart commands)
# ============================================================================

SERVICE_WIRELESS = "wireless"
SERVICE_DNSMASQ = "dnsmasq"
SERVICE_FIREWALL = "firewall"
SERVICE_VPN_CLIENT_TEMPLATE = "vpnclient{}"  # Format with 1-5

# ============================================================================
# File Paths
# ============================================================================

VPN_SERVER_STATUS_FILE_TEMPLATE = "/etc/openvpn/server{}/status"  # Format with 1-2
VPN_DIRECTOR_RULELIST_FILE = (
    "/jffs/openvpn/vpndirector_rulelist"  # VPN Director rules file
)
ROUTER_PASSWD_FILE = "/etc/passwd"

# ============================================================================
# Constants and Limits
# ============================================================================

# VPN Client Numbers
VPN_CLIENT_MIN = 1
VPN_CLIENT_MAX = 5

# VPN Server Numbers
VPN_SERVER_MIN = 1
VPN_SERVER_MAX = 2

# URL/Keyword Filter Limits
URL_FILTER_MAX_RULES = 64
KEYWORD_FILTER_MAX_RULES = 64

# Network Service Filter Limits
NETWORK_SERVICE_FILTER_MAX_RULES = 128

# URL Filter Modes
URL_MODE_BLACKLIST = "0"
URL_MODE_WHITELIST = "1"

# NVRAM Delimiters (ASUS uses < and > for list formatting)
NVRAM_LIST_START_DELIMITER = "<"
NVRAM_LIST_END_DELIMITER = ">"

# Filter Types
FILTER_TYPE_WHITELIST = "whitelist"
FILTER_TYPE_BLACKLIST = "blacklist"
MAC_MODE_ALLOW = "allow"
MAC_MODE_DENY = "deny"

# Radio Bands
RADIO_2GHZ = "2.4ghz"
RADIO_5GHZ = "5ghz"
RADIO_BOTH = "both"

# ============================================================================
# Validation Patterns
# ============================================================================

# MAC Address: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
MAC_ADDRESS_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

# IPv4 Address: 0.0.0.0 to 255.255.255.255
IPV4_ADDRESS_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
