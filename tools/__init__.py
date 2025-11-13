"""
Tools module for MCP ASUS Router server.

Contains handler functions for various router management operations.
"""

# System info tools
from .system_info import (
    handle_download_file,
    handle_execute_command,
    handle_get_aiprotection_status,
    handle_get_all_network_devices,
    handle_get_connected_devices,
    handle_get_router_info,
    handle_get_system_log,
    handle_get_vpn_status,
    handle_get_wifi_status,
    handle_list_processes,
    handle_read_file,
    handle_reboot_router,
    handle_restart_service,
    handle_get_nvram_variable,
    handle_set_nvram_variable,
    handle_set_system_log_config,
    handle_upload_file,
)

# MAC filtering tools
from .mac_filtering import (
    handle_add_mac_filter,
    handle_list_mac_filters,
    handle_remove_mac_filter,
)

# DHCP management tools
from .dhcp_management import (
    handle_add_dhcp_reservation,
    handle_list_dhcp_reservations,
    handle_remove_dhcp_reservation,
)

# Internet control tools
from .internet_control import (
    handle_block_device_internet,
    handle_list_blocked_devices,
)

# VPN routing tools
from .vpn_routing import (
    handle_add_vpn_routing_policy,
    handle_list_vpn_policies,
    handle_remove_vpn_routing_policy,
)

# VPN server tools
from .vpn_server import (
    handle_get_vpn_server_status,
    handle_get_vpn_server_users,
)

# Firewall tools
from .firewall import (
    handle_get_firewall_status,
    handle_set_firewall_config,
)

# URL/Keyword filtering tools
from .url_filtering import (
    handle_add_keyword_filter,
    handle_add_url_filter,
    handle_get_keyword_filter_status,
    handle_get_url_filter_status,
    handle_list_keyword_filters,
    handle_list_url_filters,
    handle_remove_keyword_filter,
    handle_remove_url_filter,
    handle_set_url_filter_mode,
)

# Network Service filtering tools
from .network_service_filter import (
    handle_add_network_service_filter_rule,
    handle_get_network_service_filter_status,
    handle_list_network_service_filter_rules,
    handle_remove_network_service_filter_rule,
    handle_set_network_service_filter_mode,
    handle_set_network_service_filter_schedule,
)

__all__ = [
    # System info
    "handle_get_router_info",
    "handle_get_connected_devices",
    "handle_get_all_network_devices",
    "handle_get_wifi_status",
    "handle_restart_service",
    "handle_reboot_router",
    "handle_get_vpn_status",
    "handle_get_aiprotection_status",
    "handle_get_system_log",
    "handle_set_system_log_config",
    "handle_list_processes",
    "handle_get_nvram_variable",
    "handle_set_nvram_variable",
    "handle_execute_command",
    "handle_read_file",
    "handle_upload_file",
    "handle_download_file",
    # MAC filtering
    "handle_add_mac_filter",
    "handle_remove_mac_filter",
    "handle_list_mac_filters",
    # DHCP management
    "handle_add_dhcp_reservation",
    "handle_remove_dhcp_reservation",
    "handle_list_dhcp_reservations",
    # Internet control
    "handle_block_device_internet",
    "handle_list_blocked_devices",
    # VPN routing
    "handle_add_vpn_routing_policy",
    "handle_remove_vpn_routing_policy",
    "handle_list_vpn_policies",
    # VPN server
    "handle_get_vpn_server_status",
    "handle_get_vpn_server_users",
    # Firewall
    "handle_get_firewall_status",
    "handle_set_firewall_config",
    # URL/Keyword filtering
    "handle_get_url_filter_status",
    "handle_add_url_filter",
    "handle_remove_url_filter",
    "handle_list_url_filters",
    "handle_set_url_filter_mode",
    "handle_get_keyword_filter_status",
    "handle_add_keyword_filter",
    "handle_remove_keyword_filter",
    "handle_list_keyword_filters",
    # Network Service filtering
    "handle_get_network_service_filter_status",
    "handle_list_network_service_filter_rules",
    "handle_add_network_service_filter_rule",
    "handle_remove_network_service_filter_rule",
    "handle_set_network_service_filter_mode",
    "handle_set_network_service_filter_schedule",
]
