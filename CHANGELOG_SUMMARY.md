# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [3.0.1] - 2025-11-12

### 🚨 BREAKING CHANGE: Rootless Docker Container
- Container now runs as non-root user `mcpuser` (UID 1000) for security
- **Migration Required:** Update volume mount from `/root/.ssh` to `/home/mcpuser/.ssh`
- **Migration Required:** Update `ROUTER_KEY_FILE` env var to use `/home/mcpuser/.ssh/id_rsa`

### Changed
- Enhanced `execute_command` tool description with warning against heredoc/echo for file writes
- Enhanced `upload_file` tool description with workflow guidance and MD5 verification notes
- Added "CRITICAL FILE OPERATION RULES" section to CLAUDE.md with examples
- Updated all documentation (README, MCP_SETUP_GUIDE, DOCKER_HUB_SETUP) with breaking change notices

### Security
- Rootless container reduces attack surface and prevents privilege escalation
- Follows Docker security best practices

---

## [3.0] - 2025-11-11

### Added
- **6 new tools** for Network Service Filter management:
  - `get_network_service_filter_status` - View deny/allow list status and schedule
  - `list_network_service_filter_rules` - List rules for deny or allow list
  - `add_network_service_filter_rule` - Add service filter by IP/port/protocol
  - `remove_network_service_filter_rule` - Remove service filter rule
  - `set_network_service_filter_mode` - Enable/disable deny or allow list
  - `set_network_service_filter_schedule` - Configure active days and time ranges
- New module: `tools/network_service_filter.py` (673 lines)
- Helper functions: `parse_service_filter_rules`, `build_service_filter_rules`, `format_time_range`, `format_days`

### Changed
- Updated `config/constants.py` with Network Service Filter NVRAM variables
- Version bump: 2.9 → 3.0 (major - 6 tools added)

### Fixed
- Import error in `tools/network_service_filter.py` - changed `is_valid_ipv4` to `is_valid_ip`

**Total Tools:** 47 (was 41)

---

## [2.9] - 2025-11-11

### Fixed
- **CRITICAL:** VPN Director uses `/jffs/openvpn/vpndirector_rulelist` file, not NVRAM
- Fixed `add_vpn_routing_policy` to append rules to file instead of NVRAM
- Fixed `remove_vpn_routing_policy` to remove rules from file instead of NVRAM
- Fixed `list_vpn_policies` to read rules from file instead of NVRAM

### Changed
- VPN routing tools now use file-based operations with proper locking
- Helper functions: `read_vpn_director_rules`, `write_vpn_director_rules`, `parse_vpn_director_rules`, `build_vpn_director_rules`

**Note:** This was a critical bug - VPN routing tools were completely non-functional before this fix.

---

## [2.8] - 2025-11-10

### Added
- **9 new tools** for URL and Keyword filtering:
  - `get_url_filter_status` - View global URL filter status and mode
  - `add_url_filter` - Add URL pattern to filter list
  - `remove_url_filter` - Remove URL pattern from filter list
  - `list_url_filters` - List all configured URL filter rules
  - `set_url_filter_mode` - Set blacklist or whitelist mode
  - `get_keyword_filter_status` - View keyword filter status
  - `add_keyword_filter` - Add keyword to filter list
  - `remove_keyword_filter` - Remove keyword from filter list
  - `list_keyword_filters` - List all configured keyword filter rules
- New modules: `tools/url_filter.py` (341 lines), `tools/keyword_filter.py` (223 lines)

### Changed
- Version bump: 2.7 → 2.8 (minor - 9 tools added)
- Updated `config/constants.py` with URL/Keyword filter NVRAM variables

**Total Tools:** 41 (was 32)

---

## [2.7] - 2025-11-09

### Added
- **2 new tools** for firewall management:
  - `get_firewall_status` - Get comprehensive firewall config and status
  - `set_firewall_config` - Configure firewall, DoS protection, logging, VPN passthrough
- New module: `tools/firewall.py` (267 lines)
- Support for IPv6 firewall, WAN ping response, VPN passthrough protocols (PPTP, L2TP, IPSec, RTSP, H.323, SIP, PPPoE)

### Changed
- Version bump: 2.6 → 2.7 (minor - 2 tools added)
- Updated `config/constants.py` with firewall NVRAM variables

**Total Tools:** 32 (was 30)

---

## [2.6] - 2025-11-08

### Added
- **3 new tools** for system log management:
  - `get_system_log` - Retrieve system log entries with optional filtering
  - `set_system_log_config` - Configure log levels and remote syslog server
  - `list_processes` - List running processes with optional filtering
- New module: `tools/system_log.py` (185 lines)

### Changed
- Version bump: 2.5 → 2.6 (minor - 3 tools added)
- Updated `config/constants.py` with system log NVRAM variables

**Total Tools:** 30 (was 27)

---

## [2.5] - 2025-11-07

### Fixed
- AiProtection status tool now correctly parses web UI response
- Fixed string search patterns for malicious site blocking, two-way IPS, and infected device prevention
- Tool now returns proper enabled/disabled status instead of "Not available" errors

### Changed
- Improved `handle_get_aiprotection_status` with robust parsing logic
- Better error handling for missing AiProtection features

---

## [2.4] - 2025-11-06

### Added
- **1 new tool** for security monitoring:
  - `get_aiprotection_status` - Get AiProtection (Trend Micro) security status
- Module: `tools/aiprotection.py` (82 lines)
- Monitors: malicious sites blocking, two-way IPS, infected device prevention

### Changed
- Version bump: 2.3 → 2.4 (minor - 1 tool added)

**Total Tools:** 27 (was 26)

---

## [2.3] - 2025-11-05

### Fixed
- MAC filter mode validation now checks against correct values ("allow"/"deny" instead of "whitelist"/"blacklist")
- Updated `handle_add_mac_filter` to use proper NVRAM values
- Router UI now correctly reflects whitelist/blacklist mode

---

## [2.2] - 2025-11-04

### Fixed
- VPN server tools now return proper status when servers are disabled/not configured
- Improved error handling in `handle_get_vpn_server_status` for missing status files
- Better status display for disabled/unconfigured VPN servers

---

## [2.1] - 2025-11-03

### Changed
- Improved MAC filter display with radio band labels (2.4GHz vs 5GHz)
- Enhanced `list_mac_filters` output formatting with mode information
- Better visual separation in filter lists

---

## [2.0] - 2025-10-30

### Added
- **12 new high-level device management tools:**
  - **MAC Filtering:** `add_mac_filter`, `remove_mac_filter`, `list_mac_filters`
  - **DHCP Management:** `add_dhcp_reservation`, `remove_dhcp_reservation`, `list_dhcp_reservations`
  - **Internet Control:** `block_device_internet`, `list_blocked_devices`
  - **VPN Routing:** `add_vpn_routing_policy`, `remove_vpn_routing_policy`, `list_vpn_policies`
- **2 VPN server monitoring tools:**
  - `get_vpn_server_status` - Shows connected clients with transfer stats
  - `get_vpn_server_users` - Lists authorized VPN users
- Helper functions for NVRAM parsing and validation:
  - `is_valid_mac`, `is_valid_ip`, `normalize_mac`
  - `parse_nvram_list`, `build_nvram_list`
  - `parse_dhcp_reservation_list`, `build_dhcp_reservation_list`

### Changed
- Version bump: 1.0 → 2.0 (major - 14 tools added)

### Fixed
- DHCP reservation parser now handles 4-field format: `<MAC>IP>DNS>hostname>`
- Updated all DHCP tools to support optional DNS field

**Total Tools:** 27 (was 13)

---

## [1.1] - 2025-10-31

### Changed
- **Major refactoring:** Transformed 2,282-line monolithic file into modular package structure
- Main file reduced from 2,282 to 554 lines (75.7% reduction)
- Created 4 new packages:
  - `config/` - Constants and router configuration (2 modules)
  - `core/` - SSH client infrastructure (1 module)
  - `utils/` - Pure utility functions (2 modules)
  - `tools/` - Tool handler functions (6 modules)
- No functionality changes - pure refactoring
- Applied ruff linting and formatting

### Security
- Added OS package updates to Dockerfile (`apt update && apt upgrade`)
- Added pip upgrade before installing dependencies

---

## [1.0.0] - 2025-10-08

### Added
- Initial release with 13 basic tools:
  - `get_router_info` - Router system information
  - `get_connected_devices` - List DHCP devices
  - `get_all_network_devices` - Comprehensive device list (DHCP + static + ARP)
  - `get_wifi_status` - WiFi radio status
  - `restart_service` - Restart router services
  - `reboot_router` - Reboot the router
  - `get_nvram_variable` - Read NVRAM variables
  - `set_nvram_variable` - Write NVRAM variables
  - `execute_command` - Execute shell commands
  - `read_file` - Read files from router
  - `upload_file` - Upload files via SCP
  - `download_file` - Download files via SCP
  - `get_vpn_status` - VPN client/server status
- SSH/SCP connectivity via paramiko
- Environment-based configuration
- Docker support

**Total Tools:** 13

---

## Format Notes

- **BREAKING CHANGE:** Requires user action to migrate
- **Added:** New features
- **Changed:** Changes to existing functionality
- **Deprecated:** Features marked for removal
- **Removed:** Removed features
- **Fixed:** Bug fixes
- **Security:** Security improvements
