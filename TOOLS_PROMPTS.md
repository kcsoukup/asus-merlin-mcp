# ASUS Router MCP Tools - Example Prompts

This guide provides example prompts for all 47 MCP tools organized by category.

## System Information Tools (14 tools)

### get_router_info
Get router system information including uptime, memory, CPU, and firmware version.

**Example Prompts (General):**
- "What's my router's uptime?"
- "Show me router system info"
- "How much memory is the router using?"

**Example Prompts (Advanced):**
- "Show me complete system info including firmware version and kernel details"
- "What's the router's current load average and how much free memory is available?"

**Real-World Use Cases:**
- Monitor uptime to verify router stability after firmware updates
- Check memory usage when experiencing slow network performance
- Verify firmware version before/after updates
- Diagnose high CPU usage during network congestion
- Monitor system health as part of regular maintenance routine

### get_connected_devices
List all devices currently connected via DHCP.

**Example Prompts (General):**
- "List all connected devices"
- "What devices are on my network?"
- "Show DHCP clients"

**Example Prompts (Advanced):**
- "Show me all currently connected devices with their IP addresses and MAC addresses"
- "List DHCP clients and tell me which ones are unknown or unrecognized"

**Real-World Use Cases:**
- Identify unauthorized devices connected to your network
- Find device IP addresses for port forwarding configuration
- Audit network devices before implementing MAC filtering
- Troubleshoot connection issues by verifying device presence
- Monitor guest network usage and connected devices

### get_all_network_devices
Get comprehensive list of all network devices (DHCP + static + ARP).

**Example Prompts (General):**
- "Show me all network devices"
- "List all devices including static IPs"
- "Show only DHCP reservations"

**Example Prompts (Advanced):**
- "Give me a complete network inventory including DHCP, static, and ARP entries"
- "Show all devices with DHCP reservations and highlight which ones are currently connected"

**Real-World Use Cases:**
- Create complete network inventory for documentation
- Identify devices using static IPs vs DHCP
- Audit DHCP reservations before network restructuring
- Find offline devices that still have reservations
- Troubleshoot IP conflicts by reviewing all IP assignments

### get_wifi_status
Get WiFi status for all radios (2.4GHz, 5GHz, etc.).

**Example Prompts (General):**
- "What's my WiFi status?"
- "Show WiFi radio information"
- "Is my 5GHz WiFi enabled?"

**Example Prompts (Advanced):**
- "Show me detailed WiFi status for both 2.4GHz and 5GHz including channel and encryption"
- "Check if WiFi is enabled on all radios and show current SSID names"

**Real-World Use Cases:**
- Verify WiFi settings after changing channels for better performance
- Check if guest network is enabled/disabled
- Troubleshoot connection issues by verifying radio status
- Document WiFi configuration for network planning
- Verify encryption settings for security compliance

### restart_service
Restart a specific router service.

**Example Prompts (General):**
- "Restart the wireless service"
- "Restart VPN client 1"
- "Restart httpd service"

**Example Prompts (Advanced):**
- "Restart the wireless service to apply my WiFi changes"
- "Restart dnsmasq service to reload DHCP configuration"

**Real-World Use Cases:**
- Apply WiFi configuration changes without full reboot
- Restart VPN client after configuration changes
- Reload DHCP settings after adding reservations
- Restart web interface (httpd) if it becomes unresponsive
- Apply firewall rules by restarting firewall service

### reboot_router
Reboot the entire router (requires confirmation).

**Example Prompts (General):**
- "Reboot the router"
- "Restart my router"

**Example Prompts (Advanced):**
- "Reboot the router and confirm you want to do this"
- "I need to reboot the router to clear all connections"

**Real-World Use Cases:**
- Apply firmware updates that require reboot
- Clear persistent connection issues
- Reset router state after configuration changes
- Troubleshoot memory leaks by forcing restart
- Complete factory reset procedures

### get_vpn_status
Get status of all VPN clients and servers.

**Example Prompts (General):**
- "What's my VPN status?"
- "Are any VPN clients connected?"
- "Show VPN client status"

**Example Prompts (Advanced):**
- "Show me all VPN client and server statuses including connection state and IP addresses"
- "Which VPN clients are running and what are their current configurations?"

**Real-World Use Cases:**
- Verify VPN tunnel is established before routing traffic
- Troubleshoot VPN connection failures
- Monitor VPN server for remote access availability
- Check VPN client routing before adding device policies
- Audit VPN configuration across all client slots (1-5)

### list_processes
List running processes on the router.

**Example Prompts (General):**
- "List all running processes"
- "Show me processes running on the router"
- "List processes containing 'vpn'"

**Example Prompts (Advanced):**
- "Show all processes and identify any that are consuming excessive resources"
- "List all VPN-related processes and check if they're running correctly"

**Real-World Use Cases:**
- Troubleshoot high CPU usage by identifying resource-heavy processes
- Verify custom scripts are running after router restart
- Check if VPN processes are active when connection fails
- Identify zombie or stuck processes causing issues
- Monitor system health by reviewing active processes

### get_nvram_variable
Get the value of a specific NVRAM variable.

**Example Prompts (General):**
- "Get the value of wan_ipaddr"
- "Show me the router_name NVRAM variable"
- "What's the value of dhcp_start?"

**Example Prompts (Advanced):**
- "Check the current WAN IP address and DNS servers from NVRAM"
- "Show me all VPN-related NVRAM variables for VPN client 1"

**Real-World Use Cases:**
- Verify WAN IP configuration before troubleshooting connectivity
- Check DNS server settings when experiencing resolution issues
- Audit router name and identification settings
- Review DHCP range configuration (dhcp_start, dhcp_end)
- Troubleshoot custom configuration by examining NVRAM values

### set_nvram_variable
Set an NVRAM variable value (use with caution).

**Example Prompts (General):**
- "Set router_name to MyRouter"
- "Change wan_dns to 1.1.1.1"
- "Set dhcp_start to 192.168.1.100 and commit"

**Example Prompts (Advanced):**
- "Set custom DNS servers in NVRAM and commit the changes permanently"
- "Change DHCP range start address and commit to persistent storage"

**Real-World Use Cases:**
- Configure custom DNS servers (Cloudflare, Google, OpenDNS)
- Adjust DHCP range for network reorganization
- Set custom router hostname for network identification
- Modify advanced settings not available in web UI
- **Warning:** Incorrect values can break router configuration - use carefully!

### execute_command
Execute a custom shell command on the router.

**Example Prompts (General):**
- "Run the command 'uptime'"
- "Execute 'df -h' on the router"
- "Run 'cat /proc/cpuinfo'"

**Example Prompts (Advanced):**
- "Check disk space usage and show me which partitions are full"
- "Run netstat to show all active network connections and their states"

**Real-World Use Cases:**
- Check filesystem usage when router is running slow (df -h)
- Monitor active connections for security auditing (netstat)
- Verify CPU information for hardware compatibility
- Debug custom scripts by running test commands
- Gather diagnostic information for support tickets

### read_file
Read contents of a file on the router.

**Example Prompts (General):**
- "Read /jffs/scripts/init-start"
- "Show me the first 50 lines of /tmp/syslog.log"
- "Read /etc/config/wireless"

**Example Prompts (Advanced):**
- "Read my custom init script and check for syntax errors"
- "Show me the system log and highlight any error messages"

**Real-World Use Cases:**
- Review custom startup scripts before router reboot
- Check system logs for error messages and warnings
- Verify configuration files after manual edits
- Audit VPN configuration files for correctness
- Read firewall rules from configuration files

### upload_file
Upload a file to the router via SCP (with MD5 verification).

**Example Prompts (General):**
- "Upload /home/user/script.sh to /jffs/scripts/"
- "Copy my local firewall.sh to /jffs/scripts/firewall-start"

**Example Prompts (Advanced):**
- "Upload my custom startup script and verify the MD5 checksum matches"
- "Transfer my VPN configuration file to the router with integrity verification"

**Real-World Use Cases:**
- Deploy custom startup scripts for automated tasks
- Upload firewall scripts for advanced security rules
- Transfer VPN configuration files for new connections
- Install third-party packages or utilities
- Backup restore by uploading configuration files
- **Note:** All uploads are MD5 verified for data integrity

### download_file
Download a file from the router via SCP (with MD5 verification).

**Example Prompts (General):**
- "Download /tmp/syslog.log to /home/user/logs/"
- "Copy /jffs/scripts/init-start to my local directory"

**Example Prompts (Advanced):**
- "Download all system logs for analysis and verify data integrity"
- "Backup my custom scripts from the router with checksum verification"

**Real-World Use Cases:**
- Backup system logs for long-term storage and analysis
- Archive custom scripts before firmware upgrades
- Download configuration files for documentation
- Retrieve crash dumps for troubleshooting
- Export VPN logs for security auditing
- **Note:** All downloads are MD5 verified for data integrity

## MAC Filtering Tools (3 tools)

### add_mac_filter
Add a device to MAC filter (whitelist or blacklist) for WiFi access control.

**Example Prompts (General):**
- "Block MAC address AA:BB:CC:DD:EE:FF from WiFi"
- "Add AA:BB:CC:DD:EE:FF to whitelist on 5GHz"
- "Blacklist AA:BB:CC:DD:EE:FF on both radios"

**Example Prompts (Advanced):**
- "Add AA:BB:CC:DD:EE:FF to blacklist on 2.4GHz only and leave 5GHz unrestricted"
- "Create a whitelist on both radios and only allow known devices to connect"

**Real-World Use Cases:**
- Block unauthorized devices discovered on network scan
- Implement guest network security by blacklisting specific MACs
- Create whitelist for high-security networks (only known devices)
- Prevent neighbor's devices from connecting to open guest WiFi
- Separate IoT devices by blocking them from specific radio bands

### remove_mac_filter
Remove a device from MAC filter.

**Example Prompts (General):**
- "Remove AA:BB:CC:DD:EE:FF from MAC filter"
- "Unblock AA:BB:CC:DD:EE:FF from 2.4GHz"
- "Remove MAC filter for AA:BB:CC:DD:EE:FF"

**Example Prompts (Advanced):**
- "Remove all MAC filtering for AA:BB:CC:DD:EE:FF from both 2.4GHz and 5GHz"
- "Unblock this device that was accidentally added to the blacklist"

**Real-World Use Cases:**
- Remove temporary restrictions after guest leaves
- Unblock devices that were mistakenly blacklisted
- Clear MAC filters when switching from whitelist to blacklist mode
- Remove old device entries before adding new ones
- Clean up MAC filter list during network reorganization

### list_mac_filters
Show current MAC filters with friendly formatting.

**Example Prompts (General):**
- "List all MAC filters"
- "Show me WiFi access control rules"
- "What devices are blocked from WiFi?"

**Example Prompts (Advanced):**
- "Show all MAC filters for both radios and tell me which mode (whitelist/blacklist) is active"
- "List all WiFi access restrictions and identify which devices are blocked vs allowed"

**Real-World Use Cases:**
- Audit WiFi security configuration before deployment
- Verify MAC filters were applied correctly after changes
- Document access control settings for compliance
- Troubleshoot why specific device cannot connect to WiFi
- Review security policy before public event with guest WiFi

## DHCP Management Tools (3 tools)

### add_dhcp_reservation
Reserve an IP address for a specific MAC address (static DHCP lease).

**Example Prompts (General):**
- "Reserve 192.168.1.50 for MAC AA:BB:CC:DD:EE:FF"
- "Add DHCP reservation for AA:BB:CC:DD:EE:FF with IP 192.168.1.100"
- "Create static lease for AA:BB:CC:DD:EE:FF at 192.168.1.25 with hostname MyDevice"

**Example Prompts (Advanced):**
- "Reserve 192.168.1.10 for my printer's MAC address and set hostname to Office-Printer"
- "Create multiple DHCP reservations for all my IoT devices in the 192.168.1.200-220 range"

**Real-World Use Cases:**
- Assign static IPs to printers for consistent print server configuration
- Reserve IPs for security cameras and NVR systems
- Configure port forwarding with predictable IP addresses
- Organize network by IP ranges (e.g., 10-50 servers, 100-150 workstations, 200-250 IoT)
- Prevent IP conflicts in mixed static/DHCP environments

### remove_dhcp_reservation
Remove a DHCP reservation by MAC or IP address.

**Example Prompts (General):**
- "Remove DHCP reservation for AA:BB:CC:DD:EE:FF"
- "Delete static lease for 192.168.1.50"
- "Remove DHCP reservation at IP 192.168.1.100"

**Example Prompts (Advanced):**
- "Remove the DHCP reservation for this old device and free up the IP address"
- "Delete all reservations for devices that are no longer on the network"

**Real-World Use Cases:**
- Free up IP addresses after device retirement
- Clean up reservations for replaced equipment
- Remove temporary reservations after testing
- Reorganize DHCP reservations before network migration
- Clear conflicting reservations causing connectivity issues

### list_dhcp_reservations
Show all current DHCP reservations.

**Example Prompts (General):**
- "List all DHCP reservations"
- "Show me static IP assignments"
- "What devices have reserved IPs?"

**Example Prompts (Advanced):**
- "Show me all DHCP reservations and identify which devices are currently online"
- "List static IP assignments organized by IP address range"

**Real-World Use Cases:**
- Document network configuration for IT asset management
- Audit IP address allocation before adding new devices
- Find available IPs in reservation range
- Verify reservations match network documentation
- Troubleshoot duplicate IP warnings by reviewing reservations

## Internet Access Control Tools (2 tools)

### block_device_internet
Block or unblock device from internet access (parental controls).

**Example Prompts (General):**
- "Block internet access for AA:BB:CC:DD:EE:FF"
- "Unblock AA:BB:CC:DD:EE:FF from internet"
- "Enable parental controls for MAC AA:BB:CC:DD:EE:FF"

**Example Prompts (Advanced):**
- "Block internet access for my kid's tablet during homework hours"
- "Temporarily block all IoT devices from internet access for security testing"

**Real-World Use Cases:**
- Implement parental controls for children's devices
- Block compromised IoT devices from internet access
- Temporarily disable internet for specific devices during troubleshooting
- Enforce network usage policies (e.g., no internet during work hours)
- Quarantine suspicious devices while investigating security incidents

### list_blocked_devices
Show devices with internet access restrictions.

**Example Prompts (General):**
- "List all blocked devices"
- "What devices are blocked from internet?"
- "Show parental control rules"

**Example Prompts (Advanced):**
- "Show me all devices with internet restrictions and their current connection status"
- "List parental control rules and tell me which devices are currently blocked"

**Real-World Use Cases:**
- Audit parental control configuration
- Verify internet restrictions are active during scheduled times
- Troubleshoot connectivity issues by checking block status
- Document access control policies for compliance
- Review blocked devices before removing restrictions

## VPN Routing Policy Tools (3 tools - Asuswrt-Merlin only)

**Note:** These tools require Asuswrt-Merlin firmware. They use VPN Director for policy-based routing. Stock ASUS firmware is not currently supported.

### add_vpn_routing_policy
Route a specific device through a VPN client using VPN Director.

**Example Prompts (General):**
- "Route AA:BB:CC:DD:EE:FF through VPN client 1"
- "Add AA:BB:CC:DD:EE:FF to VPN client 2"
- "Send device AA:BB:CC:DD:EE:FF through VPN 1"

**Example Prompts (Advanced):**
- "Route all my streaming devices through VPN client 1 for geo-unblocking"
- "Add my work laptop to VPN client 2 for secure corporate access"

**Real-World Use Cases:**
- Route streaming devices through VPN for international content access
- Direct work devices through corporate VPN automatically
- Send privacy-sensitive traffic through VPN (smart home devices)
- Split tunnel configuration (some devices VPN, others direct)
- Bypass geo-restrictions for specific devices only

### remove_vpn_routing_policy
Remove a device from VPN routing.

**Example Prompts (General):**
- "Remove AA:BB:CC:DD:EE:FF from VPN routing"
- "Stop routing AA:BB:CC:DD:EE:FF through VPN client 1"
- "Remove VPN policy for AA:BB:CC:DD:EE:FF"

**Example Prompts (Advanced):**
- "Remove this device from all VPN routing and use direct internet connection"
- "Stop VPN routing for my gaming console to reduce latency"

**Real-World Use Cases:**
- Improve gaming performance by removing VPN overhead
- Troubleshoot VPN connection issues by removing policies
- Reorganize VPN routing before switching VPN providers
- Remove devices that no longer need VPN protection
- Clear policies when decommissioning VPN client

### list_vpn_policies
Show all VPN routing policies.

**Example Prompts (General):**
- "List all VPN routing policies"
- "What devices are using VPN client 1?"
- "Show me all VPN policy routing rules"

**Example Prompts (Advanced):**
- "Show me all VPN routing policies organized by VPN client number"
- "List which devices are routed through each VPN client and their connection status"

**Real-World Use Cases:**
- Audit VPN routing configuration before changes
- Document split-tunnel setup for network diagram
- Troubleshoot why specific device traffic isn't using VPN
- Verify routing policies after VPN configuration changes
- Plan VPN load distribution across multiple clients

## VPN Server Monitoring Tools (2 tools)

### get_vpn_server_status
Get detailed VPN server status including connected clients.

**Example Prompts (General):**
- "Show VPN server status"
- "What clients are connected to my VPN server?"
- "Is my VPN server running?"

**Example Prompts (Advanced):**
- "Show me all connected VPN clients with their IP addresses and connection times"
- "Check if VPN server is running and show bandwidth usage for connected clients"

**Real-World Use Cases:**
- Monitor remote access VPN usage
- Verify VPN server is accessible before traveling
- Identify unknown or unauthorized VPN connections
- Troubleshoot VPN connectivity for remote users
- Monitor VPN server health and active sessions

### get_vpn_server_users
Get list of users authorized to connect to VPN servers.

**Example Prompts (General):**
- "List VPN server users"
- "Who can connect to my VPN server?"
- "Show authorized VPN users"

**Example Prompts (Advanced):**
- "Show all VPN server users and identify which ones have connected recently"
- "List authorized VPN users for security audit"

**Real-World Use Cases:**
- Audit VPN access permissions for security compliance
- Verify user accounts before granting new VPN access
- Document authorized users for IT security policy
- Remove access for departed employees
- Review VPN user list before security certification

## Firewall Management Tools (2 tools)

### get_firewall_status
Get comprehensive firewall status and configuration including main firewall, DoS protection, logging, WAN ping response, VPN passthrough settings, and IPv6 firewall.

**Example Prompts (General):**
- "Show me the firewall status"
- "What's my current firewall configuration?"
- "Display firewall settings"

**Example Prompts (Advanced):**
- "Is DoS protection enabled on my router?"
- "Show me all VPN passthrough protocol settings and tell me which ones are enabled"

**Real-World Use Cases:**
- Check if firewall logging is enabled before troubleshooting connection issues
- Verify DoS protection status after a security incident
- Audit VPN passthrough settings when configuring VPN clients
- Confirm WAN ping is disabled (stealthed) for security hardening
- Review IPv6 firewall status when enabling IPv6 on network

### set_firewall_config
Configure firewall settings including enable/disable main firewall, DoS protection, logging mode, WAN ping response, IPv6 firewall, and VPN passthrough protocols (PPTP, L2TP, IPSec, RTSP, H.323, SIP, PPPoE).

**Example Prompts (General):**
- "Enable firewall logging"
- "Turn on DoS protection"
- "Disable WAN ping response"

**Example Prompts (Advanced):**
- "Enable firewall logging for dropped packets only, and make sure DoS protection is enabled"
- "Disable all VPN passthrough protocols except IPSec and L2TP"

**Real-World Use Cases:**
- Enable logging mode 'drop' to monitor attack attempts: `"Enable firewall logging to track dropped packets"`
- Harden security by disabling WAN ping: `"Disable WAN ping response to stealth my router"`
- Configure VPN passthrough for specific VPN type: `"Enable IPSec passthrough but disable PPTP"`
- Enable both firewall and DoS protection: `"Turn on main firewall and DoS protection"`
- Set comprehensive logging: `"Set firewall logging to 'both' to log all accepted and dropped packets"`
- Disable IPv6 firewall when troubleshooting IPv6 issues: `"Temporarily disable IPv6 firewall"`

**Example from Testing:**
```
User: "Enable firewall logging"
Result: Successfully changed fw_log_x from 'none' to 'drop'
        Firewall service automatically restarted
        Changes committed to NVRAM (persists across reboots)

User: "Show me the updated configs"
Result: Firewall Logging: Dropped packets only ✓
```

**Logging Mode Options:**
- `none` - Disable all firewall logging
- `drop` - Log dropped packets only (recommended for security monitoring)
- `accept` - Log accepted packets only (useful for traffic analysis)
- `both` - Log all packets (verbose, large log files)

**Where Firewall Logs Are Written:**
- Primary location: `/tmp/syslog.log` (view with `get_system_log` tool)
- Kernel ring buffer: `dmesg` output
- Filter logs: Use `get_system_log` with filter parameter, e.g., `"Show me firewall DROP events from the last 50 lines"`

**VPN Passthrough Protocols:**
- **PPTP** - Point-to-Point Tunneling Protocol (legacy VPN)
- **L2TP** - Layer 2 Tunneling Protocol (commonly used with IPSec)
- **IPSec** - Internet Protocol Security (secure VPN standard)
- **RTSP** - Real Time Streaming Protocol (video streaming)
- **H.323** - Video conferencing protocol
- **SIP** - Session Initiation Protocol (VoIP/telephony)
- **PPPoE Relay** - PPPoE passthrough for ISP authentication

---

## URL/Keyword Filtering Tools (12 tools)

### get_url_filter_status
Get current status and mode of global URL filtering (blacklist or whitelist).

**Example Prompts (General):**
- "Is URL filtering enabled?"
- "Show me URL filter status"
- "What mode is the URL filter in?"

**Example Prompts (Advanced):**
- "Show me complete URL filter configuration including enabled status and current mode"
- "What's the current URL filter mode and how many rules are configured?"

**Real-World Use Cases:**
- Verify URL filtering is active before adding parental control rules
- Check filter mode to understand whether you're blocking or allowing specific sites
- Audit URL filter configuration as part of network security review
- Troubleshoot website access issues by checking filter status
- Confirm filter settings match your security policy

### add_url_filter
Add URL pattern to global filter list (blacklist or whitelist depending on mode).

**Example Prompts (General):**
- "Block facebook.com"
- "Add youtube to URL filter"
- "Filter out gaming sites"

**Example Prompts (Advanced):**
- "Add multiple social media sites to the URL filter: facebook, twitter, instagram"
- "Block all streaming video sites using keywords: youtube, netflix, hulu, twitch"

**Real-World Use Cases:**
- Block social media during work/school hours
- Prevent access to gaming sites on children's devices
- Block known malicious domains for network security
- Implement content filtering for guest networks
- Create whitelist of approved educational sites only

### remove_url_filter
Remove URL pattern from global filter list.

**Example Prompts (General):**
- "Remove facebook from URL filter"
- "Unblock youtube.com"
- "Delete the gaming filter"

**Example Prompts (Advanced):**
- "Remove all social media filters I added earlier"
- "Unblock streaming sites for weekend use"

**Real-World Use Cases:**
- Temporarily remove filters for specific events or time periods
- Clean up outdated filter rules
- Adjust filters based on changing household needs
- Remove test filters after configuration verification
- Unblock sites that were incorrectly categorized

### list_url_filters
Show all current URL filter patterns.

**Example Prompts (General):**
- "What URLs are being filtered?"
- "Show me all URL filters"
- "List blocked websites"

**Example Prompts (Advanced):**
- "Show me all URL filter rules and tell me which ones might be blocking educational content"
- "List all URL filters and organize them by category (social media, gaming, streaming, etc.)"

**Real-World Use Cases:**
- Audit which sites are currently blocked or allowed
- Review filters before making changes
- Document network security policies
- Troubleshoot unexpected site blocking
- Verify parental control rules are working as intended

### set_url_filter_mode
Switch URL filtering between blacklist mode (block listed sites) and whitelist mode (allow only listed sites).

**Example Prompts (General):**
- "Switch URL filter to whitelist mode"
- "Change to blacklist mode"
- "Enable whitelist for strict filtering"

**Example Prompts (Advanced):**
- "Switch to whitelist mode and explain the difference from blacklist mode"
- "Change to whitelist mode for maximum security - only allow approved educational sites"

**Real-World Use Cases:**
- Implement strict parental controls with whitelist (only allow approved sites)
- Switch to blacklist for general blocking of specific unwanted sites
- Create highly restrictive guest network (whitelist of business sites only)
- Implement school/work environment with limited site access
- Lock down network during homework hours (whitelist educational sites)

### get_keyword_filter_status
Get current status of keyword-based filtering.

**Example Prompts (General):**
- "Is keyword filtering enabled?"
- "Show me keyword filter status"
- "Check if keyword blocking is active"

**Example Prompts (Advanced):**
- "Show keyword filter status and list how many keywords are being filtered"
- "Check if keyword filtering is enabled and what effect it has on network traffic"

**Real-World Use Cases:**
- Verify keyword filters are active for content blocking
- Check filter status when troubleshooting search result access
- Audit content filtering configuration
- Confirm security policy compliance
- Validate parental control effectiveness

### add_keyword_filter
Add keyword to filter list (blocks any URL containing the keyword).

**Example Prompts (General):**
- "Block sites with 'gambling' in the URL"
- "Add 'adult' to keyword filter"
- "Filter URLs containing 'game'"

**Example Prompts (Advanced):**
- "Add multiple inappropriate keywords to filter: gambling, casino, poker, betting"
- "Block social media keywords: facebook, twitter, instagram, snapchat, tiktok"

**Real-World Use Cases:**
- Block gambling sites by filtering 'casino', 'poker', 'betting' keywords
- Implement parental controls with inappropriate content keywords
- Block social media by filtering platform names
- Prevent access to streaming sites with keywords like 'stream', 'video'
- Filter job search sites during work hours ('indeed', 'linkedin', 'glassdoor')

### remove_keyword_filter
Remove keyword from filter list.

**Example Prompts (General):**
- "Remove 'gaming' from keyword filter"
- "Unblock keyword 'social'"
- "Delete the 'video' keyword filter"

**Example Prompts (Advanced):**
- "Remove all social media keywords I added yesterday"
- "Clean up keyword filters that are blocking too many legitimate sites"

**Real-World Use Cases:**
- Adjust overly aggressive filters blocking legitimate content
- Remove temporary filters after time-based restrictions end
- Fine-tune keyword lists to reduce false positives
- Update filter policies based on user feedback
- Remove outdated or unnecessary keyword blocks

### list_keyword_filters
Show all current keyword filters.

**Example Prompts (General):**
- "What keywords are being filtered?"
- "Show me all keyword filters"
- "List blocked keywords"

**Example Prompts (Advanced):**
- "List all keyword filters and show me which ones might be too broad"
- "Show keyword filters and suggest optimizations to reduce false blocking"

**Real-World Use Cases:**
- Audit content filtering policies
- Review keywords before adding new ones to avoid duplicates
- Troubleshoot unexpected website blocking
- Document network security configuration
- Verify parental control keyword coverage

### add_device_url_filter
Add URL/keyword filter pattern for specific device (per-device filtering).

**Example Prompts (General):**
- "Block facebook for device AA:BB:CC:DD:EE:FF"
- "Add gaming filter for my child's laptop"
- "Filter youtube on the tablet"

**Example Prompts (Advanced):**
- "Add strict social media filtering for device AA:BB:CC:DD:EE:FF: block facebook, twitter, instagram, snapchat, tiktok"
- "Create device-specific gaming filter for MAC AA:BB:CC:DD:EE:FF blocking: steam, xbox, playstation, twitch"

**Real-World Use Cases:**
- Apply stricter filtering to children's devices while leaving adult devices unrestricted
- Block work-related distractions on personal devices during office hours
- Implement different filter policies per family member
- Create device-specific parental controls for tablets and phones
- Allow streaming on living room TV but block on bedroom devices

### remove_device_url_filter
Remove URL/keyword filter pattern from specific device.

**Example Prompts (General):**
- "Remove facebook filter from device AA:BB:CC:DD:EE:FF"
- "Unblock youtube on the tablet"
- "Delete gaming filter for this laptop"

**Example Prompts (Advanced):**
- "Remove all social media filters from device AA:BB:CC:DD:EE:FF"
- "Clean up device-specific filters for devices that are no longer in use"

**Real-World Use Cases:**
- Adjust individual device permissions as children get older
- Remove temporary restrictions after time periods expire
- Update filters when devices change ownership
- Relax filters for weekend/vacation periods
- Fix overly restrictive filters on specific devices

### list_device_url_filters
Show URL/keyword filters applied to specific devices.

**Example Prompts (General):**
- "What filters are on device AA:BB:CC:DD:EE:FF?"
- "Show me device-specific URL filters"
- "List all per-device filters"

**Example Prompts (Advanced):**
- "Show me all device-specific filters and organize them by device name/owner"
- "List per-device filters and highlight which devices have the strictest filtering"

**Real-World Use Cases:**
- Audit parental control configurations per device
- Review child's device filtering before adjusting permissions
- Verify device-specific filters are working correctly
- Document family network filtering policies
- Troubleshoot why specific device can't access certain sites

---

**URL Filtering Modes:**
- **Blacklist Mode (0)**: Block access to URLs matching the filter list (allow everything else)
- **Whitelist Mode (1)**: Allow ONLY URLs matching the filter list (block everything else)

**Filter Pattern Format:**
- URL filters: Simple keyword or domain matching (e.g., "facebook", "youtube.com", "gaming")
- Keyword filters: Blocks any URL containing the keyword anywhere in the address
- Per-device filters: Same pattern format, but applied only to specific MAC addresses

**Important Notes:**
- URL/Keyword filters apply at the router level (cannot be bypassed with VPN if VPN traffic also routed through router)
- Filters are case-insensitive
- Both URL and keyword filters can work simultaneously
- Per-device filters override global filters for specific devices
- Maximum 64 rules each for URL filters and keyword filters
- Service restart required: Changes take effect immediately via automatic firewall restart

---

## Network Service Filtering Tools (6 tools - NEW in v3.0)

### get_network_service_filter_status
Get comprehensive status of both deny and allow lists including rules, schedules, and configuration.

**Example Prompts (General):**
- "Show network service filter status"
- "What network service filters are configured?"
- "Get the current network service filter settings"

**Example Prompts (Advanced):**
- "Show me both deny and allow list status with all rules and schedules"
- "Display network service filter configuration with active days and time ranges"

**Real-World Use Cases:**
- Audit network service restrictions before making changes
- Verify parental control schedules are correctly configured
- Check which services are blocked/allowed for troubleshooting
- Review security policies for network access control
- Monitor active filtering rules and their schedules

### list_network_service_filter_rules
List all rules for either the deny list (black list) or allow list (white list).

**Example Prompts (General):**
- "List network service filter deny list rules"
- "Show me allow list rules for network services"
- "What's in the network service filter black list?"

**Example Prompts (Advanced):**
- "List all deny list rules showing source IP, destination IP, ports, and protocols"
- "Show me the allow list with complete rule details"

**Real-World Use Cases:**
- Review blocking rules before modifying network policy
- Audit allow list to ensure critical services aren't restricted
- Document current network service restrictions
- Troubleshoot connectivity issues by checking filter rules
- Verify rules match security requirements

### add_network_service_filter_rule
Add rule to block/allow specific network services by IP address, port, and protocol.

**Example Prompts (General):**
- "Block port 80 from 192.168.0.10"
- "Add deny rule for device 192.168.0.5 to block HTTPS traffic"
- "Block all outbound traffic on port 443 from 192.168.0.20"

**Example Prompts (Advanced):**
- "Add network service filter deny rule: source IP 192.168.0.10, destination port 80, protocol TCP"
- "Block UDP port 53 from 192.168.0.15 to any destination"
- "Create allow list rule for device 192.168.0.50 port 443 TCP"

**Real-World Use Cases:**
- Block HTTP/HTTPS for specific devices during work hours
- Prevent gaming consoles from accessing specific ports
- Implement parental controls by blocking service ports
- Restrict P2P traffic by blocking common ports
- Create custom firewall rules for specific device/service combinations
- Block DNS (port 53) to force specific DNS servers

### remove_network_service_filter_rule
Remove network service filter rule by matching all criteria exactly.

**Example Prompts (General):**
- "Remove network service filter rule for 192.168.0.10 port 80"
- "Delete the deny rule blocking HTTPS from 192.168.0.5"
- "Remove network service filter for device 192.168.0.20"

**Example Prompts (Advanced):**
- "Remove deny list rule: source 192.168.0.10, destination port 80, protocol TCP"
- "Delete network service filter rule with source IP 192.168.0.15, destination port 53, UDP protocol"

**Real-World Use Cases:**
- Remove temporary blocking rules after work hours
- Clean up test rules after troubleshooting
- Remove outdated parental control restrictions
- Delete rules for devices no longer on network
- Adjust network policy by removing restrictive rules

### set_network_service_filter_mode
Enable or disable the deny list (black list) or allow list (white list).

**Example Prompts (General):**
- "Enable network service filter deny list"
- "Disable the network service filter allow list"
- "Turn off network service filter"

**Example Prompts (Advanced):**
- "Enable the deny list for network service filtering"
- "Disable allow list mode and clear active restrictions"

**Real-World Use Cases:**
- Temporarily disable filtering for troubleshooting
- Enable parental controls during school hours
- Switch between permissive and restrictive modes
- Quick enable/disable for network policy changes
- Activate filters for specific time periods

### set_network_service_filter_schedule
Configure active days and time ranges for when filtering rules apply.

**Example Prompts (General):**
- "Set network service filter to weekdays 9 AM to 5 PM"
- "Schedule deny list for Monday, Wednesday, Friday from 8 AM to 6 PM"
- "Set network filter to run all week from 6 PM to 10 PM"

**Example Prompts (Advanced):**
- "Configure deny list schedule: Mon/Wed/Fri active, weekday time 08:00-17:00, weekend 00:00-23:59"
- "Set network service filter schedule for deny list: all days active, 06:00-22:00"
- "Schedule allow list for weekdays only 09:00-17:00, weekends 10:00-16:00"

**Real-World Use Cases:**
- Implement parental controls during homework hours (4PM-8PM weekdays)
- Block gaming services during school/work hours
- Restrict social media access during business hours
- Create weekend-only restrictions for specific devices
- Schedule content filtering for after-hours only
- Implement different rules for weekdays vs weekends

**Important Notes:**
- **Deny List (Black List)**: During scheduled times, blocks listed services. Outside schedule, all services allowed.
- **Allow List (White List)**: During scheduled times, ONLY allows listed services. Outside schedule, normal routing applies.
- **Days Format**: 7-character string (Sun-Sat), '1'=active, '0'=inactive. Example: '0111110' = Mon-Fri only
- **Time Format**: HHMM format, e.g., '0800' for 8:00 AM, '1700' for 5:00 PM
- **Source IP**: Leave blank to apply rule to ALL LAN devices
- **Protocols**: TCP, UDP, or specific TCP flags (TCPSYN, TCPACK, TCPFIN, TCPRST, TCPURG, TCPPSH)
- **Maximum Rules**: 128 rules per list (deny/allow)
- **Service Restart**: Changes take effect immediately via automatic firewall restart

---

## Tips for Using These Tools

1. **Natural Language**: You can use natural language - Claude will understand your intent and map it to the appropriate tool.

2. **MAC Address Format**: MAC addresses can be in any common format (AA:BB:CC:DD:EE:FF, aa-bb-cc-dd-ee-ff, etc.) - they will be normalized automatically.

3. **Combining Operations**: You can chain multiple operations in one request:
   - "Add DHCP reservation for AA:BB:CC:DD:EE:FF at 192.168.1.50, then block it from internet"

4. **Error Recovery**: If a command fails, the error message will guide you on what went wrong.

5. **Confirmation Required**: Destructive operations (reboot, NVRAM commit) require explicit confirmation.

6. **File Operations**: All file uploads and downloads are verified with MD5 checksums for data integrity.

---

**Total Tools**: 47 tools across 9 categories
- System Information: 14 tools
- Firewall Management: 2 tools
- URL/Keyword Filtering: 9 tools
- Network Service Filtering: 6 tools (NEW in v3.0)
- MAC Filtering: 3 tools
- DHCP Management: 3 tools
- Internet Access Control: 2 tools
- VPN Routing Policy: 3 tools
- VPN Server Monitoring: 2 tools
