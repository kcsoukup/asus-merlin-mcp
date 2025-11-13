"""
NVRAM list parsing and building utilities.

Handles ASUS router's special delimited list format: <item1>item2>item3>
"""


def parse_nvram_list(value: str, delimiter: str = "<") -> list[str]:
    """
    Parse NVRAM delimited list into Python list.

    ASUS routers use '<' and '>' as delimiters for list-based NVRAM variables.
    Format: <item1>item2>item3>

    Args:
        value: NVRAM value string to parse
        delimiter: Delimiter character (default: '<')

    Returns:
        List of items extracted from NVRAM string

    Examples:
        >>> parse_nvram_list("<AA:BB:CC:DD:EE:FF>11:22:33:44:55:66>")
        ['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66']
        >>> parse_nvram_list("")
        []
    """
    if not value or value.strip() == "":
        return []

    # Remove leading '<' and split by '>'
    items = value.lstrip(delimiter).rstrip(">").split(">")
    # Filter out empty strings
    return [item.strip() for item in items if item.strip()]


def build_nvram_list(items: list[str], delimiter: str = "<") -> str:
    """
    Build NVRAM delimited string from Python list.

    Args:
        items: List of items to convert
        delimiter: Delimiter character (default: '<')

    Returns:
        NVRAM-formatted delimited string

    Examples:
        >>> build_nvram_list(['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'])
        '<AA:BB:CC:DD:EE:FF>11:22:33:44:55:66>'
        >>> build_nvram_list([])
        ''
    """
    if not items:
        return ""
    return delimiter + ">".join(items) + ">"


def parse_dhcp_reservation_list(value: str) -> list[dict[str, str]]:
    """
    Parse DHCP reservation list from NVRAM format.

    Format: <MAC>IP>DNS>hostname<MAC2>IP2>DNS2>hostname2>
    All fields after IP are optional (DNS and hostname)

    Note: ASUS UI labels are reversed - UI "Hostname" writes to field 4 (hostname),
    UI "DNS Server" writes to field 3 (DNS).

    Args:
        value: NVRAM DHCP reservation string

    Returns:
        List of dicts with 'mac', 'ip', 'dns', and 'hostname' keys

    Examples:
        >>> parse_dhcp_reservation_list("<AA:BB:CC:DD:EE:FF>192.168.1.100>>Device1>")
        [{'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '192.168.1.100', 'dns': '', 'hostname': 'Device1'}]
    """
    if not value or value.strip() == "":
        return []

    reservations = []

    # Split by '<' to get each reservation block
    blocks = [block for block in value.split("<") if block.strip()]

    for block in blocks:
        # Remove trailing '>' and split by '>'
        parts = block.rstrip(">").split(">")

        if len(parts) >= 2:
            mac = parts[0].strip()
            ip = parts[1].strip()
            dns = parts[2].strip() if len(parts) > 2 else ""
            hostname = parts[3].strip() if len(parts) > 3 else ""

            if mac and ip:
                reservations.append(
                    {"mac": mac, "ip": ip, "dns": dns, "hostname": hostname}
                )

    return reservations


def build_dhcp_reservation_list(reservations: list[dict[str, str]]) -> str:
    """
    Build DHCP reservation NVRAM string from list of reservations.

    Format: <MAC>IP>DNS>hostname>
    DNS and hostname are optional fields

    Note: ASUS UI labels are reversed - to set hostname via UI, it goes to field 4.
    To set DNS via UI, it goes to field 3.

    Args:
        reservations: List of dicts with 'mac', 'ip', 'dns', and 'hostname' keys

    Returns:
        NVRAM-formatted DHCP reservation string

    Examples:
        >>> build_dhcp_reservation_list([{'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '192.168.1.100', 'dns': '', 'hostname': 'Device1'}])
        '<AA:BB:CC:DD:EE:FF>192.168.1.100>>Device1>'
    """
    if not reservations:
        return ""

    parts = []
    for res in reservations:
        mac = res.get("mac", "")
        ip = res.get("ip", "")
        dns = res.get("dns", "")
        hostname = res.get("hostname", "")
        if mac and ip:
            # Format: <MAC>IP>DNS>hostname
            parts.append(f"<{mac}>{ip}>{dns}>{hostname}")

    return "".join(parts) + ">" if parts else ""


def parse_multifilter_list(value: str) -> list[str]:
    """
    Parse MULTIFILTER NVRAM variable (uses > delimiter, NO leading <).

    MULTIFILTER variables use a different format than MAC filtering:
    - Format: MAC1>MAC2>MAC3 or NAME1>NAME2>NAME3
    - Uses '>' as delimiter between items
    - NO leading '<' character
    - Has trailing '>' at end

    This is used for parental control (MULTIFILTER_MAC, MULTIFILTER_DEVICENAME, etc.)
    and per-device URL filtering.

    Args:
        value: NVRAM MULTIFILTER_* value

    Returns:
        List of items (MACs, names, etc.)

    Examples:
        >>> parse_multifilter_list("AA:BB:CC:DD:EE:FF>11:22:33:44:55:66>")
        ['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66']
        >>> parse_multifilter_list("")
        []
    """
    if not value or value.strip() == "":
        return []

    # Split by '>' and filter empty strings
    items = [item.strip() for item in value.split(">") if item.strip()]
    return items


def build_multifilter_list(items: list[str]) -> str:
    """
    Build MULTIFILTER NVRAM string (uses > delimiter, NO leading <).

    MULTIFILTER format differs from MAC filtering format:
    - Format: MAC1>MAC2>MAC3
    - Uses '>' as delimiter
    - NO leading '<' character
    - Has trailing '>' at end

    Args:
        items: List of items (MACs, names, etc.)

    Returns:
        NVRAM-formatted MULTIFILTER string

    Examples:
        >>> build_multifilter_list(['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'])
        'AA:BB:CC:DD:EE:FF>11:22:33:44:55:66>'
        >>> build_multifilter_list([])
        ''
    """
    if not items:
        return ""

    # Join with '>' and add trailing '>'
    return ">".join(items) + ">"


def parse_vpn_fusion_policy_list(value: str) -> list[dict[str, str]]:
    """
    Parse VPN Fusion device routing policy list.

    VPN Fusion uses a 6-field format to route devices through VPN clients.
    Format: <MAC>IP>DNS>vpn_idx>active>hostname<MAC2>IP2>DNS2>vpn_idx2>active2>hostname2>

    Fields:
        1. MAC address (uppercase, colon-separated)
        2. IP address (can be empty for DHCP-assigned IPs)
        3. DNS server (optional, can be empty)
        4. VPN client index (1-5) - which VPN client to route through
        5. Active status (1=active, 0=inactive)
        6. Hostname (optional, can be empty)

    Delimiters:
        - Entry separator: <
        - Field separator: >
        - Trailing delimiter: >

    Args:
        value: NVRAM vpnc_dev_policy_list value

    Returns:
        List of policy dicts with keys: mac, ip, dns, vpn_client, active, hostname

    Examples:
        >>> parse_vpn_fusion_policy_list('<AA:BB:CC:DD:EE:FF>192.168.1.100>8.8.8.8>1>1>Laptop>')
        [{'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '192.168.1.100', 'dns': '8.8.8.8',
          'vpn_client': '1', 'active': '1', 'hostname': 'Laptop'}]
        >>> parse_vpn_fusion_policy_list('<AA:BB:CC:DD:EE:FF>>9.9.9.9>2>1>>')
        [{'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '', 'dns': '9.9.9.9',
          'vpn_client': '2', 'active': '1', 'hostname': ''}]
        >>> parse_vpn_fusion_policy_list('')
        []
    """
    if not value or value.strip() == "":
        return []

    policies = []
    # Split by '<' to get individual entries
    blocks = [block for block in value.split("<") if block.strip()]

    for block in blocks:
        # Split by '>' to get fields, remove trailing '>'
        parts = block.rstrip(">").split(">")

        # Need at least MAC and vpn_client fields (4 minimum)
        if len(parts) >= 4:
            mac = parts[0].strip()
            ip = parts[1].strip() if len(parts) > 1 else ""
            dns = parts[2].strip() if len(parts) > 2 else ""
            vpn_client = parts[3].strip() if len(parts) > 3 else "1"
            active = parts[4].strip() if len(parts) > 4 else "1"
            hostname = parts[5].strip() if len(parts) > 5 else ""

            if mac:  # Only add if MAC is present
                policies.append(
                    {
                        "mac": mac,
                        "ip": ip,
                        "dns": dns,
                        "vpn_client": vpn_client,
                        "active": active,
                        "hostname": hostname,
                    }
                )

    return policies


def build_vpn_fusion_policy_list(policies: list[dict[str, str]]) -> str:
    """
    Build VPN Fusion policy list string.

    Creates NVRAM-formatted string for vpnc_dev_policy_list variable.
    Format: <MAC>IP>DNS>vpn_idx>active>hostname<MAC2>...>

    Args:
        policies: List of policy dicts with keys: mac, ip, dns, vpn_client, active, hostname

    Returns:
        NVRAM-formatted vpnc_dev_policy_list string

    Examples:
        >>> policies = [{'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '192.168.1.100',
        ...              'dns': '8.8.8.8', 'vpn_client': '1', 'active': '1', 'hostname': 'Laptop'}]
        >>> build_vpn_fusion_policy_list(policies)
        '<AA:BB:CC:DD:EE:FF>192.168.1.100>8.8.8.8>1>1>Laptop>'
        >>> policies = [{'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '', 'dns': '',
        ...              'vpn_client': '2', 'active': '1', 'hostname': ''}]
        >>> build_vpn_fusion_policy_list(policies)
        '<AA:BB:CC:DD:EE:FF>>>2>1>>'
        >>> build_vpn_fusion_policy_list([])
        ''
    """
    if not policies:
        return ""

    parts = []
    for policy in policies:
        mac = policy.get("mac", "")
        ip = policy.get("ip", "")
        dns = policy.get("dns", "")
        vpn_client = policy.get("vpn_client", "1")
        active = policy.get("active", "1")
        hostname = policy.get("hostname", "")

        if mac and vpn_client:  # MAC and VPN client are required
            parts.append(f"<{mac}>{ip}>{dns}>{vpn_client}>{active}>{hostname}")

    return "".join(parts) + ">" if parts else ""


def detect_vpn_policy_format(value: str) -> str:
    """
    Detect VPN policy format by analyzing the NVRAM value structure.

    Determines whether the vpnc_dev_policy_list uses the older 5-field IP-based
    format (firmware 388.10) or the newer 6-field MAC-based format.

    Detection Logic:
        - Checks first entry's first field
        - If field 1 matches MAC pattern (XX:XX:XX:XX:XX:XX) → MAC-based format
        - If field 1 is numeric (0 or 1 for activate flag) → IP-based format
        - Empty/invalid → defaults to IP-based format (safer for older firmware)

    Args:
        value: NVRAM vpnc_dev_policy_list value

    Returns:
        Format identifier: "mac" for MAC-based (6-field), "ip" for IP-based (5-field)

    Examples:
        >>> detect_vpn_policy_format('<AA:BB:CC:DD:EE:FF>192.168.1.100>>1>1>hostname>')
        'mac'
        >>> detect_vpn_policy_format('<1>192.168.1.100>>1>br0>')
        'ip'
        >>> detect_vpn_policy_format('')
        'ip'
    """
    if not value or value.strip() == "":
        return "ip"  # Default to IP format for empty values

    # Extract first entry
    blocks = [block for block in value.split("<") if block.strip()]
    if not blocks:
        return "ip"

    # Get first field of first entry
    parts = blocks[0].rstrip(">").split(">")
    if not parts or not parts[0].strip():
        return "ip"

    first_field = parts[0].strip()

    # Check if first field looks like a MAC address (contains colons)
    if ":" in first_field and len(first_field) == 17:
        return "mac"

    # Otherwise assume IP-based format (first field is activate: 0 or 1)
    return "ip"


def parse_vpn_fusion_ip_policy_list(value: str) -> list[dict[str, str]]:
    """
    Parse VPN Fusion IP-based device routing policy list (firmware 388.10 format).

    Older firmware versions (e.g., 388.10) use a 5-field IP-based format integrated
    into the DHCP page instead of the newer 6-field MAC-based format.

    Format: <activate>ip>dest_ip>vpnc_idx>brifname<activate2>ip2>dest_ip2>vpnc_idx2>brifname2>

    Fields:
        1. activate: Active status (1=active, 0=inactive)
        2. ip: Source IP address (device IP to route)
        3. dest_ip: Destination IP (optional, often empty for "all destinations")
        4. vpnc_idx: VPN client index (1-5) - which VPN client to route through
        5. brifname: Bridge interface name (e.g., "br0", typically for network isolation)

    Delimiters:
        - Entry separator: <
        - Field separator: >
        - Trailing delimiter: >

    Args:
        value: NVRAM vpnc_dev_policy_list value (IP-based format)

    Returns:
        List of policy dicts with keys: active, ip, dest_ip, vpn_client, interface

    Examples:
        >>> parse_vpn_fusion_ip_policy_list('<1>192.168.1.100>>1>br0>')
        [{'active': '1', 'ip': '192.168.1.100', 'dest_ip': '', 'vpn_client': '1', 'interface': 'br0'}]
        >>> parse_vpn_fusion_ip_policy_list('<1>192.168.1.50>8.8.8.8>2>br0>')
        [{'active': '1', 'ip': '192.168.1.50', 'dest_ip': '8.8.8.8', 'vpn_client': '2', 'interface': 'br0'}]
        >>> parse_vpn_fusion_ip_policy_list('')
        []
    """
    if not value or value.strip() == "":
        return []

    policies = []
    # Split by '<' to get individual entries
    blocks = [block for block in value.split("<") if block.strip()]

    for block in blocks:
        # Split by '>' to get fields, remove trailing '>'
        parts = block.rstrip(">").split(">")

        # Need at least activate, ip, and vpnc_idx fields (minimum 4 fields)
        if len(parts) >= 4:
            activate = parts[0].strip()
            ip = parts[1].strip() if len(parts) > 1 else ""
            dest_ip = parts[2].strip() if len(parts) > 2 else ""
            vpnc_idx = parts[3].strip() if len(parts) > 3 else "1"
            brifname = parts[4].strip() if len(parts) > 4 else "br0"

            if ip:  # Only add if IP is present
                policies.append(
                    {
                        "active": activate,
                        "ip": ip,
                        "dest_ip": dest_ip,
                        "vpn_client": vpnc_idx,
                        "interface": brifname,
                    }
                )

    return policies


def build_vpn_fusion_ip_policy_list(policies: list[dict[str, str]]) -> str:
    """
    Build VPN Fusion IP-based policy list string (firmware 388.10 format).

    Creates NVRAM-formatted string for vpnc_dev_policy_list variable using
    the older 5-field IP-based format.

    Format: <activate>ip>dest_ip>vpnc_idx>brifname<activate2>ip2>...>

    Args:
        policies: List of policy dicts with keys: active, ip, dest_ip, vpn_client, interface

    Returns:
        NVRAM-formatted vpnc_dev_policy_list string (IP-based format)

    Examples:
        >>> policies = [{'active': '1', 'ip': '192.168.1.100', 'dest_ip': '',
        ...              'vpn_client': '1', 'interface': 'br0'}]
        >>> build_vpn_fusion_ip_policy_list(policies)
        '<1>192.168.1.100>>1>br0>'
        >>> policies = [{'active': '1', 'ip': '192.168.1.50', 'dest_ip': '8.8.8.8',
        ...              'vpn_client': '2', 'interface': 'br0'}]
        >>> build_vpn_fusion_ip_policy_list(policies)
        '<1>192.168.1.50>8.8.8.8>2>br0>'
        >>> build_vpn_fusion_ip_policy_list([])
        ''
    """
    if not policies:
        return ""

    parts = []
    for policy in policies:
        active = policy.get("active", "1")
        ip = policy.get("ip", "")
        dest_ip = policy.get("dest_ip", "")
        vpn_client = policy.get("vpn_client", "1")
        interface = policy.get("interface", "br0")

        if ip and vpn_client:  # IP and VPN client are required
            parts.append(f"<{active}>{ip}>{dest_ip}>{vpn_client}>{interface}")

    return "".join(parts) + ">" if parts else ""


def parse_vpn_director_rules(value: str) -> list[dict[str, str]]:
    """
    Parse VPN Director rules (Asuswrt-Merlin firmware).

    VPN Director is Merlin's replacement for VPN Fusion. It uses a simpler
    5-field format for policy-based routing rules.

    Format: <enable>description>localIP>remoteIP>interface<enable2>description2>localIP2>remoteIP2>interface2>

    Fields:
        1. enable: "1" (enabled) or "0" (disabled)
        2. description: Rule name/description
        3. localIP: Source IP address (device IP to route)
        4. remoteIP: Destination IP (empty = all destinations)
        5. interface: VPN interface (OVPN1-5, WGC1-5, WAN)

    Delimiters:
        - Entry separator: <
        - Field separator: >
        - Trailing delimiter: >

    Args:
        value: NVRAM vpndirector_rulelist value

    Returns:
        List of rule dicts with keys: enable, description, local_ip, remote_ip, interface

    Examples:
        >>> parse_vpn_director_rules('<1>MyDevice>192.168.0.237>>OVPN3>')
        [{'enable': '1', 'description': 'MyDevice', 'local_ip': '192.168.0.237',
          'remote_ip': '', 'interface': 'OVPN3'}]
        >>> parse_vpn_director_rules('<1>Work>192.168.0.100>10.0.0.0/8>OVPN1>')
        [{'enable': '1', 'description': 'Work', 'local_ip': '192.168.0.100',
          'remote_ip': '10.0.0.0/8', 'interface': 'OVPN1'}]
        >>> parse_vpn_director_rules('')
        []
    """
    if not value or value.strip() == "":
        return []

    rules = []
    # Split by '<' to get individual entries
    blocks = [block for block in value.split("<") if block.strip()]

    for block in blocks:
        # Split by '>' to get fields, remove trailing '>'
        parts = block.rstrip(">").split(">")

        # Need all 5 fields
        if len(parts) >= 5:
            enable = parts[0].strip()
            description = parts[1].strip()
            local_ip = parts[2].strip()
            remote_ip = parts[3].strip()
            interface = parts[4].strip()

            if local_ip and interface:  # LocalIP and interface are required
                rules.append(
                    {
                        "enable": enable,
                        "description": description,
                        "local_ip": local_ip,
                        "remote_ip": remote_ip,
                        "interface": interface,
                    }
                )

    return rules


def build_vpn_director_rules(rules: list[dict[str, str]]) -> str:
    """
    Build VPN Director rules string (Asuswrt-Merlin firmware).

    Creates NVRAM-formatted string for vpndirector_rulelist variable.
    Format: <enable>description>localIP>remoteIP>interface>

    Args:
        rules: List of rule dicts with keys: enable, description, local_ip, remote_ip, interface

    Returns:
        NVRAM-formatted vpndirector_rulelist string

    Examples:
        >>> rules = [{'enable': '1', 'description': 'MyDevice', 'local_ip': '192.168.0.237',
        ...           'remote_ip': '', 'interface': 'OVPN3'}]
        >>> build_vpn_director_rules(rules)
        '<1>MyDevice>192.168.0.237>>OVPN3>'
        >>> rules = [{'enable': '1', 'description': 'Work', 'local_ip': '192.168.0.100',
        ...           'remote_ip': '10.0.0.0/8', 'interface': 'OVPN1'}]
        >>> build_vpn_director_rules(rules)
        '<1>Work>192.168.0.100>10.0.0.0/8>OVPN1>'
        >>> build_vpn_director_rules([])
        ''
    """
    if not rules:
        return ""

    parts = []
    for rule in rules:
        enable = rule.get("enable", "1")
        description = rule.get("description", "")
        local_ip = rule.get("local_ip", "")
        remote_ip = rule.get("remote_ip", "")
        interface = rule.get("interface", "")

        if local_ip and interface:  # LocalIP and interface are required
            parts.append(f"<{enable}>{description}>{local_ip}>{remote_ip}>{interface}")

    return "".join(parts) + ">" if parts else ""
