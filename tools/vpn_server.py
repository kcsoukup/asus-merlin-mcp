"""
VPN server monitoring and management tools.
"""

from typing import Any

from mcp.types import TextContent

from core.ssh_client import RouterSSHClient


def handle_get_vpn_server_status(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """Get detailed VPN server status including connected clients."""
    result = "VPN Server Status Report\n"
    result += "=" * 70 + "\n\n"

    # Check both possible VPN servers (1 and 2)
    for server_num in [1, 2]:
        # Get server configuration
        state_output, _, _ = router.execute_command(
            f"nvram get vpn_server{server_num}_state"
        )
        proto_output, _, _ = router.execute_command(
            f"nvram get vpn_server{server_num}_proto"
        )
        port_output, _, _ = router.execute_command(
            f"nvram get vpn_server{server_num}_port"
        )
        sn_output, _, _ = router.execute_command(f"nvram get vpn_server{server_num}_sn")
        if_output, _, _ = router.execute_command(f"nvram get vpn_server{server_num}_if")

        state = state_output.strip()
        proto = proto_output.strip().upper()
        port = port_output.strip()
        subnet = sn_output.strip()
        interface = if_output.strip()

        # Determine status
        is_running = state == "2"
        status_text = "RUNNING" if is_running else "STOPPED"
        status_icon = "✓" if is_running else "⚫"

        result += f"VPN Server {server_num} - {status_icon} {status_text}\n"
        result += "-" * 70 + "\n"
        result += f"Protocol: {proto}\n"
        result += f"Port: {port}\n"
        result += f"Subnet: {subnet}\n"
        result += f"Interface: {interface}\n"

        if is_running:
            # Get interface details
            tun_if = f"tun{server_num}1" if server_num == 1 else f"tun{server_num}1"
            if_status, _, if_code = router.execute_command(
                f"ip addr show {tun_if} 2>/dev/null"
            )

            if if_code == 0 and if_status:
                # Extract IP address from interface
                for line in if_status.split("\n"):
                    if "inet " in line:
                        ip_info = line.strip().split()[1]
                        result += f"Server IP: {ip_info}\n"
                        break

            # Get connected clients from status file
            status_file = f"/etc/openvpn/server{server_num}/status"
            clients_output, _, clients_code = router.execute_command(
                f"cat {status_file} 2>/dev/null | grep '^CLIENT_LIST'"
            )

            if clients_code == 0 and clients_output:
                client_lines = [
                    line
                    for line in clients_output.split("\n")
                    if line and not line.startswith("HEADER")
                ]

                if client_lines:
                    result += f"\nConnected Clients: {len(client_lines)}\n"
                    result += "-" * 70 + "\n"
                    for idx, line in enumerate(client_lines, 1):
                        parts = line.split(",")
                        if len(parts) >= 8:
                            common_name = parts[1]
                            real_addr = parts[2]
                            virtual_addr = parts[3]
                            bytes_recv = parts[5]
                            bytes_sent = parts[6]
                            connected_since = parts[7]

                            # Format bytes
                            try:
                                recv_mb = int(bytes_recv) / (1024 * 1024)
                                sent_mb = int(bytes_sent) / (1024 * 1024)
                                data_str = f"↓{recv_mb:.1f}MB / ↑{sent_mb:.1f}MB"
                            except (ValueError, TypeError):
                                data_str = f"↓{bytes_recv} / ↑{bytes_sent}"

                            result += f"\n  Client {idx}: {common_name}\n"
                            result += f"    Real IP: {real_addr}\n"
                            result += f"    VPN IP: {virtual_addr}\n"
                            result += f"    Data: {data_str}\n"
                            result += f"    Connected: {connected_since}\n"
                else:
                    result += "\nConnected Clients: 0\n"
            else:
                result += "\nConnected Clients: 0 (or unable to read status)\n"

            # Get process info
            ps_output, _, _ = router.execute_command(
                f"ps | grep vpnserver{server_num} | grep -v grep"
            )
            if ps_output.strip():
                process_count = len(ps_output.strip().split("\n"))
                result += f"Processes: {process_count} running\n"
        else:
            result += "Status: Server is not running\n"

        result += "\n"

    result += "=" * 70 + "\n"
    return [TextContent(type="text", text=result)]


def handle_get_vpn_server_users(
    router: RouterSSHClient, _arguments: Any
) -> list[TextContent]:
    """Get list of users authorized to connect to VPN servers."""
    # Get list of system users that can authenticate to VPN servers
    result = "VPN Server Authorized Users\n"
    result += "=" * 70 + "\n\n"

    # Read /etc/passwd to get user list
    passwd_output, _, passwd_code = router.execute_command("cat /etc/passwd")

    if passwd_code != 0 or not passwd_output:
        return [
            TextContent(
                type="text",
                text="Error: Unable to read user list from /etc/passwd",
            )
        ]

    result += "Authentication Method: PAM (System Users)\n"
    result += "Users with valid passwords can connect to enabled VPN servers.\n\n"

    # Parse passwd file and categorize users
    system_users = []
    service_users = []

    for line in passwd_output.strip().split("\n"):
        if line.strip() and not line.startswith("#"):
            parts = line.split(":")
            if len(parts) >= 7:
                username = parts[0]
                uid = parts[2]
                gid = parts[3]
                home_dir = parts[5]
                shell = parts[6]

                # Categorize users
                if shell in ["/bin/sh", "/bin/bash", "/bin/ash"]:
                    # Real user accounts with shell access
                    system_users.append(
                        {
                            "username": username,
                            "uid": uid,
                            "gid": gid,
                            "home": home_dir,
                            "shell": shell,
                        }
                    )
                elif username not in ["nobody", "tor"]:
                    # Service accounts (can still authenticate via PAM)
                    service_users.append(
                        {
                            "username": username,
                            "uid": uid,
                            "gid": gid,
                            "home": home_dir,
                            "shell": shell,
                        }
                    )

    # Display user accounts
    if system_users:
        result += "User Accounts (Shell Access):\n"
        result += "-" * 70 + "\n"
        for user in system_users:
            result += f"  • {user['username']}\n"
            result += f"    UID: {user['uid']}, GID: {user['gid']}\n"
            result += f"    Home: {user['home']}, Shell: {user['shell']}\n"
            if user["uid"] == "0":
                result += "    Role: Administrator (root equivalent)\n"
            result += "\n"

    if service_users:
        result += "Service Accounts:\n"
        result += "-" * 70 + "\n"
        for user in service_users:
            result += f"  • {user['username']}\n"
            result += f"    UID: {user['uid']}, GID: {user['gid']}\n"
            result += f"    Shell: {user['shell']}\n\n"

    # Check which VPN servers are configured
    result += "VPN Server Configuration:\n"
    result += "-" * 70 + "\n"
    for server_num in [1, 2]:
        state_output, _, _ = router.execute_command(
            f"nvram get vpn_server{server_num}_state"
        )
        state = state_output.strip()

        if state == "2":
            result += f"  VPN Server {server_num}: ✓ Running (accepts above users)\n"
        elif state == "1":
            result += f"  VPN Server {server_num}: ⚫ Stopped (configured)\n"
        else:
            result += f"  VPN Server {server_num}: ⚪ Disabled\n"

    result += "\n" + "=" * 70 + "\n"
    result += "Note: Users must have valid passwords set to authenticate to VPN.\n"
    result += "Use SSH to set passwords: passwd <username>\n"

    return [TextContent(type="text", text=result)]
