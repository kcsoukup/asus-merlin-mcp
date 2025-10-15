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
  Asuswrt-Merlin Firmware Home -- https://www.asuswrt-merlin.net/
"""

__project__ = "MCP Server for ASUS Router"
__version__ = "1.0"
__author__ = "Ken C. Soukup"
__company__ = "Vigorous Programming"
__minted__ = "2025"

import asyncio
import logging
from typing import Any, Sequence, Optional
import paramiko
from mcp.server import Server
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource
import mcp.server.stdio
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("asus-merlin-mcp")

# Router connection configuration
ROUTER_CONFIG = {
    "host": os.getenv("ROUTER_HOST", "192.168.1.1"),
    "port": int(os.getenv("ROUTER_PORT", "22")),
    "username": os.getenv("ROUTER_USER", "admin"),
    "password": os.getenv("ROUTER_PASSWORD", ""),
    "key_file": os.getenv("ROUTER_KEY_FILE", ""),
}


class RouterSSHClient:
    """Handles SSH connections to the ASUS router"""

    def __init__(self, config: dict):
        self.config = config
        self.client: Optional[paramiko.SSHClient] = None

    def connect(self):
        """Establish SSH connection to router"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Use key-based auth if key file provided, otherwise password
            if self.config["key_file"] and os.path.exists(self.config["key_file"]):
                self.client.connect(
                    hostname=self.config["host"],
                    port=self.config["port"],
                    username=self.config["username"],
                    key_filename=self.config["key_file"],
                    timeout=10,
                )
            else:
                self.client.connect(
                    hostname=self.config["host"],
                    port=self.config["port"],
                    username=self.config["username"],
                    password=self.config["password"],
                    timeout=10,
                )
            logger.info(f"Connected to router at {self.config['host']}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to router: {e}")
            return False

    def execute_command(self, command: str) -> tuple[str, str, int]:
        """Execute a command on the router"""
        if not self.client:
            if not self.connect():
                return "", "Failed to connect to router", 1

        assert self.client is not None  # Type narrowing for Pylance
        try:
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode("utf-8", errors="replace")
            error = stderr.read().decode("utf-8", errors="replace")
            return output, error, exit_code
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return "", str(e), 1

    def upload_file(self, local_path: str, remote_path: str) -> tuple[bool, str]:
        """Upload file to router via SCP"""
        if not self.client:
            if not self.connect():
                return False, "Failed to connect to router"

        assert self.client is not None  # Type narrowing for Pylance
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            logger.info(f"Uploaded {local_path} to {remote_path}")
            return True, "SFTP upload successful"
        except Exception as e:
            error_msg = f"SFTP upload failed: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def download_file(self, remote_path: str, local_path: str) -> tuple[bool, str]:
        """Download file from router via SCP"""
        if not self.client:
            if not self.connect():
                return False, "Failed to connect to router"

        assert self.client is not None  # Type narrowing for Pylance
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            logger.info(f"Downloaded {remote_path} to {local_path}")
            return True, "SFTP download successful"
        except Exception as e:
            error_msg = f"SFTP download failed: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def upload_file_shell(self, local_path: str, remote_path: str) -> tuple[bool, str]:
        """Upload file to router using shell commands (fallback when SFTP unavailable)"""
        try:
            import hashlib

            # Read local file and calculate checksum
            with open(local_path, "rb") as f:
                content = f.read()
            local_md5 = hashlib.md5(content).hexdigest()

            # Convert to hex string
            hex_content = content.hex()

            # Split into chunks to avoid command line length limits (4000 chars per chunk)
            chunk_size = 4000
            chunks = [
                hex_content[i : i + chunk_size]
                for i in range(0, len(hex_content), chunk_size)
            ]

            # Clear/create the file first
            output, error, code = self.execute_command(f"> {remote_path}")
            if code != 0:
                error_msg = f"Shell upload failed to create file: {error}"
                logger.error(error_msg)
                return False, error_msg

            # Upload in chunks using printf with hex escape sequences
            for i, chunk in enumerate(chunks):
                # Convert hex pairs to \x escape sequences for printf
                escaped = "".join(
                    f"\\x{chunk[j : j + 2]}" for j in range(0, len(chunk), 2)
                )
                cmd = f"printf '{escaped}' >> {remote_path}"
                output, error, code = self.execute_command(cmd)

                if code != 0:
                    error_msg = (
                        f"Shell upload failed at chunk {i + 1}/{len(chunks)}: {error}"
                    )
                    logger.error(error_msg)
                    return False, error_msg

            # Verify upload with size and checksum
            verify_output, _, verify_code = self.execute_command(
                f"test -f {remote_path} && wc -c < {remote_path} && md5sum {remote_path}"
            )
            if verify_code == 0:
                lines = verify_output.strip().split("\n")
                remote_size = int(lines[0].strip())
                remote_md5 = lines[1].split()[0] if len(lines) > 1 else ""

                if remote_size != len(content):
                    error_msg = f"Shell upload size mismatch: expected {len(content)}, got {remote_size}"
                    logger.error(error_msg)
                    return False, error_msg

                if remote_md5 and remote_md5 != local_md5:
                    error_msg = f"Shell upload checksum mismatch: expected {local_md5}, got {remote_md5}"
                    logger.error(error_msg)
                    return False, error_msg

                logger.info(
                    f"Uploaded {local_path} to {remote_path} via shell ({len(content)} bytes, MD5: {local_md5})"
                )
                return (
                    True,
                    f"Shell-based upload successful ({len(content)} bytes, MD5: {local_md5}, verified)",
                )
            else:
                error_msg = "Shell upload verification failed: file not found on router"
                logger.error(error_msg)
                return False, error_msg

        except Exception as e:
            error_msg = f"Shell upload failed: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def download_file_shell(
        self, remote_path: str, local_path: str
    ) -> tuple[bool, str]:
        """Download file from router using shell commands (fallback when SFTP unavailable)"""
        try:
            import hashlib

            # Get remote file checksum first
            md5_output, _, md5_code = self.execute_command(f"md5sum {remote_path}")
            remote_md5 = ""
            if md5_code == 0:
                remote_md5 = md5_output.split()[0]

            # Use hexdump to get binary-safe output from router
            output, error, code = self.execute_command(
                f"hexdump -v -e '/1 \"%02x\"' {remote_path}"
            )

            if code != 0:
                error_msg = f"Shell download failed: {error}"
                logger.error(error_msg)
                return False, error_msg

            # Convert hex string back to binary
            try:
                binary_data = bytes.fromhex(output.strip())
            except ValueError as e:
                error_msg = f"Shell download failed to decode hex data: {e}"
                logger.error(error_msg)
                return False, error_msg

            # Calculate local checksum
            local_md5 = hashlib.md5(binary_data).hexdigest()

            # Verify checksum matches
            if remote_md5 and local_md5 != remote_md5:
                error_msg = f"Shell download checksum mismatch: expected {remote_md5}, got {local_md5}"
                logger.error(error_msg)
                return False, error_msg

            # Write to local file in binary mode
            with open(local_path, "wb") as f:
                f.write(binary_data)

            logger.info(
                f"Downloaded {remote_path} to {local_path} via shell ({len(binary_data)} bytes, MD5: {local_md5})"
            )
            return (
                True,
                f"Shell-based download successful ({len(binary_data)} bytes, MD5: {local_md5}, verified)",
            )
        except Exception as e:
            error_msg = f"Shell download failed: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.client = None


# Initialize MCP server
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
            description="Execute a custom command on the router via SSH",
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
            description="Upload a file to the router via SCP",
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
    ]


@app.call_tool()
async def call_tool(
    name: str, arguments: Any
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Handle tool calls"""

    try:
        if name == "get_router_info":
            output, error, code = router.execute_command(
                "echo '=== Uptime ==='; uptime; "
                "echo '=== Memory ==='; free; "
                "echo '=== Firmware ==='; nvram get firmver; nvram get buildno"
            )
            return [
                TextContent(
                    type="text", text=output if code == 0 else f"Error: {error}"
                )
            ]

        elif name == "get_connected_devices":
            output, error, code = router.execute_command(
                "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || arp -a"
            )
            return [
                TextContent(
                    type="text", text=output if code == 0 else f"Error: {error}"
                )
            ]

        elif name == "get_wifi_status":
            output, error, code = router.execute_command(
                "wl -i eth1 status 2>/dev/null; "
                "wl -i eth2 status 2>/dev/null; "
                "nvram get wl0_ssid; nvram get wl1_ssid"
            )
            return [
                TextContent(
                    type="text", text=output if code == 0 else f"Error: {error}"
                )
            ]

        elif name == "restart_service":
            service = arguments.get("service_name")
            output, error, code = router.execute_command(f"service restart_{service}")
            result = f"Service '{service}' restart command executed.\n{output}"
            if error:
                result += f"\nErrors: {error}"
            return [TextContent(type="text", text=result)]

        elif name == "reboot_router":
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

        elif name == "get_nvram_variable":
            var = arguments.get("variable_name")
            output, error, code = router.execute_command(f"nvram get {var}")
            return [
                TextContent(
                    type="text", text=output.strip() if code == 0 else f"Error: {error}"
                )
            ]

        elif name == "set_nvram_variable":
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

        elif name == "execute_command":
            cmd = arguments.get("command")
            output, error, code = router.execute_command(cmd)
            result = f"Command: {cmd}\n\nOutput:\n{output}"
            if error:
                result += f"\n\nErrors:\n{error}"
            result += f"\n\nExit code: {code}"
            return [TextContent(type="text", text=result)]

        elif name == "read_file":
            path = arguments.get("file_path")
            max_lines = arguments.get("max_lines", 100)
            output, error, code = router.execute_command(f"head -n {max_lines} {path}")
            return [
                TextContent(
                    type="text", text=output if code == 0 else f"Error: {error}"
                )
            ]

        elif name == "upload_file":
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
                    result += (
                        "Note: Used shell commands (SFTP not available on router)\n"
                    )
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

        elif name == "download_file":
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
                    result += (
                        "Note: Used shell commands (SFTP not available on router)\n"
                    )
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

        elif name == "get_vpn_status":
            output, error, code = router.execute_command(
                "nvram get vpn_client1_state; "
                "nvram get vpn_client2_state; "
                "ps | grep vpn"
            )
            return [
                TextContent(
                    type="text", text=output if code == 0 else f"Error: {error}"
                )
            ]

        elif name == "list_processes":
            filter_name = arguments.get("filter", "")
            cmd = "ps" if not filter_name else f"ps | grep {filter_name}"
            output, error, code = router.execute_command(cmd)
            return [
                TextContent(
                    type="text", text=output if code == 0 else f"Error: {error}"
                )
            ]

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
