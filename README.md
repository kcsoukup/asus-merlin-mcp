# ASUS Merlin Router MCP Server

Model Context Protocol (MCP) server for managing ASUS routers running Asuswrt-Merlin firmware via SSH/SCP.

## Features

- **System Information**: Get router uptime, memory, CPU, firmware version
- **Device Management**: List connected devices
- **WiFi Control**: Check WiFi status across all radios
- **Service Management**: Restart services (wireless, VPN, etc.)
- **NVRAM Operations**: Read/write router configuration variables
- **File Operations**: Upload/download files via SCP
- **VPN Management**: Check VPN status
- **Process Monitoring**: List running processes
- **Custom Commands**: Execute any SSH command

## Prerequisites

### Router Setup
1. Enable SSH on your router:
   - Login to router web interface
   - Go to **Administration > System**
   - Set **Enable SSH** to **LAN only** (or LAN & WAN if needed)
   - Click **Apply**

2. (Recommended) Set up SSH key authentication:
   ```bash
   # On your Debian workstation
   ssh-keygen -t rsa -b 4096

   # Copy your public key to router
   ssh-copy-id admin@192.168.1.1

   # Or manually via web interface:
   # Administration > System > SSH Authentication Key
   ```

### Debian Workstation Setup
```bash
# Install Python 3.11+ if not already installed
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Optional: Install Docker/Podman for containerized deployment
sudo apt install docker.io docker-compose
# OR
sudo apt install podman podman-compose
# OR
pip3 install podman-compose
```

## Installation

### Option 1: Local Installation (Recommended for Development)

1. **Clone or create project directory:**
   ```bash
   mkdir asus-merlin-mcp
   cd asus-merlin-mcp
   ```

2. **Save the MCP server code as `asus_merlin_mcp.py`**

3. **Create virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

4. **Configure router connection:**
   ```bash
   cp .env.example .env
   nano .env  # Edit with your router details
   ```

5. **Test the connection:**
   ```bash
   # Export environment variables
   export $(cat .env | xargs)

   # Run the server (it will connect via stdio)
   python asus_merlin_mcp.py
   ```

### Option 2: Docker Installation

1. **Build the Docker image:**
   ```bash
   docker build -t asus-merlin-mcp .
   ```

2. **Edit docker-compose.yml with your router credentials**

3. **Run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

### Option 3: Podman Installation

```bash
# Build with Podman
podman build -t asus-merlin-mcp .

# Run with Podman Compose
podman-compose up -d

# Or run directly
podman run -it --rm \
  -v ~/.ssh:/root/.ssh:ro \
  -e ROUTER_HOST=192.168.1.1 \
  -e ROUTER_PORT=22 \
  -e ROUTER_USER=admin \
  -e ROUTER_KEY_FILE=/root/.ssh/id_rsa \
  asus-merlin-mcp
```

## Claude Configuration

The configuration location depends on which Claude installation you're using:

### Claude Code (Native Installation)

MCP servers are automatically configured in `~/.claude.json` under your project path:

**Config file:** `~/.claude.json`

#### For Local Installation:
```json
{
  "installMethod": "native",
  "projects": {
    "/path/to/asus-merlin-mcp": {
      "mcpServers": {
        "asus-router": {
          "command": "/path/to/asus-merlin-mcp/venv/bin/python",
          "args": ["/path/to/asus-merlin-mcp/asus_merlin_mcp.py"],
          "env": {
            "ROUTER_HOST": "192.168.1.1",
            "ROUTER_PORT": "22",
            "ROUTER_USER": "admin",
            "ROUTER_KEY_FILE": "/home/yourusername/.ssh/id_rsa"
          }
        }
      }
    }
  }
}
```

#### For Docker Installation:
```json
{
  "installMethod": "native",
  "projects": {
    "/path/to/asus-merlin-mcp": {
      "mcpServers": {
        "asus-router": {
          "command": "docker",
          "args": [
            "run", "-i", "--rm",
            "-v", "/home/yourusername/.ssh:/root/.ssh:ro",
            "-e", "ROUTER_HOST=192.168.1.1",
            "-e", "ROUTER_PORT=22",
            "-e", "ROUTER_USER=admin",
            "-e", "ROUTER_KEY_FILE=/root/.ssh/id_rsa",
            "asus-merlin-mcp"
          ]
        }
      }
    }
  }
}
```

#### For Podman Installation:
```json
{
  "installMethod": "native",
  "projects": {
    "/path/to/asus-merlin-mcp": {
      "mcpServers": {
        "asus-router": {
          "command": "podman",
          "args": [
            "run", "-i", "--rm",
            "-v", "/home/yourusername/.ssh:/root/.ssh:ro",
            "-e", "ROUTER_HOST=192.168.1.1",
            "-e", "ROUTER_PORT=22",
            "-e", "ROUTER_USER=admin",
            "-e", "ROUTER_KEY_FILE=/root/.ssh/id_rsa",
            "asus-merlin-mcp"
          ]
        }
      }
    }
  }
}
```

---

### Claude Code (NPM Installation)

**Config file:** `~/.claude/settings.json`

#### For Local Installation:
```json
{
  "mcpServers": {
    "asus-router": {
      "command": "/path/to/asus-merlin-mcp/venv/bin/python",
      "args": ["/path/to/asus-merlin-mcp/asus_merlin_mcp.py"],
      "env": {
        "ROUTER_HOST": "192.168.1.1",
        "ROUTER_PORT": "22",
        "ROUTER_USER": "admin",
        "ROUTER_KEY_FILE": "/home/yourusername/.ssh/id_rsa"
      }
    }
  }
}
```

#### For Docker Installation:
```json
{
  "mcpServers": {
    "asus-router": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/yourusername/.ssh:/root/.ssh:ro",
        "-e", "ROUTER_HOST=192.168.1.1",
        "-e", "ROUTER_PORT=22",
        "-e", "ROUTER_USER=admin",
        "-e", "ROUTER_KEY_FILE=/root/.ssh/id_rsa",
        "asus-merlin-mcp"
      ]
    }
  }
}
```

#### For Podman Installation:
```json
{
  "mcpServers": {
    "asus-router": {
      "command": "podman",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/yourusername/.ssh:/root/.ssh:ro",
        "-e", "ROUTER_HOST=192.168.1.1",
        "-e", "ROUTER_PORT=22",
        "-e", "ROUTER_USER=admin",
        "-e", "ROUTER_KEY_FILE=/root/.ssh/id_rsa",
        "asus-merlin-mcp"
      ]
    }
  }
}
```

---

### Claude Desktop

**Config file locations:**
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

#### For Local Installation:
```json
{
  "mcpServers": {
    "asus-router": {
      "command": "/path/to/asus-merlin-mcp/venv/bin/python",
      "args": ["/path/to/asus-merlin-mcp/asus_merlin_mcp.py"],
      "env": {
        "ROUTER_HOST": "192.168.1.1",
        "ROUTER_PORT": "22",
        "ROUTER_USER": "admin",
        "ROUTER_KEY_FILE": "/home/yourusername/.ssh/id_rsa"
      }
    }
  }
}
```

#### For Docker Installation:
```json
{
  "mcpServers": {
    "asus-router": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/yourusername/.ssh:/root/.ssh:ro",
        "-e", "ROUTER_HOST=192.168.1.1",
        "-e", "ROUTER_PORT=22",
        "-e", "ROUTER_USER=admin",
        "-e", "ROUTER_KEY_FILE=/root/.ssh/id_rsa",
        "asus-merlin-mcp"
      ]
    }
  }
}
```

#### For Podman Installation:
```json
{
  "mcpServers": {
    "asus-router": {
      "command": "podman",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/yourusername/.ssh:/root/.ssh:ro",
        "-e", "ROUTER_HOST=192.168.1.1",
        "-e", "ROUTER_PORT=22",
        "-e", "ROUTER_USER=admin",
        "-e", "ROUTER_KEY_FILE=/root/.ssh/id_rsa",
        "asus-merlin-mcp"
      ]
    }
  }
}
```

**Important Notes:**
- Replace `/home/yourusername` with your actual home directory path (e.g., `/home/triskull`)
- Do NOT use `${HOME}` or `~` in JSON configuration files - they will not expand
- After updating the configuration file, restart Claude Code or Claude Desktop for the changes to take effect

## Usage Examples

Once configured in Claude Desktop, you can interact with your router:

**Example prompts:**
- "What's the current status of my router?"
- "List all connected devices"
- "Restart the wireless service"
- "Show me the WiFi configuration"
- "Get the value of wan_ipaddr from NVRAM"
- "Upload this backup script to /jffs/scripts/"
- "Check if VPN is running"
- "Show me the router's system log"

## Available Tools

| Tool | Description |
|------|-------------|
| `get_router_info` | System info (uptime, memory, firmware) |
| `get_connected_devices` | List DHCP clients |
| `get_wifi_status` | WiFi status for all radios |
| `restart_service` | Restart specific service |
| `reboot_router` | Reboot router (requires confirmation) |
| `get_nvram_variable` | Read NVRAM variable |
| `set_nvram_variable` | Write NVRAM variable |
| `execute_command` | Run custom SSH command |
| `read_file` | Read file from router |
| `upload_file` | Upload file (tries SFTP, falls back to shell if unavailable) |
| `download_file` | Download file (tries SFTP, falls back to shell if unavailable) |
| `get_vpn_status` | Check VPN status |
| `list_processes` | Show running processes |

## Common Services to Restart

- `wireless` - WiFi services
- `wan` - WAN connection
- `httpd` - Web interface
- `vpnclient1` - VPN client 1
- `vpnclient2` - VPN client 2
- `dnsmasq` - DNS/DHCP server

## Security Notes

1. **Use SSH keys instead of passwords** for better security
2. **Enable SSH on LAN only** unless you need WAN access
3. **Be careful with NVRAM operations** - incorrect values can break your router
4. **Test commands manually first** before automating
5. **Keep backups** of your router configuration

## Troubleshooting

### Connection Issues
```bash
# Test SSH connection manually
ssh admin@192.168.1.1

# Check if SSH is enabled on router
# Via web interface: Administration > System > Enable SSH
```

### Permission Denied
```bash
# Ensure SSH keys are readable
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub

# Verify key is added to router
ssh admin@192.168.1.1 "cat /tmp/home/root/.ssh/authorized_keys"
```

### Import Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Volume Mount Errors (Docker/Podman)
If you see an error like:
```
Error: error creating named volume "${HOME}/.keys":
error running volume create option: names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*: invalid argument
```

**Cause:** JSON configuration files do not expand shell variables like `${HOME}` or `~`.

**Solution:** Replace `${HOME}` with your actual home directory path in the configuration:
```json
// Wrong - will not work:
"-v", "${HOME}/.ssh:/root/.ssh:ro"

// Correct - use absolute path:
"-v", "/home/triskull/.ssh:/root/.ssh:ro"
```

To find your home directory:
```bash
echo $HOME
# Output: /home/triskull
```

## How-To Guide: Common Administrative Tasks

This section provides practical examples for common router administration tasks using the MCP tools.

### Managing the Hosts File

The router's custom hosts file (`/jffs/configs/hosts.add`) allows you to add static DNS entries that persist across reboots.

#### View Current Hosts File
**Via Claude:**
```
"Show me the contents of /jffs/configs/hosts.add"
```

**MCP Tool Used:** `read_file`

#### Add a New Host Entry

**Option 1: Download, Edit, Upload (Recommended)**

1. Download the file:
   ```
   "Download /jffs/configs/hosts.add from the router to ./hosts.add"
   ```
   *Uses: `download_file` tool*
   *Note: Downloads are MD5 checksum verified for integrity*

2. Edit the file locally with your text editor:
   ```bash
   nano hosts.add
   # Add line like:
   # 192.168.0.100    newserver.damage.inc    newserver
   ```

3. Upload back to router:
   ```
   "Upload ./hosts.add to /jffs/configs/hosts.add on the router"
   ```
   *Uses: `upload_file` tool*
   *Note: Uploads are MD5 checksum verified to ensure file integrity*

4. Apply changes:
   ```
   "Restart the dnsmasq service"
   ```
   *Uses: `restart_service` with `service_name: dnsmasq`*

**Option 2: Direct Command**

Via Claude:
```
"Execute this command on the router: echo '192.168.0.100    newserver.damage.inc    newserver' >> /jffs/configs/hosts.add"
```
*Uses: `execute_command` tool*

Then restart dnsmasq:
```
"Restart the dnsmasq service"
```

#### Update an Existing Host Entry

1. Download the hosts file
2. Edit locally to change the desired line
3. Upload back to router
4. Restart dnsmasq

#### Remove a Host Entry

Via Claude:
```
"Execute this command: sed -i '/hostname-to-remove/d' /jffs/configs/hosts.add"
"Restart the dnsmasq service"
```

*Replace `hostname-to-remove` with the actual hostname or IP*

### Managing NVRAM Variables

NVRAM stores persistent router configuration. **Warning:** Incorrect values can break your router!

#### Get a Single NVRAM Variable
```
"Get the NVRAM variable wan_ipaddr"
```
*Uses: `get_nvram_variable`*

#### Set an NVRAM Variable (Without Commit)
```
"Set NVRAM variable custom_setting to value123 but don't commit"
```
*Uses: `set_nvram_variable` with `commit: false`*

This sets the variable in RAM but won't persist across reboots.

#### Set and Commit NVRAM Variable
```
"Set NVRAM variable custom_setting to value123 and commit it"
```
*Uses: `set_nvram_variable` with `commit: true`*

**⚠️ Warning:** Committed changes persist across reboots. Double-check values before committing!

#### Backup NVRAM to File
```
"Execute this command: nvram show > /jffs/nvram_backup_$(date +%Y%m%d).txt"
"Download /jffs/nvram_backup_20250101.txt to ./nvram_backup.txt"
```

### Managing Custom Scripts

Scripts in `/jffs/scripts/` persist across reboots and can run at various router events.

#### Common Script Hooks
- `init-start` - First script run during boot
- `services-start` - Runs after router services start
- `wan-start` - Runs when WAN interface comes up
- `firewall-start` - Runs when firewall starts

#### Upload a Custom Script
```
"Upload ./my-custom-script.sh to /jffs/scripts/services-start on the router"
```
*MD5 checksum automatically verified to ensure script integrity*

Then make it executable:
```
"Execute this command: chmod +x /jffs/scripts/services-start"
```

#### View Existing Scripts
```
"Execute this command: ls -la /jffs/scripts/"
```

#### Read a Script's Contents
```
"Read the file /jffs/scripts/firewall-start"
```

### Monitoring and Diagnostics

#### Check System Resources
```
"What's my router's current status?"
```
*Uses: `get_router_info` - Shows uptime, memory, firmware*

#### List All Connected Devices
```
"List all connected devices on my network"
```
*Uses: `get_connected_devices` - Shows DHCP leases*

#### Find a Specific Device
```
"Show connected devices and look for hostname 'rpiserver'"
"Execute this command: cat /var/lib/misc/dnsmasq.leases | grep rpiserver"
```

#### Check WiFi Status
```
"What's my WiFi status?"
```
*Uses: `get_wifi_status` - Shows radio status and SSIDs*

#### View System Logs
```
"Read the file /jffs/syslog.log with max 50 lines"
```
*Uses: `read_file` with `max_lines: 50`*

#### Monitor Running Processes
```
"List all running processes"
"List processes filtered by 'vpn'"
```
*Uses: `list_processes` with optional filter*

### VPN Management

#### Check VPN Status
```
"What's my VPN status?"
```
*Uses: `get_vpn_status` - Shows client/server states*

#### View VPN Configuration
```
"Execute this command: nvram show | grep vpn_client1"
```

#### Restart VPN Client
```
"Restart the vpnclient1 service"
```
*Uses: `restart_service` with `service_name: vpnclient1`*

### Service Management

#### Restart Wireless Service
```
"Restart the wireless service"
```
*Useful after changing WiFi settings*

#### Restart WAN Connection
```
"Restart the wan service"
```
*Forces WAN reconnection*

#### Restart Web Interface
```
"Restart the httpd service"
```
*Restarts the router's web UI*

### File Management

**Note:** All file uploads and downloads are cryptographically verified using MD5 checksums to ensure data integrity. This is especially important for binary files, scripts, and executables.

#### Download Router Files
```
"Download /jffs/configs/dnsmasq.conf.add to ./dnsmasq.conf.add"
```
*Checksum verified for integrity*

#### Upload Configuration Files
```
"Upload ./firewall-rules.txt to /jffs/scripts/firewall-start"
```
*Checksum verified to prevent corruption*

#### Check File Permissions
```
"Execute this command: ls -la /jffs/scripts/"
```

#### Make Script Executable
```
"Execute this command: chmod +x /jffs/scripts/script-name"
```

### Advanced Router Operations

#### Backup Entire JFFS Partition
```
"Execute this command: tar -czf /tmp/jffs_backup_$(date +%Y%m%d).tar.gz /jffs/"
"Download /tmp/jffs_backup_20250101.tar.gz to ./router_backup.tar.gz"
```

#### View Network Connections
```
"Execute this command: netstat -an | grep ESTABLISHED"
```

#### Check Router Temperature (if supported)
```
"Execute this command: wl -i eth1 phy_tempsense"
```

#### Reboot Router
```
"Reboot the router"
```
*Requires confirmation - **⚠️ This will disconnect all clients!***

### Tips and Best Practices

1. **Always test commands manually first** before automating them
2. **Keep backups** of configuration files before making changes
3. **Use descriptive hostnames** in hosts.add for easier management
4. **Document your custom scripts** with comments
5. **Restart services after configuration changes** to apply them
6. **Use SSH keys** instead of passwords for better security
7. **Be cautious with NVRAM commits** - test without commit first
8. **Monitor logs** after making changes to catch issues early

## Advanced Usage

### Backup Router Configuration
```bash
# Via Claude: "Download the router's NVRAM backup"
# This will use the download_file tool to get /jffs/nvram/nvram.txt
```

### Upload Custom Scripts
```bash
# Upload a script to run on router boot
# Files in /jffs/scripts/ persist across reboots
```

### Monitor Router Health
```bash
# Set up periodic checks via cron jobs on the router
# Use the execute_command tool to create cron entries
```

## Contributing

Feel free to extend this MCP server with additional tools for:
- Traffic monitoring
- Firewall rule management
- Bandwidth statistics
- Port forwarding configuration
- Guest network management

## Resources

- [Asuswrt-Merlin Wiki](https://github.com/RMerl/asuswrt-merlin.ng/wiki)
- [MCP Documentation](https://modelcontextprotocol.io/)
- [Paramiko Documentation](https://www.paramiko.org/)

## License

MIT License - Use at your own risk. Always maintain backups of your router configuration.
