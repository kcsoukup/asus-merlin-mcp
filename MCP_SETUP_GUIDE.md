# MCP Setup Guide: Deep Dive

A comprehensive guide to understanding and setting up Model Context Protocol (MCP) servers with Claude Code.

---

## 🚨 BREAKING CHANGE - v3.x Security Update

**Docker containers now run as rootless (non-root user `mcpuser`) for enhanced security.**

**If upgrading from v1.0.0 to v3.x, you MUST update TWO things in your MCP configuration:**

| Component | v1.0.0 (Deprecated) | v3.x (Current) |
|-----------|---------------------|----------------|
| Volume Mount | `~/.ssh:/root/.ssh:ro` | `~/.ssh:/home/mcpuser/.ssh:ro` |
| SSH Key Path | `/root/.ssh/id_rsa` | `/home/mcpuser/.ssh/id_rsa` |

**Required Changes:**
1. Update volume mount: `-v ~/.ssh:/home/mcpuser/.ssh:ro`
2. Update environment variable: `ROUTER_KEY_FILE=/home/mcpuser/.ssh/id_rsa`

See README.md for complete migration instructions with full configuration example.

---

## Table of Contents

1. [What is MCP?](#what-is-mcp)
2. [MCP Architecture](#mcp-architecture)
3. [How Claude Code Uses MCP Servers](#how-claude-code-uses-mcp-servers)
4. [Setting Up an MCP Server](#setting-up-an-mcp-server)
5. [Configuration Deep Dive](#configuration-deep-dive)
6. [Testing and Debugging](#testing-and-debugging)
7. [Building Your Own MCP Servers](#building-your-own-mcp-servers)
8. [Troubleshooting](#troubleshooting)

---

## What is MCP?

**Model Context Protocol (MCP)** is an open protocol that allows AI assistants like Claude to interact with external tools and data sources in a standardized way.

### Key Concepts:

- **MCP Server**: A separate process that exposes tools/resources to Claude
- **MCP Client**: Claude Code acts as the client, discovering and calling tools
- **Tools**: Functions the MCP server provides (e.g., read file, control router, manage network)
- **Resources**: Data sources the server can provide (files, API responses, etc.)
- **Prompts**: Pre-defined prompt templates the server can offer

### Why MCP?

- **Extensibility**: Add new capabilities to Claude without modifying Claude itself
- **Security**: Servers run in isolated processes with explicit permissions
- **Standardization**: Single protocol for many different integrations
- **Language Agnostic**: Write servers in any language (Python, TypeScript, Go, etc.)

---

## MCP Architecture

```
┌─────────────────┐
│   Claude Code   │  (MCP Client)
│    (AI Agent)   │
└────────┬────────┘
         │ JSON-RPC over stdio
         │
    ┌────┴────┬──────────┬──────────┐
    │         │          │          │
┌───▼───┐  ┌──▼───┐  ┌───▼───┐  ┌───▼───┐
│ MCP   │  │ MCP  │  │ MCP   │  │ MCP   │
│Server │  │Server│  │Server │  │Server │
│   1   │  │  2   │  │   3   │  │   4   │
└───┬───┘  └──┬───┘  └───┬───┘  └───┬───┘
    │         │          │          │
    ▼         ▼          ▼          ▼
  Router    Files   External   Services
                      API
```

### Communication Flow:

1. **Startup**: Claude Code reads `~/.claude/settings.json`
2. **Launch**: Spawns each configured MCP server as a subprocess
3. **Discovery**: Servers advertise their tools via `list_tools()` method
4. **Usage**: Claude calls tools via JSON-RPC messages over stdin/stdout
5. **Results**: Server responds with structured data Claude can use
6. **Lifecycle**: Servers run for the duration of the Claude Code session

### Protocol Details:

- **Transport**: Standard input/output (stdio)
- **Format**: JSON-RPC 2.0 messages
- **Lifecycle**: Request/response pattern
- **Error Handling**: Structured error responses with codes

---

## How Claude Code Uses MCP Servers

### Configuration Discovery

MCP server configuration locations vary depending on your Claude installation type:

#### Claude Code (Native Installation)
- **Configuration**: `~/.claude.json` (consolidated configuration file)
- **Project-specific MCP servers**: Stored under `projects.<project-path>.mcpServers` in `~/.claude.json`
- **User-level settings**: `~/.claude/settings.json` (optional, for global MCP servers)
- **Example structure**:
  ```json
  {
    "installMethod": "native",
    "projects": {
      "/path/to/project": {
        "mcpServers": {
          "server-name": { ... }
        }
      }
    }
  }
  ```

#### Claude Code (NPM Installation)
- **Primary**: `~/.claude/settings.json`
- **Alternative**: `~/.config/claude-code/config.json`
- **Project-specific**: May use `.claude/settings.json` within project directories

#### Claude Desktop
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Configuration format**:
  ```json
  {
    "mcpServers": {
      "server-name": {
        "command": "/path/to/command",
        "args": ["arg1", "arg2"],
        "env": {
          "VAR": "value"
        }
      }
    }
  }
  ```

**Note**: Native Claude Code installations consolidate project settings (including MCP servers, permissions, and history) into `~/.claude.json`, while NPM installations and Claude Desktop use separate configuration files.

### Server Lifecycle

```python
# 1. Claude Code starts up and reads settings.json
{
  "mcpServers": {
    "server-name": { ... }
  }
}

# 2. Claude Code spawns server process
subprocess = spawn(command, args, env)

# 3. Server initializes and registers tools
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(...), Tool(...)]

# 4. Claude can now call tools
result = await server.call_tool("tool_name", {"param": "value"})

# 5. Server runs until Claude Code exits
```

### When Tools Are Available

- **Immediately**: After Claude Code starts and servers initialize
- **During conversation**: Claude decides when to use tools based on context
- **User requests**: You can explicitly ask Claude to use specific tools
- **Automatic**: Claude may proactively use tools when relevant

---

## Setting Up an MCP Server

### Step-by-Step: ASUS Router Example

#### 1. Prepare the Environment

```bash
# Navigate to project directory
cd /path/to/mcp-asus-merlin

# Create virtual environment with Python 3.11+
python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Why virtual environment?**
- Isolates dependencies from system Python
- Prevents version conflicts
- Makes deployment consistent
- Easy to recreate on other machines

#### 2. Configure Server Credentials

Create/edit `.env` file:
```bash
ROUTER_HOST=192.168.1.1
ROUTER_PORT=22
ROUTER_USER=admin
ROUTER_PASSWORD=your_password_here
# OR
ROUTER_KEY_FILE=/home/user/.ssh/id_rsa
```

**Security Best Practices:**
- Use SSH keys instead of passwords when possible
- Never commit `.env` files to version control
- Keep credentials in environment variables, not hardcoded
- Use least-privilege accounts (create dedicated user if possible)

#### 3. Test Server Manually

```bash
# Export environment variables
export $(cat .env | xargs)

# Run server in stdio mode
python asus_merlin_mcp.py
```

The server should start and wait for input. You'll see logging output if configured.

**Press Ctrl+C to exit when done testing.**

#### 4. Configure Claude Code/Desktop

The configuration location depends on your installation type:

##### For Claude Code (Native Installation)

The MCP server will be automatically added to your project in `~/.claude.json`:

```json
{
  "installMethod": "native",
  "projects": {
    "/path/to/mcp-asus-merlin": {
      "mcpServers": {
        "asus-router": {
          "command": "/path/to/mcp-asus-merlin/venv/bin/python",
          "args": ["/path/to/mcp-asus-merlin/asus_merlin_mcp.py"],
          "env": {
            "ROUTER_HOST": "192.168.1.1",
            "ROUTER_PORT": "22",
            "ROUTER_USER": "admin",
            "ROUTER_KEY_FILE": "/home/user/.ssh/id_rsa"
          }
        }
      }
    }
  }
}
```

##### For Claude Code (NPM Installation)

Edit `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "asus-router": {
      "command": "/path/to/mcp-asus-merlin/venv/bin/python",
      "args": ["/path/to/mcp-asus-merlin/asus_merlin_mcp.py"],
      "env": {
        "ROUTER_HOST": "192.168.1.1",
        "ROUTER_PORT": "22",
        "ROUTER_USER": "admin",
        "ROUTER_KEY_FILE": "/home/user/.ssh/id_rsa"
      }
    }
  }
}
```

##### For Claude Desktop

Edit the appropriate configuration file for your OS:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "asus-router": {
      "command": "/path/to/mcp-asus-merlin/venv/bin/python",
      "args": ["/path/to/mcp-asus-merlin/asus_merlin_mcp.py"],
      "env": {
        "ROUTER_HOST": "192.168.1.1",
        "ROUTER_PORT": "22",
        "ROUTER_USER": "admin",
        "ROUTER_KEY_FILE": "/home/user/.ssh/id_rsa"
      }
    }
  }
}
```

**Configuration Notes:**
- `command`: Full path to Python interpreter in venv
- `args`: Full path to MCP server script
- `env`: Environment variables passed to server process
- Native Claude Code stores project-specific MCP servers in `~/.claude.json`
- NPM installations and Claude Desktop use separate configuration files

#### 5. Restart Claude Code

```bash
# Exit Claude Code completely
# Restart Claude Code

# Or use restart command if available
claude restart
```

**Why restart?**
- MCP servers are loaded only at startup
- Configuration changes require full restart
- Changes to `settings.json` aren't hot-reloaded

#### 6. Verify Installation

Ask Claude:
```
What MCP servers do you have access to?
```

Claude should list `asus-router` with its available tools.

#### 7. Test Tools

```
Get my router's uptime
List connected devices
What's my router's firmware version?
```

---

## Configuration Deep Dive

### Complete Configuration Schema

```json
{
  "mcpServers": {
    "server-identifier": {
      "command": "/path/to/executable",
      "args": [
        "arg1",
        "arg2"
      ],
      "env": {
        "VAR1": "value1",
        "VAR2": "value2"
      },
      "cwd": "/working/directory",
      "disabled": false
    }
  }
}
```

### Configuration Fields Explained

#### `server-identifier` (string)
- Unique name for this MCP server
- Used in logs and when Claude references the server
- Should be descriptive (e.g., "asus-router", "postgres-db", "file-system")

#### `command` (string, required)
- Path to executable that runs the MCP server
- **Must be absolute path**, not relative
- Common values:
  - `/path/to/venv/bin/python` - Python server
  - `/usr/bin/node` - Node.js server
  - `/usr/local/bin/go` - Go binary
  - `/path/to/compiled/binary` - Native executable

#### `args` (array of strings, required)
- Command-line arguments passed to the executable
- First argument is typically the script/entry point
- Examples:
  ```json
  ["server.py"]  // Python script
  ["dist/index.js"]  // JavaScript entry point
  ["run", "server"]  // Go subcommand
  ```

#### `env` (object, optional)
- Environment variables available to the server process
- Merged with system environment
- Use for:
  - Credentials (API keys, passwords)
  - Configuration (hosts, ports, paths)
  - Feature flags
  - Debug settings

#### `cwd` (string, optional)
- Working directory for the server process
- Defaults to directory containing the executable
- Useful if server expects to run from specific directory

#### `disabled` (boolean, optional)
- Set to `true` to prevent server from loading
- Useful for temporarily disabling servers without removing config
- Default: `false`

### Multiple MCP Servers

You can configure multiple servers simultaneously:

```json
{
  "mcpServers": {
    "asus-router": {
      "command": "/path/to/python",
      "args": ["asus_merlin_mcp.py"],
      "env": { "ROUTER_HOST": "192.168.0.1" }
    },
    "postgres-db": {
      "command": "/path/to/node",
      "args": ["postgres-server.js"],
      "env": { "DB_CONNECTION": "postgresql://..." }
    },
    "file-system": {
      "command": "/path/to/filesystem-server",
      "args": [],
      "cwd": "/home/user/documents"
    }
  }
}
```

Claude will have access to all enabled servers concurrently.

---

## Testing and Debugging

### Manual Testing

#### Test 1: Server Starts Successfully

```bash
cd /path/to/mcp-server
source venv/bin/activate
export $(cat .env | xargs)
python server.py
```

**Expected behavior:**
- Server starts without errors
- Logs show initialization messages
- Process waits for stdin (doesn't exit immediately)

**Troubleshooting:**
- Import errors → Check dependencies installed
- Connection errors → Verify credentials and connectivity
- Permission errors → Check file permissions and paths

#### Test 2: Server Responds to MCP Protocol

You can manually send JSON-RPC messages:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python server.py
```

**Expected response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [...]
  }
}
```

#### Test 3: Tool Execution

```bash
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_router_info","arguments":{}}}' | python server.py
```

### Debugging with Logs

Add detailed logging to your MCP server:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/mcp-server.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("mcp-server")
logger.info("Server starting...")
```

**Log file locations:**
- `/tmp/mcp-server.log` - Custom log file
- `~/.claude/logs/` - Claude Code logs (may include MCP errors)
- stderr - Captured by Claude Code

### Common Issues

#### Server Not Appearing in Claude

**Symptoms:**
- Claude says "No MCP servers configured"
- Server not listed when asked

**Causes:**
1. Configuration file not in correct location
2. Invalid JSON syntax in settings.json
3. Server identifier misspelled
4. Server disabled with `"disabled": true`

**Solutions:**
```bash
# Verify config location
cat ~/.claude/settings.json

# Validate JSON syntax
python3 -m json.tool ~/.claude/settings.json

# Check for typos in server name
```

#### Server Starts But Tools Don't Work

**Symptoms:**
- Server appears in list
- Tool calls fail or timeout

**Causes:**
1. Network connectivity issues
2. Invalid credentials
3. Permissions problems
4. Server crashes on tool execution

**Solutions:**
```bash
# Test connectivity manually
ssh user@host

# Check server logs
tail -f /tmp/mcp-server.log

# Test tool in isolation
python -c "from server import router; print(router.execute_command('uptime'))"
```

#### Environment Variables Not Working

**Symptoms:**
- Server can't find configuration
- Connection failures despite correct credentials

**Causes:**
1. Environment variables not set in settings.json
2. Variables not accessible to subprocess
3. Variables contain special characters needing escaping

**Solutions:**
```json
{
  "env": {
    "DEBUG": "true",
    "ROUTER_HOST": "192.168.0.1",
    "PATH": "/usr/local/bin:/usr/bin:/bin"
  }
}
```

### Using MCP Inspector (Optional)

If you have the MCP Inspector tool installed:

```bash
mcp inspect /path/to/venv/bin/python /path/to/server.py
```

This provides an interactive interface to test your MCP server.

---

## Building Your Own MCP Servers

### Server Structure

Every MCP server needs:

1. **Entry point** - Main script that starts the server
2. **Tool definitions** - Declare what tools are available
3. **Tool handlers** - Implement tool functionality
4. **Communication layer** - Handle JSON-RPC protocol (usually via SDK)

### Python Example Structure

```python
#!/usr/bin/env python3
import asyncio
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

# Initialize server
app = Server("my-server-name")

# Define tools
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="example_tool",
            description="What this tool does",
            inputSchema={
                "type": "object",
                "properties": {
                    "param1": {
                        "type": "string",
                        "description": "Parameter description"
                    }
                },
                "required": ["param1"]
            }
        )
    ]

# Implement tool handler
@app.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "example_tool":
        param1 = arguments.get("param1")
        result = f"You provided: {param1}"
        return [TextContent(type="text", text=result)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

# Run server
async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
```

### Tool Design Patterns

#### Pattern 1: Information Retrieval

**Use case**: Get data from external source

```python
Tool(
    name="get_data",
    description="Retrieve information from X",
    inputSchema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to retrieve"}
        },
        "required": ["query"]
    }
)
```

#### Pattern 2: State Modification

**Use case**: Change something in external system

```python
Tool(
    name="update_setting",
    description="Modify configuration",
    inputSchema={
        "type": "object",
        "properties": {
            "key": {"type": "string", "description": "Setting name"},
            "value": {"type": "string", "description": "New value"},
            "confirm": {"type": "boolean", "description": "Confirmation flag"}
        },
        "required": ["key", "value", "confirm"]
    }
)
```

**Best practice**: Require confirmation for destructive operations.

#### Pattern 3: File Operations

**Use case**: Upload/download files

```python
Tool(
    name="upload_file",
    description="Upload file to destination",
    inputSchema={
        "type": "object",
        "properties": {
            "local_path": {"type": "string"},
            "remote_path": {"type": "string"}
        },
        "required": ["local_path", "remote_path"]
    }
)
```

#### Pattern 4: Command Execution

**Use case**: Run arbitrary commands (use cautiously)

```python
Tool(
    name="execute_command",
    description="Execute command on remote system",
    inputSchema={
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Command to execute"}
        },
        "required": ["command"]
    }
)
```

**Security warning**: Validate and sanitize all inputs!

### Input Validation

Always validate tool inputs:

```python
async def call_tool(name: str, arguments: dict):
    if name == "set_config":
        key = arguments.get("key")
        value = arguments.get("value")

        # Validation
        if not key or not isinstance(key, str):
            return [TextContent(type="text", text="Error: Invalid key")]

        if len(key) > 100:
            return [TextContent(type="text", text="Error: Key too long")]

        # Sanitization
        safe_key = key.strip()

        # Execute
        result = set_configuration(safe_key, value)
        return [TextContent(type="text", text=f"Set {safe_key} = {value}")]
```

### Error Handling

Return meaningful errors to Claude:

```python
async def call_tool(name: str, arguments: dict):
    try:
        # Tool logic
        result = perform_operation(arguments)
        return [TextContent(type="text", text=result)]

    except ConnectionError as e:
        return [TextContent(type="text", text=f"Connection failed: {e}")]

    except PermissionError as e:
        return [TextContent(type="text", text=f"Permission denied: {e}")]

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return [TextContent(type="text", text=f"Error: {str(e)}")]
```

### Response Formats

Tools can return different content types:

```python
from mcp.types import TextContent, ImageContent, EmbeddedResource

# Text response
return [TextContent(type="text", text="Plain text result")]

# Multiple text blocks
return [
    TextContent(type="text", text="Section 1"),
    TextContent(type="text", text="Section 2")
]

# Image response (base64 encoded)
return [ImageContent(
    type="image",
    data="base64-encoded-image-data",
    mimeType="image/png"
)]

# Embedded resource
return [EmbeddedResource(
    type="resource",
    resource={
        "uri": "file:///path/to/file",
        "mimeType": "application/json",
        "text": json.dumps(data)
    }
)]
```

### Best Practices

1. **Tool Naming**: Use clear, descriptive names (`get_router_info` not `gri`)
2. **Descriptions**: Write from Claude's perspective (what Claude can do with this)
3. **Parameters**: Provide clear descriptions and types
4. **Validation**: Always validate inputs before use
5. **Errors**: Return helpful error messages, not stack traces
6. **Logging**: Log important operations for debugging
7. **Security**: Never trust user input, sanitize everything
8. **Documentation**: Include docstrings and comments
9. **Testing**: Test each tool independently before integration
10. **Versioning**: Track server version for compatibility

---

## Troubleshooting

### Diagnostic Checklist

When things don't work, check in this order:

#### ✓ Configuration File
- [ ] File exists at `~/.claude/settings.json`
- [ ] JSON syntax is valid
- [ ] Server identifier is unique
- [ ] Paths are absolute, not relative
- [ ] No typos in field names

#### ✓ Executable & Scripts
- [ ] Python interpreter path is correct
- [ ] Virtual environment exists
- [ ] Server script exists at specified path
- [ ] Server script has execute permissions
- [ ] All dependencies installed in venv

#### ✓ Environment Variables
- [ ] Variables defined in `env` section
- [ ] Variable values are correct
- [ ] No unescaped special characters
- [ ] Credentials are valid

#### ✓ Network & Connectivity
- [ ] Can reach target system from command line
- [ ] Firewall allows connections
- [ ] Credentials work manually
- [ ] SSH keys have correct permissions (600)

#### ✓ Server Logs
- [ ] Check logs for startup errors
- [ ] Look for connection failures
- [ ] Verify tools are registered
- [ ] Check for runtime exceptions

### Getting Help

1. **Check the logs**: Most issues show up in logs
2. **Test manually**: Run server outside of Claude Code
3. **Simplify**: Start with minimal working example
4. **Read errors**: Error messages often point to exact issue
5. **Search docs**: MCP documentation at modelcontextprotocol.io
6. **Community**: Ask in MCP community forums/Discord

---

## Conclusion

You now have a comprehensive understanding of:

- ✓ What MCP is and how it works
- ✓ How Claude Code discovers and uses MCP servers
- ✓ How to configure MCP servers in settings.json
- ✓ How to test and debug MCP servers
- ✓ How to build your own custom MCP servers
- ✓ Common patterns and best practices

### Next Steps

1. **Experiment**: Modify the ASUS router server to add new tools
2. **Create**: Build an MCP server for your own use case
3. **Share**: Contribute MCP servers to the community
4. **Learn more**: Visit [modelcontextprotocol.io](https://modelcontextprotocol.io)

### Resources

- **MCP Documentation**: https://modelcontextprotocol.io
- **MCP Python SDK**: https://github.com/modelcontextprotocol/python-sdk
- **Example Servers**: https://github.com/modelcontextprotocol/servers
- **Community**: MCP Discord/Forums

---

**Happy building!** 🚀
