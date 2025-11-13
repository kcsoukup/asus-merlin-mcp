FROM python:3.12-slim

# Create non-root user early
RUN groupadd -r mcpuser && useradd -r -g mcpuser -u 1000 mcpuser

WORKDIR /app

# Update OS
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy MCP server code and packages
COPY asus_merlin_mcp.py .
COPY config/ ./config/
COPY core/ ./core/
COPY utils/ ./utils/
COPY tools/ ./tools/

# Change ownership of app directory to non-root user
RUN chown -R mcpuser:mcpuser /app

# Create directory for SSH keys with proper ownership
RUN mkdir -p /home/mcpuser/.ssh && chown -R mcpuser:mcpuser /home/mcpuser/.ssh

# Switch to non-root user
USER mcpuser

# Run the MCP server
CMD ["python", "asus_merlin_mcp.py"]
