FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY asus_merlin_mcp.py .

# Create directory for SSH keys
RUN mkdir -p /root/.ssh

# Run the MCP server
CMD ["python", "asus_merlin_mcp.py"]
