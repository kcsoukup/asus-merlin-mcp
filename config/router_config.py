"""
Router connection configuration loaded from environment variables.
"""

import os

ROUTER_CONFIG = {
    "host": os.getenv("ROUTER_HOST", "192.168.1.1"),
    "port": int(os.getenv("ROUTER_PORT", "22")),
    "username": os.getenv("ROUTER_USER", "admin"),
    "password": os.getenv("ROUTER_PASSWORD", ""),
    "key_file": os.getenv("ROUTER_KEY_FILE", ""),
}
