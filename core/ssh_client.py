"""
SSH/SCP client for ASUS router communication.

Handles SSH connections, command execution, and file transfers.
"""

import logging
import os
from typing import Optional

import paramiko

logger = logging.getLogger("asus-merlin-mcp")


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
        # Check if we need to establish initial connection
        if not self.client:
            if not self.connect():
                return "", "Failed to connect to router", 1

        assert self.client is not None  # Type narrowing for Pylance

        # Check if existing connection is still alive
        try:
            transport = self.client.get_transport()
            if transport is None or not transport.is_active():
                logger.info("Detected dead SSH connection, reconnecting...")
                self.client = None
                if not self.connect():
                    return "", "Failed to reconnect to router", 1
        except Exception as e:
            logger.warning(f"Error checking connection status: {e}")
            # Continue and let exec_command fail if connection is truly dead

        # Execute the command
        try:
            _stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode("utf-8", errors="replace")
            error = stderr.read().decode("utf-8", errors="replace")
            return output, error, exit_code
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            # Try to reconnect once on failure
            logger.info("Attempting to reconnect...")
            self.client = None
            if self.connect():
                try:
                    _stdin, stdout, stderr = self.client.exec_command(
                        command, timeout=30
                    )
                    exit_code = stdout.channel.recv_exit_status()
                    output = stdout.read().decode("utf-8", errors="replace")
                    error = stderr.read().decode("utf-8", errors="replace")
                    logger.info("Reconnected successfully")
                    return output, error, exit_code
                except Exception as retry_e:
                    logger.error(f"Retry after reconnect failed: {retry_e}")
                    return "", str(retry_e), 1
            return "", "Failed to reconnect after connection loss", 1

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

    def read_file_content(self, remote_path: str) -> tuple[bool, str, str]:
        """
        Read file content from router.

        Args:
            remote_path: Path to file on router

        Returns:
            Tuple of (success, content, error_message)
            - success: True if file was read successfully
            - content: File content as string (empty if failed)
            - error_message: Error description (empty if successful)
        """
        output, error, code = self.execute_command(f"cat {remote_path} 2>/dev/null")

        if code != 0:
            return False, "", f"Failed to read file {remote_path}: {error}"

        return True, output, ""

    def write_file_content(self, remote_path: str, content: str) -> tuple[bool, str]:
        """
        Write content to file on router with MD5 verification.

        Args:
            remote_path: Path to file on router
            content: Content to write

        Returns:
            Tuple of (success, error_message)
            - success: True if file was written and verified successfully
            - error_message: Error description (empty if successful)
        """
        import hashlib
        import tempfile

        try:
            # Calculate expected MD5
            expected_md5 = hashlib.md5(content.encode("utf-8")).hexdigest()

            # Create temporary local file
            with tempfile.NamedTemporaryFile(
                mode="w", delete=False, encoding="utf-8"
            ) as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name

            try:
                # Try SFTP upload first
                success, msg = self.upload_file(temp_path, remote_path)

                if not success:
                    # Fallback to shell-based upload
                    success, msg = self.upload_file_shell(temp_path, remote_path)

                if not success:
                    return False, f"Failed to upload file: {msg}"

                # Verify MD5 checksum on router
                md5_output, _, md5_code = self.execute_command(
                    f"md5sum {remote_path} 2>/dev/null | awk '{{print $1}}'"
                )

                if md5_code == 0:
                    actual_md5 = md5_output.strip()
                    if actual_md5 != expected_md5:
                        return (
                            False,
                            f"MD5 verification failed: expected {expected_md5}, got {actual_md5}",
                        )
                    logger.info(
                        f"File {remote_path} written and verified (MD5: {actual_md5})"
                    )
                else:
                    logger.warning(
                        f"MD5 verification unavailable for {remote_path}, assuming success"
                    )

                return True, ""

            finally:
                # Clean up temporary file
                os.unlink(temp_path)

        except Exception as e:
            error_msg = f"Failed to write file content: {type(e).__name__}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def close(self):
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.client = None
