"""Nginx deployer for CertPilot.

Deploys SSL certificates to Nginx web server by updating
configuration files and reloading the service.
"""

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, Optional

from certpilot.deployers.base import BaseDeployer

logger = logging.getLogger(__name__)


class NginxDeployer(BaseDeployer):
    """Nginx certificate deployer.

    Handles copying certificate files to the Nginx SSL directory,
    updating Nginx configuration to point to the new certificates,
    testing the configuration, and reloading Nginx.

    Configuration:
        config_path: Path to nginx.conf (default: /etc/nginx/nginx.conf)
        cert_path: Target path for the certificate file
        key_path: Target path for the private key file
        chain_path: Target path for the chain file
        fullchain_path: Target path for the fullchain file
        reload_command: Command to reload Nginx (default: nginx -s reload)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Nginx deployer.

        Args:
            config: Nginx deployer configuration.
        """
        super().__init__(config)
        self._config_path = self._config.get("config_path", "/etc/nginx/nginx.conf")
        self._cert_path = self._config.get("cert_path", "/etc/nginx/ssl/cert.pem")
        self._key_path = self._config.get("key_path", "/etc/nginx/ssl/key.pem")
        self._chain_path = self._config.get("chain_path", "/etc/nginx/ssl/chain.pem")
        self._fullchain_path = self._config.get("fullchain_path", "/etc/nginx/ssl/fullchain.pem")
        self._reload_command = self._config.get("reload_command", "nginx -s reload")

    def deploy(
        self,
        domain: str,
        cert_path: str,
        key_path: str,
        chain_path: Optional[str] = None,
        fullchain_path: Optional[str] = None,
    ) -> bool:
        """Deploy certificate files to Nginx SSL directory.

        Args:
            domain: The primary domain.
            cert_path: Source certificate file path.
            key_path: Source private key file path.
            chain_path: Source chain file path.
            fullchain_path: Source fullchain file path.

        Returns:
            True if deployment was successful.
        """
        try:
            # Ensure SSL directory exists
            ssl_dir = os.path.dirname(self._cert_path)
            os.makedirs(ssl_dir, exist_ok=True)

            # Copy certificate files
            files_to_copy = [
                (cert_path, self._cert_path, 0o644),
                (key_path, self._key_path, 0o600),
            ]
            if chain_path:
                files_to_copy.append((chain_path, self._chain_path, 0o644))
            if fullchain_path:
                files_to_copy.append((fullchain_path, self._fullchain_path, 0o644))

            for src, dst, perms in files_to_copy:
                if os.path.exists(src):
                    shutil.copy2(src, dst)
                    os.chmod(dst, perms)
                    self._logger.info(f"Copied {src} -> {dst}")
                else:
                    self._logger.warning(f"Source file not found: {src}")

            # Update Nginx configuration if needed
            self._update_nginx_config(domain)

            # Test and reload
            if self.reload_service():
                self._logger.info(f"Nginx certificate deployed successfully for {domain}")
                return True
            else:
                self._logger.error("Nginx reload failed")
                return False

        except Exception as e:
            self._logger.error(f"Failed to deploy certificate to Nginx: {e}")
            return False

    def _update_nginx_config(self, domain: str) -> bool:
        """Update Nginx configuration to use the new certificate paths.

        Scans Nginx configuration files for the domain's server block
        and updates SSL certificate directives if they exist.

        Args:
            domain: The domain to update configuration for.

        Returns:
            True if configuration was updated or no update needed.
        """
        if not os.path.exists(self._config_path):
            self._logger.warning(f"Nginx config not found: {self._config_path}")
            return True

        try:
            with open(self._config_path, "r") as f:
                content = f.read()

            # Check if there's a server block for this domain
            if domain not in content:
                self._logger.info(
                    f"Domain {domain} not found in Nginx config. "
                    f"Skipping config update."
                )
                return True

            # Update SSL certificate paths if they exist
            ssl_patterns = {
                r"ssl_certificate\s+[^;]+;": f"ssl_certificate {self._fullchain_path};",
                r"ssl_certificate_key\s+[^;]+;": f"ssl_certificate_key {self._key_path};",
            }

            updated = content
            for pattern, replacement in ssl_patterns.items():
                updated = re.sub(pattern, replacement, updated)

            if updated != content:
                with open(self._config_path, "w") as f:
                    f.write(updated)
                self._logger.info(f"Updated Nginx SSL config for {domain}")

            return True

        except Exception as e:
            self._logger.error(f"Failed to update Nginx config: {e}")
            return False

    def remove(self, domain: str) -> bool:
        """Remove certificate files for a domain from Nginx.

        Args:
            domain: The domain to remove certificates for.

        Returns:
            True if removal was successful.
        """
        files_to_remove = [
            self._cert_path,
            self._key_path,
            self._chain_path,
            self._fullchain_path,
        ]

        for filepath in files_to_remove:
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    self._logger.info(f"Removed {filepath}")
                except OSError as e:
                    self._logger.error(f"Failed to remove {filepath}: {e}")
                    return False

        return True

    def reload_service(self) -> bool:
        """Test Nginx configuration and reload the service.

        Returns:
            True if Nginx was reloaded successfully.
        """
        # Test configuration first
        try:
            result = subprocess.run(
                ["nginx", "-t"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                self._logger.error(f"Nginx config test failed: {result.stderr}")
                return False
        except FileNotFoundError:
            self._logger.warning("nginx command not found, skipping config test")
        except subprocess.TimeoutExpired:
            self._logger.error("Nginx config test timed out")
            return False

        # Reload Nginx
        try:
            result = subprocess.run(
                self._reload_command.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                self._logger.error(f"Nginx reload failed: {result.stderr}")
                return False
            self._logger.info("Nginx reloaded successfully")
            return True
        except FileNotFoundError:
            self._logger.error(f"Reload command not found: {self._reload_command}")
            return False
        except subprocess.TimeoutExpired:
            self._logger.error("Nginx reload timed out")
            return False

    def test_config(self) -> bool:
        """Test if Nginx configuration is accessible and valid.

        Returns:
            True if Nginx is properly configured.
        """
        if not os.path.exists(self._config_path):
            self._logger.error(f"Nginx config not found: {self._config_path}")
            return False

        try:
            result = subprocess.run(
                ["nginx", "-t"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
