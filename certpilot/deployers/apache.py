"""Apache deployer for CertPilot.

Deploys SSL certificates to Apache HTTP Server by updating
VirtualHost configuration and reloading the service.
"""

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, Optional

from certpilot.deployers.base import BaseDeployer

logger = logging.getLogger(__name__)


class ApacheDeployer(BaseDeployer):
    """Apache certificate deployer.

    Handles copying certificate files to the Apache SSL directory,
    updating VirtualHost configurations, and reloading Apache.

    Configuration:
        config_path: Path to apache2.conf (default: /etc/apache2/apache2.conf)
        sites_available: Path to sites-available directory
        sites_enabled: Path to sites-enabled directory
        cert_path: Target path for the certificate file
        key_path: Target path for the private key file
        chain_path: Target path for the chain file
        reload_command: Command to reload Apache (default: apache2ctl graceful)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Apache deployer.

        Args:
            config: Apache deployer configuration.
        """
        super().__init__(config)
        self._config_path = self._config.get("config_path", "/etc/apache2/apache2.conf")
        self._sites_available = self._config.get("sites_available", "/etc/apache2/sites-available")
        self._sites_enabled = self._config.get("sites_enabled", "/etc/apache2/sites-enabled")
        self._cert_path = self._config.get("cert_path", "/etc/apache2/ssl/cert.pem")
        self._key_path = self._config.get("key_path", "/etc/apache2/ssl/key.pem")
        self._chain_path = self._config.get("chain_path", "/etc/apache2/ssl/chain.pem")
        self._reload_command = self._config.get("reload_command", "apache2ctl graceful")

    def deploy(
        self,
        domain: str,
        cert_path: str,
        key_path: str,
        chain_path: Optional[str] = None,
        fullchain_path: Optional[str] = None,
    ) -> bool:
        """Deploy certificate files to Apache SSL directory.

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

            for src, dst, perms in files_to_copy:
                if os.path.exists(src):
                    shutil.copy2(src, dst)
                    os.chmod(dst, perms)
                    self._logger.info(f"Copied {src} -> {dst}")
                else:
                    self._logger.warning(f"Source file not found: {src}")

            # Update Apache VirtualHost configuration
            self._update_apache_config(domain)

            # Test and reload
            if self.reload_service():
                self._logger.info(f"Apache certificate deployed successfully for {domain}")
                return True
            else:
                self._logger.error("Apache reload failed")
                return False

        except Exception as e:
            self._logger.error(f"Failed to deploy certificate to Apache: {e}")
            return False

    def _find_vhost_file(self, domain: str) -> Optional[str]:
        """Find the VirtualHost configuration file for a domain.

        Args:
            domain: The domain to search for.

        Returns:
            Path to the VirtualHost config file, or None if not found.
        """
        if not os.path.isdir(self._sites_available):
            return None

        for filename in os.listdir(self._sites_available):
            if not filename.endswith((".conf", "")):
                continue
            filepath = os.path.join(self._sites_available, filename)
            try:
                with open(filepath, "r") as f:
                    content = f.read()
                if domain in content and "VirtualHost" in content:
                    return filepath
            except (IOError, OSError):
                continue

        return None

    def _update_apache_config(self, domain: str) -> bool:
        """Update Apache VirtualHost SSL configuration.

        Args:
            domain: The domain to update configuration for.

        Returns:
            True if configuration was updated or no update needed.
        """
        vhost_file = self._find_vhost_file(domain)
        if not vhost_file:
            self._logger.info(
                f"No VirtualHost config found for {domain}. Skipping config update."
            )
            return True

        try:
            with open(vhost_file, "r") as f:
                content = f.read()

            updated = content

            # Update SSL certificate paths
            ssl_patterns = {
                r"SSLCertificateFile\s+[^ \n]+": f"SSLCertificateFile {self._cert_path}",
                r"SSLCertificateKeyFile\s+[^ \n]+": f"SSLCertificateKeyFile {self._key_path}",
            }
            if self._chain_path:
                ssl_patterns[
                    r"SSLCertificateChainFile\s+[^ \n]+"
                ] = f"SSLCertificateChainFile {self._chain_path}"

            for pattern, replacement in ssl_patterns.items():
                updated = re.sub(pattern, replacement, updated)

            if updated != content:
                with open(vhost_file, "w") as f:
                    f.write(updated)
                self._logger.info(f"Updated Apache SSL config in {vhost_file}")

            return True

        except Exception as e:
            self._logger.error(f"Failed to update Apache config: {e}")
            return False

    def remove(self, domain: str) -> bool:
        """Remove certificate files for a domain from Apache.

        Args:
            domain: The domain to remove certificates for.

        Returns:
            True if removal was successful.
        """
        files_to_remove = [
            self._cert_path,
            self._key_path,
            self._chain_path,
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
        """Test Apache configuration and reload the service.

        Returns:
            True if Apache was reloaded successfully.
        """
        # Test configuration first
        try:
            result = subprocess.run(
                ["apache2ctl", "configtest"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                self._logger.error(f"Apache config test failed: {result.stderr}")
                return False
        except FileNotFoundError:
            self._logger.warning("apache2ctl not found, skipping config test")
        except subprocess.TimeoutExpired:
            self._logger.error("Apache config test timed out")
            return False

        # Reload Apache
        try:
            result = subprocess.run(
                self._reload_command.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                self._logger.error(f"Apache reload failed: {result.stderr}")
                return False
            self._logger.info("Apache reloaded successfully")
            return True
        except FileNotFoundError:
            self._logger.error(f"Reload command not found: {self._reload_command}")
            return False
        except subprocess.TimeoutExpired:
            self._logger.error("Apache reload timed out")
            return False

    def test_config(self) -> bool:
        """Test if Apache configuration is accessible and valid.

        Returns:
            True if Apache is properly configured.
        """
        if not os.path.exists(self._config_path):
            self._logger.error(f"Apache config not found: {self._config_path}")
            return False

        try:
            result = subprocess.run(
                ["apache2ctl", "configtest"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
