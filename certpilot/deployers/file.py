"""File system deployer for CertPilot.

Deploys SSL certificates to the local file system with
configurable paths and permissions.
"""

import logging
import os
import shutil
from typing import Any, Dict, Optional

from certpilot.deployers.base import BaseDeployer

logger = logging.getLogger(__name__)


class FileDeployer(BaseDeployer):
    """File system certificate deployer.

    Saves certificate files to a specified directory with configurable
    file naming patterns and permissions.

    Configuration:
        output_dir: Base output directory (default: ./certs)
        cert_filename: Certificate filename pattern (supports {domain})
        key_filename: Private key filename pattern (supports {domain})
        chain_filename: Chain filename pattern (supports {domain})
        fullchain_filename: Fullchain filename pattern (supports {domain})
        permissions: File permissions for certificates (default: 644)
        key_permissions: File permissions for private keys (default: 600)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the file deployer.

        Args:
            config: File deployer configuration.
        """
        super().__init__(config)
        self._output_dir = os.path.expanduser(
            self._config.get("output_dir", "./certs")
        )
        self._cert_filename = self._config.get("cert_filename", "{domain}/cert.pem")
        self._key_filename = self._config.get("key_filename", "{domain}/key.pem")
        self._chain_filename = self._config.get("chain_filename", "{domain}/chain.pem")
        self._fullchain_filename = self._config.get("fullchain_filename", "{domain}/fullchain.pem")
        self._permissions = self._config.get("permissions", 644)
        self._key_permissions = self._config.get("key_permissions", 600)

    def _resolve_path(self, pattern: str, domain: str) -> str:
        """Resolve a filename pattern to an absolute path.

        Args:
            pattern: Filename pattern with {domain} placeholder.
            domain: The domain name to substitute.

        Returns:
            Absolute file path.
        """
        filename = pattern.replace("{domain}", domain)
        return os.path.join(self._output_dir, filename)

    def deploy(
        self,
        domain: str,
        cert_path: str,
        key_path: str,
        chain_path: Optional[str] = None,
        fullchain_path: Optional[str] = None,
    ) -> bool:
        """Deploy certificate files to the configured output directory.

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
            # Define file mappings: (source, target_pattern, permissions)
            file_mappings = [
                (cert_path, self._cert_filename, self._permissions),
                (key_path, self._key_filename, self._key_permissions),
            ]
            if chain_path:
                file_mappings.append(
                    (chain_path, self._chain_filename, self._permissions)
                )
            if fullchain_path:
                file_mappings.append(
                    (fullchain_path, self._fullchain_filename, self._permissions)
                )

            for src, pattern, perms in file_mappings:
                if not os.path.exists(src):
                    self._logger.warning(f"Source file not found: {src}")
                    continue

                dst = self._resolve_path(pattern, domain)
                dst_dir = os.path.dirname(dst)
                os.makedirs(dst_dir, exist_ok=True)

                shutil.copy2(src, dst)
                os.chmod(dst, perms)
                self._logger.info(f"Deployed {src} -> {dst} (0o{perms:o})")

            self._logger.info(f"Certificate files deployed to {self._output_dir} for {domain}")
            return True

        except Exception as e:
            self._logger.error(f"Failed to deploy certificate files: {e}")
            return False

    def remove(self, domain: str) -> bool:
        """Remove certificate files for a domain.

        Args:
            domain: The domain to remove certificates for.

        Returns:
            True if removal was successful.
        """
        patterns = [
            self._cert_filename,
            self._key_filename,
            self._chain_filename,
            self._fullchain_filename,
        ]

        removed_count = 0
        for pattern in patterns:
            filepath = self._resolve_path(pattern, domain)
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    self._logger.info(f"Removed {filepath}")
                    removed_count += 1
                except OSError as e:
                    self._logger.error(f"Failed to remove {filepath}: {e}")

        # Try to remove empty domain directory
        domain_dir = os.path.join(self._output_dir, domain)
        if os.path.isdir(domain_dir) and not os.listdir(domain_dir):
            try:
                os.rmdir(domain_dir)
                self._logger.info(f"Removed empty directory: {domain_dir}")
            except OSError:
                pass

        return True

    def test_config(self) -> bool:
        """Test if the output directory is writable.

        Returns:
            True if the output directory is accessible and writable.
        """
        try:
            os.makedirs(self._output_dir, exist_ok=True)
            test_file = os.path.join(self._output_dir, ".certpilot_test")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
            return True
        except Exception as e:
            self._logger.error(f"Output directory test failed: {e}")
            return False
