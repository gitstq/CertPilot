"""Kubernetes deployer for CertPilot.

Deploys SSL certificates as Kubernetes TLS secrets.
"""

import base64
import json
import logging
import os
import subprocess
from typing import Any, Dict, Optional

from certpilot.deployers.base import BaseDeployer

logger = logging.getLogger(__name__)


class K8sDeployer(BaseDeployer):
    """Kubernetes certificate deployer.

    Creates or updates Kubernetes TLS secrets with certificate data.
    Requires kubectl to be installed and configured with cluster access.

    Configuration:
        secret_name: Secret name pattern (supports {domain})
        namespace: Kubernetes namespace (default: default)
        kubeconfig: Path to kubeconfig file (optional, uses default)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Kubernetes deployer.

        Args:
            config: Kubernetes deployer configuration.
        """
        super().__init__(config)
        self._secret_name_pattern = self._config.get(
            "secret_name", "tls-cert-{domain}"
        )
        self._namespace = self._config.get("namespace", "default")
        self._kubeconfig = self._config.get("kubeconfig")

    def _get_kubectl_args(self) -> list:
        """Build kubectl command arguments.

        Returns:
            List of kubectl command arguments.
        """
        args = ["kubectl"]
        if self._kubeconfig:
            args.extend(["--kubeconfig", self._kubeconfig])
        args.extend(["-n", self._namespace])
        return args

    def _run_kubectl(self, args: list, input_data: Optional[str] = None) -> subprocess.CompletedProcess:
        """Run a kubectl command.

        Args:
            args: Additional kubectl arguments.
            input_data: Optional stdin data.

        Returns:
            CompletedProcess instance.

        Raises:
            subprocess.CalledProcessError: If the command fails.
        """
        full_args = self._get_kubectl_args() + args
        self._logger.debug(f"Running: {' '.join(full_args)}")

        return subprocess.run(
            full_args,
            capture_output=True,
            text=True,
            input=input_data,
            timeout=60,
        )

    def _read_file_b64(self, filepath: str) -> str:
        """Read a file and return base64-encoded content.

        Args:
            filepath: Path to the file.

        Returns:
            Base64-encoded file content.
        """
        with open(filepath, "rb") as f:
            return base64.b64encode(f.read()).decode("utf-8")

    def deploy(
        self,
        domain: str,
        cert_path: str,
        key_path: str,
        chain_path: Optional[str] = None,
        fullchain_path: Optional[str] = None,
    ) -> bool:
        """Deploy certificate as a Kubernetes TLS secret.

        Args:
            domain: The primary domain.
            cert_path: Path to the certificate file.
            key_path: Path to the private key file.
            chain_path: Path to the chain file (appended to cert).
            fullchain_path: Path to the fullchain file (used if available).

        Returns:
            True if deployment was successful.
        """
        try:
            secret_name = self._secret_name_pattern.replace("{domain}", domain)

            # Use fullchain if available, otherwise cert + chain
            cert_data_path = fullchain_path or cert_path
            if not fullchain_path and chain_path:
                # Combine cert and chain for Kubernetes
                with open(cert_path, "r") as f:
                    cert_data = f.read()
                with open(chain_path, "r") as f:
                    chain_data = f.read()
                combined = cert_data + chain_data
                # Write to temp file
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tmp:
                    tmp.write(combined)
                    cert_data_path = tmp.name

            # Read and encode files
            tls_crt = self._read_file_b64(cert_data_path)
            tls_key = self._read_file_b64(key_path)

            # Build the secret manifest
            secret_manifest = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": secret_name,
                    "namespace": self._namespace,
                    "labels": {
                        "certpilot/managed": "true",
                        "certpilot/domain": domain,
                    },
                },
                "type": "kubernetes.io/tls",
                "data": {
                    "tls.crt": tls_crt,
                    "tls.key": tls_key,
                },
            }

            manifest_json = json.dumps(secret_manifest, indent=2)

            # Check if secret already exists
            try:
                self._run_kubectl(["get", "secret", secret_name])
                # Secret exists, replace it
                result = self._run_kubectl(
                    ["replace", "-f", "-"],
                    input_data=manifest_json,
                )
            except subprocess.CalledProcessError:
                # Secret doesn't exist, create it
                result = self._run_kubectl(
                    ["create", "-f", "-"],
                    input_data=manifest_json,
                )

            if result.returncode != 0:
                self._logger.error(f"kubectl command failed: {result.stderr}")
                return False

            self._logger.info(
                f"Kubernetes TLS secret '{secret_name}' "
                f"deployed in namespace '{self._namespace}'"
            )
            return True

        except FileNotFoundError as e:
            self._logger.error(f"Certificate file not found: {e}")
            return False
        except subprocess.TimeoutExpired:
            self._logger.error("kubectl command timed out")
            return False
        except Exception as e:
            self._logger.error(f"Failed to deploy to Kubernetes: {e}")
            return False

    def remove(self, domain: str) -> bool:
        """Remove a Kubernetes TLS secret.

        Args:
            domain: The domain to remove the secret for.

        Returns:
            True if removal was successful.
        """
        try:
            secret_name = self._secret_name_pattern.replace("{domain}", domain)
            result = self._run_kubectl(["delete", "secret", secret_name])

            if result.returncode != 0:
                self._logger.error(f"Failed to delete secret: {result.stderr}")
                return False

            self._logger.info(f"Deleted Kubernetes TLS secret '{secret_name}'")
            return True

        except subprocess.TimeoutExpired:
            self._logger.error("kubectl command timed out")
            return False
        except Exception as e:
            self._logger.error(f"Failed to remove Kubernetes secret: {e}")
            return False

    def test_config(self) -> bool:
        """Test if kubectl is available and cluster is accessible.

        Returns:
            True if kubectl is working.
        """
        try:
            result = self._run_kubectl(["version", "--client"])
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
