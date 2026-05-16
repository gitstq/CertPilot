"""Base deployer interface for CertPilot.

All deployers must implement this interface to support
deploying certificates to various targets.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BaseDeployer(ABC):
    """Abstract base class for certificate deployers.

    Deployers are responsible for deploying certificates to various targets
    such as web servers, file systems, or Kubernetes clusters.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the deployer.

        Args:
            config: Deployer-specific configuration dictionary.
        """
        self._config = config or {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def deploy(
        self,
        domain: str,
        cert_path: str,
        key_path: str,
        chain_path: Optional[str] = None,
        fullchain_path: Optional[str] = None,
    ) -> bool:
        """Deploy a certificate to the target.

        Args:
            domain: The primary domain of the certificate.
            cert_path: Path to the certificate file.
            key_path: Path to the private key file.
            chain_path: Path to the certificate chain file.
            fullchain_path: Path to the full chain (cert + chain) file.

        Returns:
            True if deployment was successful, False otherwise.
        """
        ...

    @abstractmethod
    def remove(self, domain: str) -> bool:
        """Remove a deployed certificate from the target.

        Args:
            domain: The primary domain of the certificate to remove.

        Returns:
            True if removal was successful, False otherwise.
        """
        ...

    def reload_service(self) -> bool:
        """Reload the target service to pick up the new certificate.

        Returns:
            True if the service was reloaded successfully, False otherwise.
        """
        self._logger.info("No reload action defined for this deployer")
        return True

    def test_config(self) -> bool:
        """Test the deployer configuration.

        Returns:
            True if the configuration is valid, False otherwise.
        """
        return True

    @property
    def name(self) -> str:
        """Return the deployer name."""
        return self.__class__.__name__

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"


def get_deployer(
    deployer_type: str,
    config: Optional[Dict[str, Any]] = None,
) -> BaseDeployer:
    """Factory function to create a deployer instance.

    Args:
        deployer_type: The deployer type identifier.
        config: Deployer-specific configuration.

    Returns:
        An instance of the requested deployer.

    Raises:
        ValueError: If the deployer type is not supported.
    """
    deployer_type = deployer_type.lower().strip()

    if deployer_type == "nginx":
        from certpilot.deployers.nginx import NginxDeployer
        return NginxDeployer(config)
    elif deployer_type == "apache":
        from certpilot.deployers.apache import ApacheDeployer
        return ApacheDeployer(config)
    elif deployer_type == "file":
        from certpilot.deployers.file import FileDeployer
        return FileDeployer(config)
    elif deployer_type == "k8s" or deployer_type == "kubernetes":
        from certpilot.deployers.k8s import K8sDeployer
        return K8sDeployer(config)
    else:
        raise ValueError(
            f"Unsupported deployer: {deployer_type}. "
            f"Supported: nginx, apache, file, k8s"
        )
