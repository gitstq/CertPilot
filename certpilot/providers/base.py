"""Base DNS provider interface for CertPilot.

All DNS providers must implement this interface to support
ACME DNS-01 challenge verification.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BaseDNSProvider(ABC):
    """Abstract base class for DNS providers.

    DNS providers are responsible for creating and deleting TXT records
    needed for ACME DNS-01 challenge verification.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the DNS provider.

        Args:
            config: Provider-specific configuration dictionary.
        """
        self._config = config or {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def create_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: str,
        ttl: int = 60,
    ) -> bool:
        """Create a DNS TXT record for ACME challenge verification.

        Args:
            domain: The domain being verified.
            record_name: The full record name (FQDN) for the TXT record.
            record_value: The TXT record value (challenge token).
            ttl: Time-to-live for the DNS record in seconds.

        Returns:
            True if the record was created successfully, False otherwise.
        """
        ...

    @abstractmethod
    def delete_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: Optional[str] = None,
    ) -> bool:
        """Delete a DNS TXT record after challenge verification.

        Args:
            domain: The domain that was verified.
            record_name: The full record name (FQDN) of the TXT record.
            record_value: Optional record value to match for deletion.

        Returns:
            True if the record was deleted successfully, False otherwise.
        """
        ...

    def wait_for_propagation(
        self,
        record_name: str,
        expected_value: str,
        timeout: int = 300,
        interval: int = 10,
    ) -> bool:
        """Wait for DNS record propagation by polling.

        Args:
            record_name: The FQDN of the TXT record to check.
            expected_value: The expected TXT record value.
            timeout: Maximum wait time in seconds.
            interval: Polling interval in seconds.

        Returns:
            True if the record propagated within the timeout, False otherwise.
        """
        import time

        self._logger.info(
            f"Waiting for DNS propagation of {record_name} "
            f"(timeout: {timeout}s, interval: {interval}s)"
        )

        elapsed = 0
        while elapsed < timeout:
            try:
                current_value = self._query_txt_record(record_name)
                if current_value and expected_value in current_value:
                    self._logger.info(f"DNS record propagated after {elapsed}s")
                    return True
            except Exception as e:
                self._logger.debug(f"DNS query failed: {e}")

            time.sleep(interval)
            elapsed += interval

        self._logger.warning(
            f"DNS propagation timed out after {timeout}s for {record_name}"
        )
        return False

    def _query_txt_record(self, fqdn: str) -> Optional[str]:
        """Query a TXT record from DNS.

        Args:
            fqdn: The fully qualified domain name to query.

        Returns:
            The TXT record value, or None if not found.
        """
        import dns.resolver

        try:
            # Strip trailing dot if present
            query_name = fqdn.rstrip(".")
            answers = dns.resolver.resolve(query_name, "TXT")
            for rdata in answers:
                value = str(rdata).strip('"')
                if value:
                    return value
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            self._logger.debug(f"DNS query error for {fqdn}: {e}")

        return None

    @property
    def name(self) -> str:
        """Return the provider name."""
        return self.__class__.__name__

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"


def get_dns_provider(
    provider_type: str,
    config: Optional[Dict[str, Any]] = None,
) -> BaseDNSProvider:
    """Factory function to create a DNS provider instance.

    Args:
        provider_type: The provider type identifier.
        config: Provider-specific configuration.

    Returns:
        An instance of the requested DNS provider.

    Raises:
        ValueError: If the provider type is not supported.
    """
    provider_type = provider_type.lower().strip()

    if provider_type == "cloudflare":
        from certpilot.providers.cloudflare import CloudflareProvider
        return CloudflareProvider(config)
    elif provider_type == "aliyun":
        from certpilot.providers.aliyun import AliyunProvider
        return AliyunProvider(config)
    elif provider_type == "tencent":
        from certpilot.providers.tencent import TencentProvider
        return TencentProvider(config)
    elif provider_type == "manual":
        from certpilot.providers.manual import ManualProvider
        return ManualProvider(config)
    else:
        raise ValueError(
            f"Unsupported DNS provider: {provider_type}. "
            f"Supported: cloudflare, aliyun, tencent, manual"
        )
