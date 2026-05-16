"""Manual DNS provider for CertPilot.

Provides instructions for manually creating DNS TXT records
when automated DNS providers are not available.
"""

import logging
import time
from typing import Any, Dict, Optional

from certpilot.providers.base import BaseDNSProvider

logger = logging.getLogger(__name__)


class ManualProvider(BaseDNSProvider):
    """Manual DNS provider for user-guided ACME challenge verification.

    This provider does not automatically create DNS records. Instead, it
    displays instructions to the user and waits for manual record creation.
    Suitable for environments where API-based DNS management is not available.

    Configuration:
        wait_timeout: Maximum time to wait for user confirmation (default: 600)
        auto_continue: Whether to auto-continue without waiting (default: False)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Manual DNS provider.

        Args:
            config: Configuration dictionary.
        """
        super().__init__(config)
        self._wait_timeout = self._config.get("wait_timeout", 600)
        self._auto_continue = self._config.get("auto_continue", False)
        self._created_records: Dict[str, str] = {}  # record_name -> record_value

    def create_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: str,
        ttl: int = 60,
    ) -> bool:
        """Display instructions for creating a TXT record manually.

        Args:
            domain: The domain being verified.
            record_name: The full FQDN for the TXT record.
            record_value: The TXT record value.
            ttl: Time-to-live in seconds (informational only).

        Returns:
            Always True (assumes user will create the record).
        """
        self._created_records[record_name] = record_value

        logger.info(f"Manual DNS: Please create TXT record for {record_name}")

        # Print instructions using Rich
        try:
            from certpilot.utils.output import print_dns_instructions
            print_dns_instructions(record_name, record_value)
        except ImportError:
            # Fallback if Rich output not available
            print(f"\n{'='*60}")
            print("DNS Verification Required")
            print(f"{'='*60}")
            print(f"  Type:  TXT")
            print(f"  Name:  {record_name}")
            print(f"  Value: {record_value}")
            print(f"  TTL:   {ttl}")
            print(f"{'='*60}")
            print("Please create this DNS record and press Enter to continue...")
            print()

        if not self._auto_continue:
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                logger.info("User skipped manual DNS confirmation")

        return True

    def delete_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: Optional[str] = None,
    ) -> bool:
        """Display instructions for removing a TXT record.

        Args:
            domain: The domain that was verified.
            record_name: The full FQDN of the TXT record.
            record_value: Optional value to match.

        Returns:
            Always True (assumes user will clean up).
        """
        actual_value = record_value or self._created_records.get(record_name, "")

        logger.info(f"Manual DNS: Please remove TXT record for {record_name}")

        try:
            from certpilot.utils.output import print_info
            print_info(
                f"You can now remove the DNS TXT record:\n"
                f"  Name:  {record_name}\n"
                f"  Value: {actual_value}"
            )
        except ImportError:
            print(f"\nYou can now remove the DNS TXT record:")
            print(f"  Name:  {record_name}")
            if actual_value:
                print(f"  Value: {actual_value}")
            print()

        # Remove from tracking
        self._created_records.pop(record_name, None)
        return True

    def wait_for_propagation(
        self,
        record_name: str,
        expected_value: str,
        timeout: int = 300,
        interval: int = 10,
    ) -> bool:
        """Wait for user to confirm DNS record creation.

        Since we cannot verify DNS propagation automatically in manual mode,
        we simply wait for the user to confirm.

        Args:
            record_name: The FQDN of the TXT record.
            expected_value: The expected TXT record value.
            timeout: Maximum wait time in seconds.
            interval: Polling interval in seconds (unused in manual mode).

        Returns:
            True (assumes user confirmed).
        """
        # In manual mode, we trust the user's confirmation
        # Try actual DNS verification first
        result = super().wait_for_propagation(
            record_name, expected_value,
            timeout=min(timeout, 60),  # Shorter timeout for manual
            interval=interval,
        )
        if result:
            return True

        logger.info(
            f"Could not verify DNS propagation for {record_name}. "
            f"Proceeding based on user confirmation."
        )
        return True
