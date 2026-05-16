"""Cloudflare DNS provider for CertPilot.

Manages DNS TXT records via the Cloudflare API for ACME DNS-01 challenges.
Uses API token-based authentication (recommended by Cloudflare).
"""

import logging
from typing import Any, Dict, List, Optional

import requests

from certpilot.providers.base import BaseDNSProvider

logger = logging.getLogger(__name__)

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareProvider(BaseDNSProvider):
    """Cloudflare DNS provider using API token authentication.

    Supports creating and deleting TXT records for ACME challenge verification.
    Requires a Cloudflare API token with Zone:DNS:Edit permissions.

    Configuration:
        api_token: Cloudflare API token (required)
        api_email: Cloudflare account email (optional, for legacy auth)
        zone_id: Cloudflare zone ID (optional, auto-detected if not provided)
        proxy: Whether to set Cloudflare proxy (orange cloud) on records
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Cloudflare DNS provider.

        Args:
            config: Configuration dictionary with Cloudflare credentials.
        """
        super().__init__(config)
        self._api_token = self._config.get("api_token", "")
        self._api_email = self._config.get("api_email", "")
        self._zone_id = self._config.get("zone_id", "")
        self._proxy = self._config.get("proxy", False)
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
        })

        if not self._api_token:
            logger.warning("Cloudflare API token is not configured")

    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers.

        Returns:
            Dictionary of HTTP headers for Cloudflare API requests.
        """
        headers = {
            "Content-Type": "application/json",
        }
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"
        elif self._api_email:
            # Legacy API key auth fallback
            headers["X-Auth-Email"] = self._api_email
            headers["X-Auth-Key"] = self._config.get("api_key", "")
        return headers

    def _get_zone_id(self, domain: str) -> Optional[str]:
        """Get the Cloudflare zone ID for a domain.

        Args:
            domain: The domain to look up the zone for.

        Returns:
            The zone ID string, or None if not found.
        """
        if self._zone_id:
            return self._zone_id

        # Extract the base domain (zone apex)
        parts = domain.split(".")
        if len(parts) >= 2:
            zone_domain = ".".join(parts[-2:])
        else:
            zone_domain = domain

        try:
            response = self._session.get(
                f"{CLOUDFLARE_API_BASE}/zones",
                params={"name": zone_domain},
            )
            response.raise_for_status()
            data = response.json()

            if data.get("success") and data.get("result"):
                zone = data["result"][0]
                self._zone_id = zone["id"]
                logger.info(f"Found Cloudflare zone {zone_domain}: {self._zone_id}")
                return self._zone_id
            else:
                logger.error(f"Zone not found for {zone_domain}")
                return None
        except requests.RequestException as e:
            logger.error(f"Failed to get zone ID: {e}")
            return None

    def _get_record_name(self, domain: str, record_name: str) -> str:
        """Convert FQDN to relative record name for Cloudflare API.

        Cloudflare API expects record names relative to the zone.

        Args:
            domain: The zone domain.
            record_name: The full FQDN of the record.

        Returns:
            The relative record name.
        """
        # Remove trailing dot
        name = record_name.rstrip(".")
        # Remove the domain suffix
        if name.endswith("." + domain):
            name = name[: -(len(domain) + 1)]
        return name

    def create_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: str,
        ttl: int = 60,
    ) -> bool:
        """Create a TXT record in Cloudflare DNS.

        Args:
            domain: The domain being verified.
            record_name: The full FQDN for the TXT record.
            record_value: The TXT record value.
            ttl: Time-to-live in seconds.

        Returns:
            True if successful, False otherwise.
        """
        zone_id = self._get_zone_id(domain)
        if not zone_id:
            logger.error(f"Cannot create TXT record: no zone ID for {domain}")
            return False

        relative_name = self._get_record_name(domain, record_name)

        payload = {
            "type": "TXT",
            "name": relative_name,
            "content": record_value,
            "ttl": ttl,
            "proxied": False,  # TXT records cannot be proxied
        }

        try:
            response = self._session.post(
                f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("success"):
                record_id = data["result"]["id"]
                logger.info(
                    f"Created Cloudflare TXT record: {record_name} -> {record_value} "
                    f"(id: {record_id})"
                )
                return True
            else:
                errors = data.get("errors", [])
                logger.error(f"Cloudflare API error: {errors}")
                return False
        except requests.RequestException as e:
            logger.error(f"Failed to create Cloudflare TXT record: {e}")
            return False

    def delete_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: Optional[str] = None,
    ) -> bool:
        """Delete a TXT record from Cloudflare DNS.

        Args:
            domain: The domain that was verified.
            record_name: The full FQDN of the TXT record.
            record_value: Optional value to match for deletion.

        Returns:
            True if successful, False otherwise.
        """
        zone_id = self._get_zone_id(domain)
        if not zone_id:
            logger.error(f"Cannot delete TXT record: no zone ID for {domain}")
            return False

        relative_name = self._get_record_name(domain, record_name)

        try:
            # First, find the record ID
            params = {"type": "TXT", "name": relative_name}
            response = self._session.get(
                f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records",
                params=params,
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("success") or not data.get("result"):
                logger.warning(f"TXT record not found: {record_name}")
                return True  # Already deleted

            # Find the matching record
            record_id = None
            for record in data["result"]:
                if record_value and record["content"] != record_value:
                    continue
                record_id = record["id"]
                break

            if not record_id:
                logger.warning(f"No matching TXT record found for {record_name}")
                return True

            # Delete the record
            del_response = self._session.delete(
                f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records/{record_id}"
            )
            del_response.raise_for_status()
            del_data = del_response.json()

            if del_data.get("success"):
                logger.info(f"Deleted Cloudflare TXT record: {record_name} (id: {record_id})")
                return True
            else:
                logger.error(f"Failed to delete TXT record: {del_data.get('errors')}")
                return False

        except requests.RequestException as e:
            logger.error(f"Failed to delete Cloudflare TXT record: {e}")
            return False
