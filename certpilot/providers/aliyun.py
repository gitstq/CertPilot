"""Aliyun DNS provider for CertPilot.

Manages DNS TXT records via the Aliyun (Alibaba Cloud) DNS API
for ACME DNS-01 challenge verification.
"""

import base64
import hashlib
import hmac
import logging
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, Optional

import requests

from certpilot.providers.base import BaseDNSProvider

logger = logging.getLogger(__name__)

ALIYUN_API_BASE = "https://alidns.aliyuncs.com"


class AliyunProvider(BaseDNSProvider):
    """Aliyun DNS provider using AccessKey authentication.

    Supports creating and deleting TXT records for ACME challenge verification.
    Requires an Aliyun AccessKey ID and Secret with DNS management permissions.

    Configuration:
        access_key_id: Aliyun AccessKey ID (required)
        access_key_secret: Aliyun AccessKey Secret (required)
        region_id: Aliyun region ID (default: cn-hangzhou)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Aliyun DNS provider.

        Args:
            config: Configuration dictionary with Aliyun credentials.
        """
        super().__init__(config)
        self._access_key_id = self._config.get("access_key_id", "")
        self._access_key_secret = self._config.get("access_key_secret", "")
        self._region_id = self._config.get("region_id", "cn-hangzhou")
        self._session = requests.Session()

        if not self._access_key_id or not self._access_key_secret:
            logger.warning("Aliyun AccessKey ID or Secret is not configured")

    def _sign_request(self, params: Dict[str, str]) -> Dict[str, str]:
        """Sign an Aliyun API request using HMAC-SHA1.

        Args:
            params: The API request parameters.

        Returns:
            Parameters dict with Signature added.
        """
        # Add common parameters
        params["Format"] = "JSON"
        params["Version"] = "2015-01-09"
        params["AccessKeyId"] = self._access_key_id
        params["SignatureMethod"] = "HMAC-SHA1"
        params["SignatureVersion"] = "1.0"
        params["SignatureNonce"] = str(time.time())
        params["Timestamp"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Sort parameters and build canonical query string
        sorted_params = sorted(params.items())
        canonical_query = "&".join(
            f"{self._percent_encode(k)}={self._percent_encode(v)}"
            for k, v in sorted_params
            if v != ""
        )

        # Build string to sign
        string_to_sign = f"GET&{self._percent_encode('/')}&{self._percent_encode(canonical_query)}"

        # Calculate HMAC-SHA1 signature
        signature = hmac.new(
            (self._access_key_secret + "&").encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha1,
        ).digest()

        params["Signature"] = base64.b64encode(signature).decode("utf-8")
        return params

    @staticmethod
    def _percent_encode(s: str) -> str:
        """URL-encode a string according to Aliyun specifications.

        Args:
            s: The string to encode.

        Returns:
            Percent-encoded string.
        """
        return urllib.parse.quote(str(s), safe="~").replace("+", "%20").replace("*", "%2A")

    def _make_request(self, action: str, params: Optional[Dict[str, str]] = None) -> Optional[Dict]:
        """Make a signed request to the Aliyun DNS API.

        Args:
            action: The API action name.
            params: Additional API parameters.

        Returns:
            Response data dictionary, or None on failure.
        """
        request_params = {"Action": action}
        if params:
            request_params.update(params)

        signed_params = self._sign_request(request_params)

        try:
            response = self._session.get(ALIYUN_API_BASE, params=signed_params, timeout=30)
            response.raise_for_status()
            data = response.json()

            if data.get("Code"):
                logger.error(f"Aliyun API error: {data.get('Message', 'Unknown error')}")
                return None

            return data
        except requests.RequestException as e:
            logger.error(f"Aliyun API request failed: {e}")
            return None

    def _get_domain_name(self, record_name: str) -> str:
        """Extract the domain name from a record FQDN.

        Args:
            record_name: The full FQDN of the record.

        Returns:
            The base domain name.
        """
        name = record_name.rstrip(".")
        parts = name.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return name

    def _get_rr(self, record_name: str, domain: str) -> str:
        """Extract the RR (relative record) name from a FQDN.

        Args:
            record_name: The full FQDN.
            domain: The base domain name.

        Returns:
            The relative record name (RR).
        """
        name = record_name.rstrip(".")
        if name.endswith("." + domain):
            return name[: -(len(domain) + 1)]
        return name

    def create_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: str,
        ttl: int = 60,
    ) -> bool:
        """Create a TXT record in Aliyun DNS.

        Args:
            domain: The domain being verified.
            record_name: The full FQDN for the TXT record.
            record_value: The TXT record value.
            ttl: Time-to-live in seconds.

        Returns:
            True if successful, False otherwise.
        """
        domain_name = self._get_domain_name(record_name)
        rr = self._get_rr(record_name, domain_name)

        params = {
            "DomainName": domain_name,
            "RR": rr,
            "Type": "TXT",
            "Value": record_value,
            "TTL": str(ttl),
        }

        data = self._make_request("AddDomainRecord", params)
        if data and data.get("RecordId"):
            logger.info(
                f"Created Aliyun TXT record: {record_name} -> {record_value} "
                f"(id: {data['RecordId']})"
            )
            return True
        return False

    def delete_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: Optional[str] = None,
    ) -> bool:
        """Delete a TXT record from Aliyun DNS.

        Args:
            domain: The domain that was verified.
            record_name: The full FQDN of the TXT record.
            record_value: Optional value to match for deletion.

        Returns:
            True if successful, False otherwise.
        """
        domain_name = self._get_domain_name(record_name)
        rr = self._get_rr(record_name, domain_name)

        # First, find the record ID
        query_params = {
            "DomainName": domain_name,
            "RRKeyWord": rr,
            "Type": "TXT",
        }

        data = self._make_request("DescribeDomainRecords", query_params)
        if not data:
            logger.warning(f"Could not query Aliyun DNS records for {record_name}")
            return False

        records = data.get("DomainRecords", {}).get("Record", [])
        record_id = None

        for record in records:
            if record.get("RR") == rr:
                if record_value and record.get("Value") != record_value:
                    continue
                record_id = record.get("RecordId")
                break

        if not record_id:
            logger.warning(f"TXT record not found: {record_name}")
            return True  # Already deleted

        # Delete the record
        del_params = {
            "RecordId": str(record_id),
        }

        del_data = self._make_request("DeleteDomainRecord", del_params)
        if del_data is not None:
            logger.info(f"Deleted Aliyun TXT record: {record_name} (id: {record_id})")
            return True
        return False
