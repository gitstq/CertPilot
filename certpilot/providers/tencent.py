"""Tencent Cloud DNS provider for CertPilot.

Manages DNS TXT records via the Tencent Cloud DNSPod API
for ACME DNS-01 challenge verification.
"""

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Dict, Optional

import requests

from certpilot.providers.base import BaseDNSProvider

logger = logging.getLogger(__name__)

TENCENT_API_BASE = "https://dnspod.tencentcloudapi.com"
TENCENT_API_VERSION = "2021-03-23"


class TencentProvider(BaseDNSProvider):
    """Tencent Cloud DNS provider using SecretId/SecretKey authentication.

    Supports creating and deleting TXT records for ACME challenge verification.
    Requires a Tencent Cloud API SecretId and SecretKey with DNSPod permissions.

    Configuration:
        secret_id: Tencent Cloud SecretId (required)
        secret_key: Tencent Cloud SecretKey (required)
        region: Tencent Cloud region (default: ap-guangzhou)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Tencent Cloud DNS provider.

        Args:
            config: Configuration dictionary with Tencent Cloud credentials.
        """
        super().__init__(config)
        self._secret_id = self._config.get("secret_id", "")
        self._secret_key = self._config.get("secret_key", "")
        self._region = self._config.get("region", "ap-guangzhou")
        self._session = requests.Session()

        if not self._secret_id or not self._secret_key:
            logger.warning("Tencent Cloud SecretId or SecretKey is not configured")

    def _sign(
        self,
        payload: str,
        timestamp: int,
        authorization: str,
    ) -> str:
        """Generate TC3-HMAC-SHA256 signature for Tencent Cloud API.

        Args:
            payload: The hashed request body.
            timestamp: Unix timestamp.
            authorization: The credential string.

        Returns:
            The signature string.
        """
        date = time.strftime("%Y-%m-%d", time.gmtime(timestamp))
        credential_scope = f"{date}/dnspod/tc3_request"

        string_to_sign = (
            f"TC3-HMAC-SHA256\n"
            f"{timestamp}\n"
            f"{credential_scope}\n"
            f"{payload}"
        )

        secret_date = hmac.new(
            ("TC3" + self._secret_key).encode("utf-8"),
            date.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        secret_service = hmac.new(
            secret_date,
            "dnspod".encode("utf-8"),
            hashlib.sha256,
        ).digest()

        secret_signing = hmac.new(
            secret_service,
            "tc3_request".encode("utf-8"),
            hashlib.sha256,
        ).digest()

        signature = hmac.new(
            secret_signing,
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return signature

    def _make_request(self, action: str, body: Dict[str, Any]) -> Optional[Dict]:
        """Make a signed request to the Tencent Cloud DNSPod API.

        Args:
            action: The API action name.
            body: The request body parameters.

        Returns:
            Response data dictionary, or None on failure.
        """
        timestamp = int(time.time())
        body["Action"] = action
        body["Version"] = TENCENT_API_VERSION
        body["Region"] = self._region if self._region else ""
        body["Timestamp"] = timestamp
        body["Nonce"] = timestamp

        payload = json.dumps(body)
        hashed_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        authorization = f"TC3-HMAC-SHA256 Credential={self._secret_id}/{time.strftime('%Y-%m-%d', time.gmtime(timestamp))}/dnspod/tc3_request"
        signature = self._sign(hashed_payload, timestamp, authorization)

        headers = {
            "Content-Type": "application/json",
            "Host": "dnspod.tencentcloudapi.com",
            "X-TC-Action": action,
            "X-TC-Version": TENCENT_API_VERSION,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Region": self._region,
            "Authorization": f"{authorization}, SignedHeaders=content-type;host, Signature={signature}",
        }

        try:
            response = self._session.post(
                TENCENT_API_BASE,
                headers=headers,
                data=payload,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            if "Response" not in data:
                logger.error(f"Unexpected Tencent API response: {data}")
                return None

            if "Error" in data["Response"]:
                error = data["Response"]["Error"]
                logger.error(f"Tencent API error: {error.get('Message', 'Unknown')}")
                return None

            return data["Response"]
        except requests.RequestException as e:
            logger.error(f"Tencent API request failed: {e}")
            return None

    def _get_sub_domain(self, record_name: str, domain: str) -> str:
        """Extract the sub-domain part from a FQDN.

        Args:
            record_name: The full FQDN.
            domain: The base domain name.

        Returns:
            The sub-domain (RR) part.
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
        """Create a TXT record in Tencent Cloud DNS.

        Args:
            domain: The domain being verified.
            record_name: The full FQDN for the TXT record.
            record_value: The TXT record value.
            ttl: Time-to-live in seconds.

        Returns:
            True if successful, False otherwise.
        """
        sub_domain = self._get_sub_domain(record_name, domain)

        body = {
            "Domain": domain,
            "SubDomain": sub_domain,
            "RecordType": "TXT",
            "Value": record_value,
            "RecordLine": "默认",
            "TTL": ttl,
        }

        data = self._make_request("CreateRecord", body)
        if data and data.get("RecordId"):
            logger.info(
                f"Created Tencent TXT record: {record_name} -> {record_value} "
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
        """Delete a TXT record from Tencent Cloud DNS.

        Args:
            domain: The domain that was verified.
            record_name: The full FQDN of the TXT record.
            record_value: Optional value to match for deletion.

        Returns:
            True if successful, False otherwise.
        """
        sub_domain = self._get_sub_domain(record_name, domain)

        # First, find the record ID
        query_body = {
            "Domain": domain,
            "Subdomain": sub_domain,
            "RecordType": "TXT",
        }

        data = self._make_request("DescribeRecordList", query_body)
        if not data:
            logger.warning(f"Could not query Tencent DNS records for {record_name}")
            return False

        record_list = data.get("RecordList", [])
        record_id = None

        for record in record_list:
            if record.get("Name") == sub_domain:
                if record_value and record.get("Value") != record_value:
                    continue
                record_id = record.get("RecordId")
                break

        if not record_id:
            logger.warning(f"TXT record not found: {record_name}")
            return True  # Already deleted

        # Delete the record
        del_body = {
            "Domain": domain,
            "RecordId": record_id,
        }

        del_data = self._make_request("DeleteRecord", del_body)
        if del_data is not None:
            logger.info(f"Deleted Tencent TXT record: {record_name} (id: {record_id})")
            return True
        return False
