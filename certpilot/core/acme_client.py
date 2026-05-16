"""ACME protocol client for CertPilot.

Implements the ACME v2 protocol for communicating with
Let's Encrypt, ZeroSSL, and Buypass certificate authorities.
"""

import hashlib
import json
import logging
import os
import time
import urllib.parse
from base64 import urlsafe_b64encode
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)


def _b64encode(data: bytes) -> str:
    """Base64url encode data without padding.

    Args:
        data: Raw bytes to encode.

    Returns:
        Base64url-encoded string.
    """
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    """Base64url decode data with padding restoration.

    Args:
        data: Base64url-encoded string.

    Returns:
        Decoded bytes.
    """
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return urlsafe_b64encode(data.encode("ascii"))


class ACMEClient:
    """ACME v2 protocol client.

    Handles account registration, order creation, challenge fulfillment,
    and certificate download from ACME-compliant certificate authorities.

    Supported CAs:
    - Let's Encrypt (production + staging)
    - ZeroSSL
    - Buypass
    """

    # Known ACME directory URLs
    CA_DIRECTORIES = {
        "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
        "letsencrypt_staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "zerossl": "https://acme.zerossl.com/v2/DV90",
        "buypass": "https://api.buypass.com/acme/directory",
    }

    def __init__(
        self,
        ca: str = "letsencrypt",
        account_dir: Optional[str] = None,
        email: Optional[str] = None,
        staging: bool = False,
    ):
        """Initialize the ACME client.

        Args:
            ca: Certificate authority identifier.
            account_dir: Directory for storing account keys and data.
            email: Contact email for ACME account.
            staging: Whether to use staging environment (Let's Encrypt only).
        """
        self._ca = ca
        self._email = email or ""
        self._account_dir = os.path.expanduser(account_dir or "~/.certpilot/accounts")
        self._staging = staging

        # Determine directory URL
        if staging and ca == "letsencrypt":
            self._directory_url = self.CA_DIRECTORIES["letsencrypt_staging"]
        else:
            self._directory_url = self.CA_DIRECTORIES.get(ca)
            if not self._directory_url:
                raise ValueError(f"Unknown CA: {ca}. Supported: {list(self.CA_DIRECTORIES.keys())}")

        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/jose+json"})

        # Account state
        self._account_key = None
        self._account_key_jwk = None
        self._account_url = None
        self._directory = None
        self._nonce = None

        # Ensure account directory exists
        os.makedirs(self._account_dir, exist_ok=True)

    @property
    def ca_name(self) -> str:
        """Return the CA display name."""
        names = {
            "letsencrypt": "Let's Encrypt",
            "letsencrypt_staging": "Let's Encrypt (Staging)",
            "zerossl": "ZeroSSL",
            "buypass": "Buypass",
        }
        return names.get(self._ca, self._ca)

    def _get_directory(self) -> Dict[str, str]:
        """Fetch the ACME server directory.

        Returns:
            Dictionary mapping resource names to URLs.
        """
        if self._directory:
            return self._directory

        logger.info(f"Fetching ACME directory from {self._directory_url}")
        response = self._session.get(self._directory_url)
        response.raise_for_status()
        self._directory = response.json()
        logger.info(f"Connected to {self.ca_name} ACME server")
        return self._directory

    def _get_nonce(self) -> str:
        """Get a fresh replay nonce from the ACME server.

        Returns:
            A nonce string.
        """
        if self._nonce:
            return self._nonce

        directory = self._get_directory()
        new_nonce_url = directory.get("newNonce")

        response = self._session.head(new_nonce_url)
        response.raise_for_status()

        self._nonce = response.headers.get("Replay-Nonce", "")
        return self._nonce

    def _load_or_create_account_key(self):
        """Load existing account key or create a new one.

        Uses ECDSA P-256 keys for account registration.
        """
        from certpilot.utils.crypto import generate_private_key, serialize_private_key

        key_path = os.path.join(self._account_dir, f"{self._ca}_account_key.pem")

        if os.path.exists(key_path):
            logger.info(f"Loading existing account key from {key_path}")
            with open(key_path, "rb") as f:
                key_data = f.read()
            from certpilot.utils.crypto import load_private_key
            self._account_key = load_private_key(key_data)
        else:
            logger.info("Generating new account key (ECDSA P-256)")
            self._account_key = generate_private_key("ecdsa_p256")
            key_data = serialize_private_key(self._account_key)
            with open(key_path, "wb") as f:
                f.write(key_data)
            os.chmod(key_path, 0o600)

        # Build JWK from the account key
        self._account_key_jwk = self._build_jwk(self._account_key)

    def _build_jwk(self, key) -> Dict[str, str]:
        """Build a JWK (JSON Web Key) from a private key.

        Args:
            key: The private key object.

        Returns:
            JWK dictionary.
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
        )

        if isinstance(key, ec.EllipticCurvePrivateKey):
            numbers = key.public_key().public_numbers()
            # Convert integers to fixed-length byte arrays
            order = key.public_key().curve.key_size
            x_bytes = numbers.x.to_bytes((order + 7) // 8, "big")
            y_bytes = numbers.y.to_bytes((order + 7) // 8, "big")

            curve_names = {
                "secp256r1": "P-256",
                "secp384r1": "P-384",
            }
            curve_name = curve_names.get(
                key.public_key().curve.name, key.public_key().curve.name
            )

            return {
                "kty": "EC",
                "crv": curve_name,
                "x": _b64encode(x_bytes),
                "y": _b64encode(y_bytes),
            }
        else:
            # RSA key
            numbers = key.public_key().public_numbers()
            return {
                "kty": "RSA",
                "n": _b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                "e": _b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            }

    def _sign_jws(
        self,
        url: str,
        payload: Dict[str, Any],
        nonce: Optional[str] = None,
    ) -> str:
        """Create a signed JWS (JSON Web Signature) for an ACME request.

        Args:
            url: The URL to send the request to.
            payload: The request payload.
            nonce: Replay nonce (fetched if not provided).

        Returns:
            JSON string of the signed JWS.
        """
        if not nonce:
            nonce = self._get_nonce()

        if self._account_url:
            # Use existing account URL
            protected = {
                "alg": "ES256",
                "kid": self._account_url,
                "nonce": nonce,
                "url": url,
            }
        else:
            # Use JWK for new account registration
            protected = {
                "alg": "ES256",
                "jwk": self._account_key_jwk,
                "nonce": nonce,
                "url": url,
            }

        protected_b64 = _b64encode(json.dumps(protected, sort_keys=True).encode("utf-8"))
        payload_b64 = _b64encode(json.dumps(payload).encode("utf-8"))

        # Sign the payload
        signing_input = f"{protected_b64}.{payload_b64}".encode("utf-8")
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.hazmat.primitives import hashes

        signature = self._account_key.sign(
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )

        # Convert DER signature to raw (r, s) format
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(signature)
        key_size = self._account_key.public_key().curve.key_size
        sig_bytes = (
            r.to_bytes(key_size // 8, "big")
            + s.to_bytes(key_size // 8, "big")
        )
        signature_b64 = _b64encode(sig_bytes)

        jws = {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }

        return json.dumps(jws)

    def _post(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a signed POST request to the ACME server.

        Args:
            url: The ACME server endpoint URL.
            payload: The request payload.

        Returns:
            Response JSON dictionary.
        """
        jws = self._sign_jws(url, payload)
        response = self._session.post(url, data=jws)

        # Update nonce from response
        new_nonce = response.headers.get("Replay-Nonce")
        if new_nonce:
            self._nonce = new_nonce

        # Handle errors
        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_type = error_data.get("type", "unknown")
                error_detail = error_data.get("detail", response.text)
                logger.error(f"ACME error ({response.status_code}): {error_type} - {error_detail}")
                raise ACMEError(f"ACME error: {error_detail}", status=response.status_code)
            except json.JSONDecodeError:
                raise ACMEError(
                    f"ACME request failed with status {response.status_code}: {response.text}",
                    status=response.status_code,
                )

        if response.status_code == 204:
            return {}

        return response.json()

    def register(self, email: Optional[str] = None) -> str:
        """Register or retrieve an ACME account.

        Args:
            email: Contact email (overrides constructor email).

        Returns:
            The account URL.
        """
        self._load_or_create_account_key()

        contact_email = email or self._email
        contacts = []
        if contact_email:
            contacts.append(f"mailto:{contact_email}")

        directory = self._get_directory()
        payload = {
            "termsOfServiceAgreed": True,
        }
        if contacts:
            payload["contact"] = contacts

        logger.info(f"Registering ACME account with {self.ca_name}")
        if contact_email:
            logger.info(f"Contact email: {contact_email}")

        try:
            result = self._post(directory["newAccount"], payload)
            self._account_url = result.get("url") or response_url(result)
            logger.info(f"Account registered: {self._account_url}")
            return self._account_url
        except ACMEError as e:
            if e.status == 200:
                # Account already exists
                logger.info("Account already exists, retrieving...")
                result = self._post(directory["newAccount"], {"onlyReturnExisting": True})
                self._account_url = result.get("url") or response_url(result)
                return self._account_url
            raise

    def create_order(self, domains: List[str]) -> Dict[str, Any]:
        """Create a new certificate order.

        Args:
            domains: List of domain names to include in the certificate.

        Returns:
            Order response dictionary with order URL, authorizations, and finalize URL.
        """
        if not self._account_url:
            self.register()

        directory = self._get_directory()

        # Build identifiers
        identifiers = [{"type": "dns", "value": d} for d in domains]

        payload = {"identifiers": identifiers}

        logger.info(f"Creating certificate order for: {', '.join(domains)}")
        result = self._post(directory["newOrder"], payload)

        order_url = result.get("url") or response_url(result)
        logger.info(f"Order created: {order_url}")

        return {
            "url": order_url,
            "status": result.get("status"),
            "authorizations": result.get("authorizations", []),
            "finalize": result.get("finalize"),
            "expires": result.get("expires"),
            "identifiers": result.get("identifiers", identifiers),
        }

    def get_authorization(self, auth_url: str) -> Dict[str, Any]:
        """Fetch authorization details.

        Args:
            auth_url: The authorization URL.

        Returns:
            Authorization details dictionary.
        """
        return self._post(auth_url, {})

    def get_challenge(self, challenge_url: str) -> Dict[str, Any]:
        """Fetch challenge details.

        Args:
            challenge_url: The challenge URL.

        Returns:
            Challenge details dictionary.
        """
        return self._post(challenge_url, {})

    def request_challenge(self, challenge_url: str) -> Dict[str, Any]:
        """Notify the ACME server that a challenge is ready for validation.

        Args:
            challenge_url: The challenge URL to trigger.

        Returns:
            Challenge response dictionary.
        """
        logger.info(f"Requesting challenge validation: {challenge_url}")
        return self._post(challenge_url, {})

    def poll_authorization(self, auth_url: str, timeout: int = 300, interval: int = 5) -> Dict[str, Any]:
        """Poll an authorization until it's valid or invalid.

        Args:
            auth_url: The authorization URL to poll.
            timeout: Maximum polling time in seconds.
            interval: Polling interval in seconds.

        Returns:
            Final authorization status dictionary.
        """
        elapsed = 0
        while elapsed < timeout:
            auth = self.get_authorization(auth_url)
            status = auth.get("status", "")

            if status == "valid":
                logger.info("Authorization validated successfully")
                return auth
            elif status == "invalid":
                error = auth.get("challenges", [{}])
                logger.error(f"Authorization failed: {auth}")
                raise ACMEError(f"Authorization failed: {status}")

            logger.debug(f"Authorization status: {status}, waiting...")
            time.sleep(interval)
            elapsed += interval

        raise ACMEError(f"Authorization timed out after {timeout}s")

    def finalize_order(
        self,
        finalize_url: str,
        csr_der: bytes,
        timeout: int = 300,
        interval: int = 5,
    ) -> Tuple[bytes, str]:
        """Finalize a certificate order by submitting the CSR.

        Args:
            finalize_url: The order's finalize URL.
            csr_der: DER-encoded Certificate Signing Request.
            timeout: Maximum wait time for order processing.
            interval: Polling interval.

        Returns:
            Tuple of (certificate_pem, order_url).
        """
        payload = {"csr": _b64encode(csr_der)}

        logger.info("Submitting CSR to finalize order")
        result = self._post(finalize_url, payload)

        order_url = result.get("url") or response_url(result)
        certificate_url = result.get("certificate")

        # If order is still processing, poll until complete
        if not certificate_url:
            elapsed = 0
            while elapsed < timeout:
                if result.get("status") == "valid":
                    certificate_url = result.get("certificate")
                    break
                elif result.get("status") == "invalid":
                    raise ACMEError("Order became invalid during finalization")

                time.sleep(interval)
                elapsed += interval

                # Re-fetch the order
                result = self._post(order_url, {})

        if not certificate_url:
            raise ACMEError("Certificate URL not found after order finalization")

        # Download the certificate
        logger.info("Downloading certificate")
        cert_response = self._post(certificate_url, {})
        cert_pem = cert_response if isinstance(cert_response, str) else json.dumps(cert_response)

        # If the response is a dict, it might be the raw cert
        if isinstance(cert_response, dict):
            cert_der = cert_response.get("certificate", "")
            # Try to get it from the response directly
            download_resp = self._session.get(certificate_url)
            cert_pem = download_resp.text

        return cert_pem.encode("utf-8"), order_url

    def revoke_certificate(self, cert_pem: bytes, reason: int = 0) -> bool:
        """Revoke a certificate.

        Args:
            cert_pem: PEM-encoded certificate to revoke.
            reason: Revocation reason code (0 = unspecified).

        Returns:
            True if revocation was successful.
        """
        from cryptography import x509

        if not self._account_url:
            self.register()

        directory = self._get_directory()
        cert = x509.load_pem_x509_certificate(cert_pem)
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        payload = {
            "certificate": _b64encode(cert_der),
            "reason": reason,
        }

        logger.info("Revoking certificate")
        try:
            self._post(directory["revokeCert"], payload)
            logger.info("Certificate revoked successfully")
            return True
        except ACMEError as e:
            logger.error(f"Failed to revoke certificate: {e}")
            return False

    def get_dns_challenge(self, auth: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract DNS-01 challenge from an authorization.

        Args:
            auth: Authorization response dictionary.

        Returns:
            DNS challenge dictionary, or None if not found.
        """
        for challenge in auth.get("challenges", []):
            if challenge.get("type") == "dns-01":
                return challenge
        return None

    def get_http_challenge(self, auth: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract HTTP-01 challenge from an authorization.

        Args:
            auth: Authorization response dictionary.

        Returns:
            HTTP challenge dictionary, or None if not found.
        """
        for challenge in auth.get("challenges", []):
            if challenge.get("type") == "http-01":
                return challenge
        return None

    @staticmethod
    def compute_dns_challenge_value(token: str, account_key_jwk: Dict[str, str]) -> str:
        """Compute the DNS TXT record value for a DNS-01 challenge.

        The value is the base64url SHA-256 digest of the key authorization.

        Args:
            token: The challenge token from the ACME server.
            account_key_jwk: The account's JWK.

        Returns:
            The DNS TXT record value.
        """
        key_authorization = f"{token}.{_b64encode(json.dumps(account_key_jwk, sort_keys=True).encode('utf-8'))}"
        digest = hashlib.sha256(key_authorization.encode("utf-8")).digest()
        return _b64encode(digest)

    @staticmethod
    def compute_http_challenge_value(token: str, account_key_jwk: Dict[str, str]) -> str:
        """Compute the key authorization for an HTTP-01 challenge.

        Args:
            token: The challenge token from the ACME server.
            account_key_jwk: The account's JWK.

        Returns:
            The key authorization string.
        """
        thumbprint = _b64encode(json.dumps(account_key_jwk, sort_keys=True).encode("utf-8"))
        return f"{token}.{thumbprint}"


class ACMEError(Exception):
    """ACME protocol error."""

    def __init__(self, message: str, status: int = 0, detail: str = ""):
        super().__init__(message)
        self.status = status
        self.detail = detail


def response_url(data: Dict[str, Any]) -> str:
    """Extract URL from ACME response headers or Location header.

    This is a helper since the actual URL may come from response headers
    rather than the JSON body.

    Args:
        data: Response data dictionary.

    Returns:
        URL string or empty string.
    """
    return data.get("url", "")


# Import needed for serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
