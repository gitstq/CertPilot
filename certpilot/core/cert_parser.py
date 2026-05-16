"""Certificate parser for CertPilot.

Parses X.509 certificates and extracts detailed information
including subject, issuer, validity periods, SANs, key usage,
and security-related checks.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from certpilot.models.certificate import CertificateChain, CertificateInfo, KeyUsageInfo

logger = logging.getLogger(__name__)


class CertificateParser:
    """X.509 certificate parser and analyzer.

    Parses PEM or DER encoded certificates and extracts comprehensive
    information including identity, validity, extensions, and security status.
    """

    def parse_file(self, filepath: str) -> CertificateInfo:
        """Parse a certificate from a PEM file.

        Args:
            filepath: Path to the PEM-encoded certificate file.

        Returns:
            CertificateInfo object with parsed certificate data.

        Raises:
            FileNotFoundError: If the certificate file does not exist.
            ValueError: If the certificate cannot be parsed.
        """
        with open(filepath, "rb") as f:
            pem_data = f.read()
        return self.parse_pem(pem_data)

    def parse_pem(self, pem_data: bytes) -> CertificateInfo:
        """Parse a PEM-encoded certificate.

        Args:
            pem_data: PEM-encoded certificate data.

        Returns:
            CertificateInfo object with parsed certificate data.

        Raises:
            ValueError: If the certificate cannot be parsed.
        """
        try:
            cert = x509.load_pem_x509_certificate(pem_data)
        except Exception as e:
            raise ValueError(f"Failed to parse PEM certificate: {e}")

        return self._extract_info(cert, pem_data)

    def parse_der(self, der_data: bytes) -> CertificateInfo:
        """Parse a DER-encoded certificate.

        Args:
            der_data: DER-encoded certificate data.

        Returns:
            CertificateInfo object with parsed certificate data.

        Raises:
            ValueError: If the certificate cannot be parsed.
        """
        try:
            cert = x509.load_der_x509_certificate(der_data)
        except Exception as e:
            raise ValueError(f"Failed to parse DER certificate: {e}")

        return self._extract_info(cert, der_data)

    def parse_chain(self, chain_data: bytes) -> CertificateChain:
        """Parse a certificate chain (multiple PEM certificates).

        Args:
            chain_data: PEM-encoded data containing multiple certificates.

        Returns:
            CertificateChain object with leaf, intermediates, and validation status.
        """
        # Split PEM data into individual certificates
        certs = self._split_pem_chain(chain_data)

        if not certs:
            return CertificateChain(
                is_complete=False,
                errors=["No certificates found in chain data"],
            )

        chain = CertificateChain()

        # First certificate is typically the leaf
        try:
            chain.leaf = self.parse_pem(certs[0])
        except Exception as e:
            chain.errors.append(f"Failed to parse leaf certificate: {e}")

        # Remaining certificates are intermediates
        for cert_pem in certs[1:]:
            try:
                intermediate = self.parse_pem(cert_pem)
                chain.intermediates.append(intermediate)
            except Exception as e:
                chain.errors.append(f"Failed to parse intermediate certificate: {e}")

        # Validate chain completeness
        chain.is_complete = self._validate_chain(chain)

        return chain

    def _extract_info(self, cert: x509.Certificate, raw_data: bytes) -> CertificateInfo:
        """Extract information from a parsed certificate.

        Args:
            cert: The parsed x509.Certificate object.
            raw_data: Raw certificate bytes for fingerprint calculation.

        Returns:
            CertificateInfo with all extracted information.
        """
        info = CertificateInfo()

        # Subject information
        info.subject_cn = self._get_name_attribute(cert.subject, NameOID.COMMON_NAME)

        # Issuer information
        info.issuer_cn = self._get_name_attribute(cert.issuer, NameOID.COMMON_NAME)
        info.issuer_organization = self._get_name_attribute(
            cert.issuer, NameOID.ORGANIZATION_NAME
        )

        # Serial number
        info.serial_number = format(cert.serial_number, "X")

        # Validity period
        info.not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        info.not_after = cert.not_valid_after_utc.replace(tzinfo=None)

        # Calculate days to expiry
        now = datetime.now()
        if info.not_after:
            delta = info.not_after - now
            info.days_to_expiry = delta.days
            info.is_expired = delta.total_seconds() < 0

        # Signature algorithm
        info.signature_algorithm = cert.signature_algorithm_oid._name

        # Public key information
        pub_key = cert.public_key()
        if hasattr(pub_key, "key_size"):
            info.public_key_size = pub_key.key_size
        info.public_key_algorithm = type(pub_key).__name__.replace("PublicKey", "")

        # Fingerprints
        der_data = cert.public_bytes(serialization.Encoding.DER)
        info.fingerprint_sha256 = self._compute_fingerprint(der_data, "sha256")
        info.fingerprint_sha1 = self._compute_fingerprint(der_data, "sha1")

        # Subject Alternative Names
        info.subject_alt_names = self._get_san(cert)
        info.is_wildcard = any(d.startswith("*.") for d in info.subject_alt_names)

        # Key Usage
        info.key_usage = self._get_key_usage(cert)

        return info

    @staticmethod
    def _get_name_attribute(name: x509.Name, oid: x509.oid.ObjectIdentifier) -> str:
        """Extract a specific attribute from an X.509 Name.

        Args:
            name: The X.509 Name object.
            oid: The OID of the attribute to extract.

        Returns:
            The attribute value string, or empty string if not found.
        """
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, Exception):
            return ""

    @staticmethod
    def _get_san(cert: x509.Certificate) -> List[str]:
        """Extract Subject Alternative Names from a certificate.

        Args:
            cert: The parsed certificate.

        Returns:
            List of SAN domain names.
        """
        san_names: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_names.append(name.value)
        except x509.ExtensionNotFound:
            pass
        return san_names

    @staticmethod
    def _get_key_usage(cert: x509.Certificate) -> Optional[KeyUsageInfo]:
        """Extract Key Usage and Extended Key Usage from a certificate.

        Args:
            cert: The parsed certificate.

        Returns:
            KeyUsageInfo object, or None if the extension is not present.
        """
        try:
            ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            usage = KeyUsageInfo(
                digital_signature=ku.digital_signature,
                key_encipherment=ku.key_encipherment,
                content_commitment=ku.content_commitment,
                data_encipherment=ku.data_encipherment,
                key_agreement=ku.key_agreement,
                key_cert_sign=ku.key_cert_sign,
                crl_sign=ku.crl_sign,
            )
        except x509.ExtensionNotFound:
            usage = KeyUsageInfo()

        # Extended Key Usage
        try:
            eku_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            eku_names = []
            for usage_oid in eku_ext.value:
                eku_names.append(usage_oid._name)
            usage.extended_key_usage = eku_names
        except x509.ExtensionNotFound:
            pass

        return usage

    @staticmethod
    def _compute_fingerprint(der_data: bytes, algorithm: str = "sha256") -> str:
        """Compute a certificate fingerprint.

        Args:
            der_data: DER-encoded certificate data.
            algorithm: Hash algorithm ('sha256' or 'sha1').

        Returns:
            Colon-separated hex fingerprint string.
        """
        if algorithm == "sha256":
            h = hashlib.sha256(der_data).hexdigest()
        elif algorithm == "sha1":
            h = hashlib.sha1(der_data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        return ":".join(h[i : i + 2] for i in range(0, len(h), 2))

    @staticmethod
    def _split_pem_chain(pem_data: bytes) -> List[bytes]:
        """Split a PEM chain into individual certificates.

        Args:
            pem_data: PEM data containing multiple certificates.

        Returns:
            List of individual PEM-encoded certificates.
        """
        import re

        pem_pattern = re.compile(
            b"-----BEGIN CERTIFICATE-----\r?\n"
            b".*?"
            b"-----END CERTIFICATE-----",
            re.DOTALL,
        )

        return [match.group(0) for match in pem_pattern.finditer(pem_data)]

    def _validate_chain(self, chain: CertificateChain) -> bool:
        """Validate a certificate chain for completeness.

        Checks that:
        1. A leaf certificate exists
        2. The chain links properly (issuer matches subject)
        3. At least one intermediate or root is present

        Args:
            chain: The certificate chain to validate.

        Returns:
            True if the chain appears complete.
        """
        if not chain.leaf:
            chain.errors.append("No leaf certificate found")
            return False

        if not chain.intermediates:
            # Self-signed certificate is valid
            if chain.leaf.issuer_cn == chain.leaf.subject_cn:
                return True
            chain.errors.append("No intermediate certificates found for non-self-signed leaf")
            return False

        # Verify chain linkage
        current_issuer = chain.leaf.issuer_cn
        found_root = False

        for intermediate in chain.intermediates:
            if intermediate.subject_cn != current_issuer:
                chain.errors.append(
                    f"Chain gap: expected issuer '{current_issuer}', "
                    f"found '{intermediate.subject_cn}'"
                )
                return False
            current_issuer = intermediate.issuer_cn
            if intermediate.subject_cn == intermediate.issuer_cn:
                found_root = True

        if not found_root:
            chain.errors.append(
                "Chain does not end with a trusted root certificate"
            )

        return len(chain.errors) == 0

    def check_security(self, info: CertificateInfo) -> List[str]:
        """Check a certificate for security issues.

        Args:
            info: Parsed certificate information.

        Returns:
            List of security warning/error messages.
        """
        issues: List[str] = []

        # Check for SHA-1 signature
        if "sha1" in info.signature_algorithm.lower():
            issues.append(
                f"WEAK: Certificate uses SHA-1 signature algorithm ({info.signature_algorithm}). "
                f"SHA-1 is deprecated and considered insecure."
            )

        # Check for MD5 signature
        if "md5" in info.signature_algorithm.lower():
            issues.append(
                f"INSECURE: Certificate uses MD5 signature algorithm ({info.signature_algorithm}). "
                f"MD5 is broken and should never be used."
            )

        # Check RSA key size
        if info.public_key_algorithm == "RSA" and info.public_key_size < 2048:
            issues.append(
                f"WEAK: RSA key size is {info.public_key_size} bits. "
                f"Minimum recommended is 2048 bits."
            )

        # Check expiry
        if info.is_expired:
            issues.append("EXPIRED: Certificate has expired.")
        elif info.days_to_expiry <= 7:
            issues.append(
                f"WARNING: Certificate expires in {info.days_to_expiry} days."
            )

        return issues

    def get_certificate_summary(self, info: CertificateInfo) -> Dict[str, Any]:
        """Get a human-readable summary of certificate information.

        Args:
            info: Parsed certificate information.

        Returns:
            Dictionary with formatted certificate summary.
        """
        return {
            "Subject CN": info.subject_cn,
            "Issuer": info.issuer_cn or info.issuer_organization,
            "Serial": info.serial_number,
            "Not Before": info.not_before.strftime("%Y-%m-%d %H:%M:%S UTC") if info.not_before else "N/A",
            "Not After": info.not_after.strftime("%Y-%m-%d %H:%M:%S UTC") if info.not_after else "N/A",
            "Days to Expiry": info.days_to_expiry,
            "Expired": "Yes" if info.is_expired else "No",
            "Signature Algorithm": info.signature_algorithm,
            "Public Key": f"{info.public_key_algorithm} {info.public_key_size} bits",
            "SHA-256 Fingerprint": info.fingerprint_sha256,
            "SANs": ", ".join(info.subject_alt_names) if info.subject_alt_names else "None",
            "Wildcard": "Yes" if info.is_wildcard else "No",
        }


# Need to import serialization for DER encoding
from cryptography.hazmat.primitives import serialization
