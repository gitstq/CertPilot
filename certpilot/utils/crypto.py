"""Cryptographic utility functions for CertPilot.

Provides key generation, CSR creation, signature operations,
and other cryptographic helpers used throughout the application.
"""

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


def generate_private_key(
    key_type: str = "rsa2048",
) -> rsa.RSAPrivateKey:
    """Generate a private key based on the specified type.

    Args:
        key_type: Key type identifier. Supported values:
            - 'rsa2048': RSA 2048-bit key
            - 'rsa4096': RSA 4096-bit key
            - 'ecdsa_p256': ECDSA P-256 key
            - 'ecdsa_p384': ECDSA P-384 key

    Returns:
        A private key object (RSA or EC).

    Raises:
        ValueError: If the key type is not supported.
    """
    key_type = key_type.lower().strip()

    if key_type == "rsa2048":
        logger.info("Generating RSA 2048-bit private key")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    elif key_type == "rsa4096":
        logger.info("Generating RSA 4096-bit private key")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
    elif key_type in ("ecdsa_p256", "p256"):
        logger.info("Generating ECDSA P-256 private key")
        return ec.generate_private_key(ec.SECP256R1())
    elif key_type in ("ecdsa_p384", "p384"):
        logger.info("Generating ECDSA P-384 private key")
        return ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError(
            f"Unsupported key type: {key_type}. "
            f"Supported: rsa2048, rsa4096, ecdsa_p256, ecdsa_p384"
        )


def serialize_private_key(
    key: rsa.RSAPrivateKey,
    password: Optional[bytes] = None,
    format_type: str = "pem",
) -> bytes:
    """Serialize a private key to bytes.

    Args:
        key: The private key to serialize.
        password: Optional password for encrypting the key (PEM only).
        format_type: Output format - 'pem' or 'der'.

    Returns:
        Serialized key bytes.
    """
    enc = serialization.NoEncryption()
    if password and format_type == "pem":
        enc = serialization.BestAvailableEncryption(password)

    if format_type == "pem":
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc,
        )
    elif format_type == "der":
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        raise ValueError(f"Unsupported format: {format_type}")


def load_private_key(
    data: bytes,
    password: Optional[bytes] = None,
) -> rsa.RSAPrivateKey:
    """Load a private key from PEM or DER bytes.

    Args:
        data: The key data in PEM or DER format.
        password: Optional password for encrypted keys.

    Returns:
        A private key object.

    Raises:
        ValueError: If the key cannot be loaded.
    """
    try:
        return serialization.load_pem_private_key(data, password=password)
    except Exception:
        try:
            return serialization.load_der_private_key(data, password=password)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}")


def create_csr(
    private_key: rsa.RSAPrivateKey,
    domains: List[str],
    organization: str = "",
    country: str = "",
    state: str = "",
    locality: str = "",
) -> bytes:
    """Create a Certificate Signing Request (CSR) for the given domains.

    Args:
        private_key: The private key to sign the CSR with.
        domains: List of domains to include in the CSR.
            The first domain is used as the Common Name (CN).
        organization: Organization name (O).
        country: Country code (C), e.g., 'CN', 'US'.
        state: State or province (ST).
        locality: City or locality (L).

    Returns:
        CSR in DER format (for ACME protocol).
    """
    if not domains:
        raise ValueError("At least one domain is required for CSR creation")

    primary = domains[0]
    san_domains = [d for d in domains[1:] if d != primary]

    # Build subject name attributes
    name_attrs: List[x509.NameAttribute] = [x509.NameAttribute(NameOID.COMMON_NAME, primary)]
    if country:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    subject = x509.Name(name_attrs)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    # Add SAN extension if there are additional domains
    all_names = [x509.DNSName(d) for d in domains]
    builder = builder.add_extension(
        x509.SubjectAlternativeName(all_names),
        critical=False,
    )

    # Determine hash algorithm based on key type
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        hash_alg = hashes.SHA256()
    else:
        hash_alg = hashes.SHA256()

    csr = builder.sign(private_key, hash_alg)
    logger.info(f"Created CSR for domains: {', '.join(domains)}")
    return csr


def create_csr_pem(
    private_key: rsa.RSAPrivateKey,
    domains: List[str],
    organization: str = "",
    country: str = "",
    state: str = "",
    locality: str = "",
) -> str:
    """Create a CSR and return it as PEM string.

    Args:
        Same as create_csr().

    Returns:
        CSR in PEM format string.
    """
    csr = create_csr(private_key, domains, organization, country, state, locality)
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def get_public_key_info(key: rsa.RSAPublicKey) -> dict:
    """Extract information from a public key.

    Args:
        key: The public key to inspect.

    Returns:
        Dictionary with key algorithm, size, and curve (if EC).
    """
    info: dict = {}
    if isinstance(key, rsa.RSAPublicKey):
        info["algorithm"] = "RSA"
        info["key_size"] = key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        info["algorithm"] = "ECDSA"
        info["key_size"] = key.key_size
        info["curve"] = key.curve.name
    else:
        info["algorithm"] = "Unknown"
        info["key_size"] = 0
    return info


def compute_fingerprint(cert_data: bytes, algorithm: str = "sha256") -> str:
    """Compute the fingerprint of a certificate.

    Args:
        cert_data: The DER-encoded certificate data.
        algorithm: Hash algorithm - 'sha256' or 'sha1'.

    Returns:
        Colon-separated hex fingerprint string.
    """
    if algorithm == "sha256":
        h = hashlib.sha256(cert_data).hexdigest()
    elif algorithm == "sha1":
        h = hashlib.sha1(cert_data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Format as colon-separated hex pairs
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


def verify_certificate_signature(
    cert: x509.Certificate,
    issuer_cert: Optional[x509.Certificate] = None,
) -> bool:
    """Verify a certificate's signature.

    Args:
        cert: The certificate to verify.
        issuer_cert: The issuer's certificate. If None, uses self-signature check.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        if issuer_cert is None:
            issuer_cert = cert
        issuer_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def save_private_key_to_file(
    key: rsa.RSAPrivateKey,
    filepath: str,
    password: Optional[bytes] = None,
) -> None:
    """Save a private key to a file with restricted permissions.

    Args:
        key: The private key to save.
        filepath: Path to save the key file.
        password: Optional password for encryption.
    """
    key_data = serialize_private_key(key, password=password)
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(key_data)
    # Set restrictive permissions on key file
    os.chmod(filepath, 0o600)
    logger.info(f"Private key saved to {filepath}")


def save_certificate_to_file(cert_data: bytes, filepath: str) -> None:
    """Save certificate data to a PEM file.

    Args:
        cert_data: PEM-encoded certificate data.
        filepath: Path to save the certificate file.
    """
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(cert_data)
    os.chmod(filepath, 0o644)
    logger.info(f"Certificate saved to {filepath}")


def pem_to_der(pem_data: bytes) -> bytes:
    """Convert PEM-encoded data to DER format.

    Args:
        pem_data: PEM-encoded data.

    Returns:
        DER-encoded data.
    """
    # Use cryptography library for reliable conversion
    if b"-----BEGIN CERTIFICATE-----" in pem_data:
        cert = x509.load_pem_x509_certificate(pem_data)
        return cert.public_bytes(serialization.Encoding.DER)
    elif b"-----BEGIN PRIVATE KEY-----" in pem_data or b"-----BEGIN RSA PRIVATE KEY-----" in pem_data:
        key = serialization.load_pem_private_key(pem_data, password=None)
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        raise ValueError("Unrecognized PEM format")


def der_to_pem(der_data: bytes, is_cert: bool = True) -> bytes:
    """Convert DER-encoded data to PEM format.

    Args:
        der_data: DER-encoded data.
        is_cert: True if the data is a certificate, False for private key.

    Returns:
        PEM-encoded data.
    """
    if is_cert:
        cert = x509.load_der_x509_certificate(der_data)
        return cert.public_bytes(serialization.Encoding.PEM)
    else:
        key = serialization.load_der_private_key(der_data, password=None)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
