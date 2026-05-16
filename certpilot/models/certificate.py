"""Certificate data models for CertPilot."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class CertificateStatus(str, Enum):
    """Certificate lifecycle status."""

    PENDING = "pending"
    ISSUED = "issued"
    RENEWING = "renewing"
    REVOKED = "revoked"
    EXPIRED = "expired"
    ERROR = "error"


class KeyType(str, Enum):
    """Supported private key types."""

    RSA_2048 = "rsa2048"
    RSA_4096 = "rsa4096"
    ECC_P256 = "ecdsa_p256"
    ECC_P384 = "ecdsa_p384"


class KeyUsageInfo(BaseModel):
    """X.509 key usage extension information."""

    digital_signature: bool = False
    key_encipherment: bool = False
    content_commitment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    extended_key_usage: List[str] = Field(default_factory=list)


class CertificateInfo(BaseModel):
    """Parsed X.509 certificate information."""

    subject_cn: str = ""
    subject_alt_names: List[str] = Field(default_factory=list)
    issuer_cn: str = ""
    issuer_organization: str = ""
    serial_number: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_size: int = 0
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""
    key_usage: Optional[KeyUsageInfo] = None
    is_wildcard: bool = False
    days_to_expiry: int = 0
    is_expired: bool = False


class CertificateRecord(BaseModel):
    """A managed certificate record stored in local database."""

    id: str = ""
    domain: str
    san_domains: List[str] = Field(default_factory=list)
    status: CertificateStatus = CertificateStatus.PENDING
    key_type: KeyType = KeyType.RSA_2048
    ca_provider: str = "letsencrypt"
    dns_provider: str = "manual"
    deployer: str = "file"
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    chain_path: Optional[str] = None
    fullchain_path: Optional[str] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    renewed_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    order_url: Optional[str] = None
    error_message: Optional[str] = None
    auto_renew: bool = True
    renew_days_before: int = 30
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    @property
    def all_domains(self) -> List[str]:
        """Return the primary domain plus all SAN domains."""
        domains = [self.domain]
        domains.extend(d for d in self.san_domains if d != self.domain)
        return domains

    @property
    def needs_renewal(self) -> bool:
        """Check if certificate needs renewal based on configured threshold."""
        if not self.expires_at:
            return False
        if not self.auto_renew:
            return False
        delta = (self.expires_at - datetime.now()).days
        return delta <= self.renew_days_before


class CertificateChain(BaseModel):
    """Certificate chain information."""

    leaf: Optional[CertificateInfo] = None
    intermediates: List[CertificateInfo] = Field(default_factory=list)
    is_complete: bool = False
    errors: List[str] = Field(default_factory=list)
