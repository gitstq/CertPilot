"""Domain-related data models for CertPilot."""

from typing import List, Optional

from pydantic import BaseModel, Field, validator


class DNSTxtRecord(BaseModel):
    """A DNS TXT record for ACME challenge verification."""

    name: str
    value: str
    ttl: int = 60

    @validator("name")
    def validate_name(cls, v: str) -> str:
        """Ensure the record name ends with a dot for FQDN."""
        if v and not v.endswith("."):
            return v + "."
        return v


class DNSChallengeInfo(BaseModel):
    """Information about a DNS challenge that needs to be fulfilled."""

    domain: str
    record_name: str
    record_value: str
    token: str
    fqdn: str = ""

    @property
    def full_record_name(self) -> str:
        """Return the full FQDN for the TXT record."""
        return self.fqdn or f"_acme-challenge.{self.domain}."


class HTTPChallengeInfo(BaseModel):
    """Information about an HTTP-01 challenge that needs to be fulfilled."""

    domain: str
    token: str
    key_authorization: str
    file_path: str = ""

    @property
    def well_known_path(self) -> str:
        """Return the well-known path for the challenge file."""
        return f"/.well-known/acme-challenge/{self.token}"


class DomainValidationResult(BaseModel):
    """Result of domain validation checks."""

    domain: str
    is_valid: bool = True
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    dns_resolved: bool = False
    ip_addresses: List[str] = Field(default_factory=list)
    has_wildcard: bool = False
    is_idna: bool = False


class DomainGroup(BaseModel):
    """A group of domains to be included in a single certificate."""

    primary_domain: str
    san_domains: List[str] = Field(default_factory=list)

    @property
    def all_domains(self) -> List[str]:
        """Return primary domain plus all SAN domains, deduplicated."""
        domains = [self.primary_domain]
        for d in self.san_domains:
            if d not in domains:
                domains.append(d)
        return domains

    @property
    def has_wildcard(self) -> bool:
        """Check if any domain in this group is a wildcard."""
        return any(d.startswith("*.") for d in self.all_domains)

    @property
    def display_name(self) -> str:
        """Return a human-readable name for this domain group."""
        if not self.san_domains:
            return self.primary_domain
        return f"{self.primary_domain} (+{len(self.san_domains)} SANs)"
