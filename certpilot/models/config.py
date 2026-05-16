"""Configuration data models for CertPilot with Pydantic validation."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class CAProvider(str, Enum):
    """Supported ACME Certificate Authority providers."""

    LETSENCRYPT = "letsencrypt"
    LETSENCRYPT_STAGING = "letsencrypt_staging"
    ZEROSSL = "zerossl"
    BUYPASS = "buypass"


class ChallengeType(str, Enum):
    """ACME challenge types."""

    HTTP_01 = "http-01"
    DNS_01 = "dns-01"


class DNSProviderType(str, Enum):
    """Supported DNS providers."""

    CLOUDFLARE = "cloudflare"
    ALIYUN = "aliyun"
    TENCENT = "tencent"
    MANUAL = "manual"


class DeployerType(str, Enum):
    """Supported deployment targets."""

    NGINX = "nginx"
    APACHE = "apache"
    FILE = "file"
    K8S = "k8s"


class NotifierType(str, Enum):
    """Supported notification channels."""

    EMAIL = "email"
    WEBHOOK = "webhook"
    CONSOLE = "console"


class CloudflareConfig(BaseModel):
    """Cloudflare DNS provider configuration."""

    api_token: str = ""
    api_email: str = ""
    zone_id: Optional[str] = None
    proxy: bool = False


class AliyunConfig(BaseModel):
    """Aliyun DNS provider configuration."""

    access_key_id: str = ""
    access_key_secret: str = ""
    region_id: str = "cn-hangzhou"


class TencentConfig(BaseModel):
    """Tencent Cloud DNS provider configuration."""

    secret_id: str = ""
    secret_key: str = ""
    region: str = "ap-guangzhou"


class DNSProviderConfig(BaseModel):
    """DNS provider configuration union."""

    provider: DNSProviderType = DNSProviderType.MANUAL
    cloudflare: Optional[CloudflareConfig] = None
    aliyun: Optional[AliyunConfig] = None
    tencent: Optional[TencentConfig] = None


class NginxDeployerConfig(BaseModel):
    """Nginx deployer configuration."""

    config_path: str = "/etc/nginx/nginx.conf"
    cert_path: str = "/etc/nginx/ssl/cert.pem"
    key_path: str = "/etc/nginx/ssl/key.pem"
    chain_path: str = "/etc/nginx/ssl/chain.pem"
    fullchain_path: str = "/etc/nginx/ssl/fullchain.pem"
    reload_command: str = "nginx -s reload"


class ApacheDeployerConfig(BaseModel):
    """Apache deployer configuration."""

    config_path: str = "/etc/apache2/apache2.conf"
    sites_available: str = "/etc/apache2/sites-available"
    sites_enabled: str = "/etc/apache2/sites-enabled"
    cert_path: str = "/etc/apache2/ssl/cert.pem"
    key_path: str = "/etc/apache2/ssl/key.pem"
    chain_path: str = "/etc/apache2/ssl/chain.pem"
    reload_command: str = "apache2ctl graceful"


class FileDeployerConfig(BaseModel):
    """File system deployer configuration."""

    output_dir: str = "./certs"
    cert_filename: str = "{domain}/cert.pem"
    key_filename: str = "{domain}/key.pem"
    chain_filename: str = "{domain}/chain.pem"
    fullchain_filename: str = "{domain}/fullchain.pem"
    permissions: int = 644
    key_permissions: int = 600


class K8sDeployerConfig(BaseModel):
    """Kubernetes deployer configuration."""

    secret_name: str = "tls-cert-{domain}"
    namespace: str = "default"
    kubeconfig: Optional[str] = None


class DeployerConfig(BaseModel):
    """Deployer configuration union."""

    deployer: DeployerType = DeployerType.FILE
    nginx: Optional[NginxDeployerConfig] = None
    apache: Optional[ApacheDeployerConfig] = None
    file: Optional[FileDeployerConfig] = FileDeployerConfig()
    k8s: Optional[K8sDeployerConfig] = None


class EmailNotifierConfig(BaseModel):
    """Email notifier configuration."""

    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_tls: bool = True
    smtp_username: str = ""
    smtp_password: str = ""
    from_address: str = ""
    to_addresses: List[str] = Field(default_factory=list)
    subject_template: str = "[CertPilot] {action} - {domain}"


class WebhookNotifierConfig(BaseModel):
    """Webhook notifier configuration."""

    url: str = ""
    method: str = "POST"
    headers: Dict[str, str] = Field(default_factory=dict)
    body_template: Optional[str] = None
    secret: Optional[str] = None


class NotifierConfig(BaseModel):
    """Notifier configuration union."""

    notifier: NotifierType = NotifierType.CONSOLE
    email: Optional[EmailNotifierConfig] = None
    webhook: Optional[WebhookNotifierConfig] = None


class DomainCertificateConfig(BaseModel):
    """Per-domain certificate configuration."""

    domain: str
    san_domains: List[str] = Field(default_factory=list)
    key_type: str = "rsa2048"
    ca: CAProvider = CAProvider.LETSENCRYPT
    challenge: ChallengeType = ChallengeType.DNS_01
    dns: Optional[DNSProviderConfig] = None
    deploy: Optional[DeployerConfig] = None
    notify: Optional[NotifierConfig] = None
    auto_renew: bool = True
    renew_days_before: int = 30
    enabled: bool = True


class GlobalConfig(BaseModel):
    """Global CertPilot configuration."""

    ca: CAProvider = CAProvider.LETSENCRYPT
    challenge: ChallengeType = ChallengeType.DNS_01
    key_type: str = "rsa2048"
    dns: Optional[DNSProviderConfig] = DNSProviderConfig()
    deploy: Optional[DeployerConfig] = DeployerConfig()
    notify: Optional[NotifierConfig] = NotifierConfig()
    auto_renew: bool = True
    renew_days_before: int = 30
    data_dir: str = "~/.certpilot"
    cert_dir: str = "~/.certpilot/certs"
    account_dir: str = "~/.certpilot/accounts"
    log_level: str = "INFO"
    schedule_enabled: bool = False
    schedule_hour: int = 3
    schedule_minute: int = 0
    notify_before_days: List[int] = Field(default_factory=lambda: [30, 14, 7, 1])


class CertPilotConfig(BaseModel):
    """Top-level CertPilot configuration."""

    version: str = "1.0"
    global_config: GlobalConfig = Field(default_factory=GlobalConfig)
    domains: List[DomainCertificateConfig] = Field(default_factory=list)

    @validator("domains", pre=True, always=True)
    def validate_domains(cls, v):
        """Ensure domains is always a list (YAML may parse empty value as None)."""
        if v is None:
            return []
        if not isinstance(v, list):
            return []
        return v

    @validator("domains")
    def validate_no_duplicate_domains(cls, v: List[DomainCertificateConfig]) -> List[DomainCertificateConfig]:
        """Ensure no duplicate domains in configuration."""
        seen = set()
        for domain_cfg in v:
            if domain_cfg.domain in seen:
                raise ValueError(f"Duplicate domain configuration: {domain_cfg.domain}")
            seen.add(domain_cfg.domain)
        return v
