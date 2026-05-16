"""Configuration file manager for CertPilot.

Handles reading, writing, and validating YAML configuration files.
"""

import logging
import os
from typing import Any, Dict, Optional

import yaml

from certpilot.models.config import (
    CertPilotConfig,
    GlobalConfig,
    DomainCertificateConfig,
)

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "~/.certpilot/config.yaml"
DEFAULT_CONFIG_CONTENT = """# CertPilot Configuration File
# certpilot --init

version: "1.0"

global_config:
  # Certificate Authority: letsencrypt, letsencrypt_staging, zerossl, buypass
  ca: letsencrypt
  # Challenge type: dns-01, http-01
  challenge: dns-01
  # Key type: rsa2048, rsa4096, ecdsa_p256, ecdsa_p384
  key_type: rsa2048
  # Auto-renewal settings
  auto_renew: true
  renew_days_before: 30
  # Data directories
  data_dir: ~/.certpilot
  cert_dir: ~/.certpilot/certs
  account_dir: ~/.certpilot/accounts
  # Logging
  log_level: INFO
  # Scheduler settings
  schedule_enabled: false
  schedule_hour: 3
  schedule_minute: 0
  # Notification thresholds (days before expiry)
  notify_before_days: [30, 14, 7, 1]

  # DNS Provider Configuration
  dns:
    provider: manual
    # Cloudflare example:
    # cloudflare:
    #   api_token: "your-api-token"
    #   zone_id: "your-zone-id"
    # Aliyun example:
    # aliyun:
    #   access_key_id: "your-access-key-id"
    #   access_key_secret: "your-access-key-secret"
    # Tencent Cloud example:
    # tencent:
    #   secret_id: "your-secret-id"
    #   secret_key: "your-secret-key"

  # Deployer Configuration
  deploy:
    deployer: file
    file:
      output_dir: ./certs
      cert_filename: "{domain}/cert.pem"
      key_filename: "{domain}/key.pem"
      chain_filename: "{domain}/chain.pem"
      fullchain_filename: "{domain}/fullchain.pem"
      permissions: 644
      key_permissions: 600
    # Nginx example:
    # nginx:
    #   config_path: /etc/nginx/nginx.conf
    #   cert_path: /etc/nginx/ssl/cert.pem
    #   key_path: /etc/nginx/ssl/key.pem
    #   reload_command: "nginx -s reload"

  # Notification Configuration
  notify:
    notifier: console
    # Email example:
    # email:
    #   smtp_host: smtp.gmail.com
    #   smtp_port: 587
    #   smtp_tls: true
    #   smtp_username: "your-email@gmail.com"
    #   smtp_password: "your-app-password"
    #   from_address: "your-email@gmail.com"
    #   to_addresses: ["admin@example.com"]
    # Webhook example:
    # webhook:
    #   url: "https://hooks.slack.com/services/..."
    #   platform: slack

# Per-domain certificate configurations
domains:
  # - domain: example.com
  #   san_domains:
  #     - www.example.com
  #   key_type: rsa2048
  #   ca: letsencrypt
  #   challenge: dns-01
  #   auto_renew: true
  #   renew_days_before: 30
  #   enabled: true
"""


class ConfigManager:
    """CertPilot configuration file manager.

    Manages reading, writing, and validating the YAML configuration file.
    Provides defaults and per-domain overrides.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the configuration manager.

        Args:
            config_path: Path to the configuration file.
                Defaults to ~/.certpilot/config.yaml.
        """
        self._config_path = os.path.expanduser(
            config_path or DEFAULT_CONFIG_PATH
        )
        self._config: Optional[CertPilotConfig] = None

    @property
    def config_path(self) -> str:
        """Return the absolute path to the configuration file."""
        return os.path.abspath(self._config_path)

    @property
    def config_dir(self) -> str:
        """Return the directory containing the configuration file."""
        return os.path.dirname(os.path.abspath(self._config_path))

    def load(self) -> CertPilotConfig:
        """Load and validate the configuration file.

        Returns:
            Validated CertPilotConfig object.

        Raises:
            FileNotFoundError: If the config file does not exist.
            ValueError: If the config is invalid.
        """
        if not os.path.exists(self._config_path):
            raise FileNotFoundError(
                f"Configuration file not found: {self._config_path}\n"
                f"Run 'certpilot config --init' to create a default configuration."
            )

        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse YAML configuration: {e}")
        except IOError as e:
            raise ValueError(f"Failed to read configuration file: {e}")

        if not isinstance(raw_data, dict):
            raise ValueError("Configuration file must contain a YAML mapping")

        try:
            self._config = CertPilotConfig(**raw_data)
            logger.info(f"Configuration loaded from {self._config_path}")
            return self._config
        except Exception as e:
            raise ValueError(f"Configuration validation failed: {e}")

    def save(self, config: Optional[CertPilotConfig] = None) -> None:
        """Save the configuration to file.

        Args:
            config: CertPilotConfig to save. Uses current config if None.
        """
        data = config or self._config
        if not data:
            raise ValueError("No configuration to save")

        # Ensure config directory exists
        os.makedirs(self.config_dir, exist_ok=True)

        # Convert to dict and serialize
        config_dict = data.dict()
        yaml_str = yaml.dump(
            config_dict,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )

        with open(self._config_path, "w", encoding="utf-8") as f:
            f.write(yaml_str)

        logger.info(f"Configuration saved to {self._config_path}")

    def init_default(self, force: bool = False) -> str:
        """Initialize a default configuration file.

        Args:
            force: Overwrite existing configuration if True.

        Returns:
            Path to the created configuration file.

        Raises:
            FileExistsError: If config exists and force is False.
        """
        if os.path.exists(self._config_path) and not force:
            raise FileExistsError(
                f"Configuration file already exists: {self._config_path}\n"
                f"Use --force to overwrite."
            )

        # Ensure directory exists
        os.makedirs(self.config_dir, exist_ok=True)

        with open(self._config_path, "w", encoding="utf-8") as f:
            f.write(DEFAULT_CONFIG_CONTENT)

        logger.info(f"Default configuration created at {self._config_path}")

        # Also create subdirectories
        for subdir in ["certs", "accounts"]:
            dir_path = os.path.join(self.config_dir, subdir)
            os.makedirs(dir_path, exist_ok=True)

        return self._config_path

    def get_domain_config(self, domain: str) -> Optional[DomainCertificateConfig]:
        """Get the configuration for a specific domain.

        Falls back to global defaults for any unset per-domain values.

        Args:
            domain: The domain name to look up.

        Returns:
            DomainCertificateConfig, or None if domain is not configured.
        """
        if not self._config:
            self.load()

        for domain_cfg in self._config.domains:
            if domain_cfg.domain == domain:
                return domain_cfg

        return None

    def get_all_domains(self) -> list:
        """Get all configured domains.

        Returns:
            List of domain configuration objects.
        """
        if not self._config:
            try:
                self.load()
            except (FileNotFoundError, ValueError):
                return []

        return [d for d in self._config.domains if d.enabled]

    def get_global(self) -> GlobalConfig:
        """Get the global configuration.

        Returns:
            GlobalConfig object.
        """
        if not self._config:
            self.load()
        return self._config.global_config

    def get_dns_config(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS provider configuration for a domain.

        Args:
            domain: Optional domain to get per-domain DNS config.

        Returns:
            DNS configuration dictionary.
        """
        if not self._config:
            self.load()

        # Check per-domain config first
        if domain:
            domain_cfg = self.get_domain_config(domain)
            if domain_cfg and domain_cfg.dns:
                return domain_cfg.dns.dict()

        # Fall back to global
        if self._config.global_config.dns:
            return self._config.global_config.dns.dict()

        return {"provider": "manual"}

    def get_deployer_config(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Get deployer configuration for a domain.

        Args:
            domain: Optional domain to get per-domain deployer config.

        Returns:
            Deployer configuration dictionary.
        """
        if not self._config:
            self.load()

        if domain:
            domain_cfg = self.get_domain_config(domain)
            if domain_cfg and domain_cfg.deploy:
                return domain_cfg.deploy.dict()

        if self._config.global_config.deploy:
            return self._config.global_config.deploy.dict()

        return {"deployer": "file"}

    def get_notifier_config(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Get notifier configuration for a domain.

        Args:
            domain: Optional domain to get per-domain notifier config.

        Returns:
            Notifier configuration dictionary.
        """
        if not self._config:
            self.load()

        if domain:
            domain_cfg = self.get_domain_config(domain)
            if domain_cfg and domain_cfg.notify:
                return domain_cfg.notify.dict()

        if self._config.global_config.notify:
            return self._config.global_config.notify.dict()

        return {"notifier": "console"}

    def add_domain(self, domain_config: DomainCertificateConfig) -> None:
        """Add or update a domain configuration.

        Args:
            domain_config: The domain configuration to add.
        """
        if not self._config:
            self.load()

        # Remove existing config for this domain
        self._config.domains = [
            d for d in self._config.domains if d.domain != domain_config.domain
        ]
        self._config.domains.append(domain_config)
        self.save()

    def remove_domain(self, domain: str) -> bool:
        """Remove a domain configuration.

        Args:
            domain: The domain to remove.

        Returns:
            True if the domain was found and removed.
        """
        if not self._config:
            self.load()

        original_len = len(self._config.domains)
        self._config.domains = [
            d for d in self._config.domains if d.domain != domain
        ]

        if len(self._config.domains) < original_len:
            self.save()
            return True
        return False

    def exists(self) -> bool:
        """Check if the configuration file exists.

        Returns:
            True if the config file exists.
        """
        return os.path.exists(self._config_path)
