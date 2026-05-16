"""Certificate manager for CertPilot.

Manages the complete certificate lifecycle including issuance,
renewal, revocation, import, and export.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from certpilot.core.acme_client import ACMEClient, ACMEError
from certpilot.core.cert_parser import CertificateParser
from certpilot.models.certificate import CertificateRecord, CertificateStatus
from certpilot.providers.base import BaseDNSProvider, get_dns_provider
from certpilot.utils.crypto import (
    create_csr,
    generate_private_key,
    save_certificate_to_file,
    save_private_key_to_file,
)

logger = logging.getLogger(__name__)


class CertificateManager:
    """Certificate lifecycle manager.

    Orchestrates the full certificate management workflow including
    ACME interaction, DNS challenge fulfillment, certificate deployment,
    and local record keeping.
    """

    def __init__(
        self,
        data_dir: Optional[str] = None,
        cert_dir: Optional[str] = None,
        account_dir: Optional[str] = None,
    ):
        """Initialize the certificate manager.

        Args:
            data_dir: Directory for storing certificate metadata.
            cert_dir: Directory for storing certificate files.
            account_dir: Directory for storing ACME account data.
        """
        self._data_dir = os.path.expanduser(data_dir or "~/.certpilot")
        self._cert_dir = os.path.expanduser(cert_dir or "~/.certpilot/certs")
        self._account_dir = os.path.expanduser(account_dir or "~/.certpilot/accounts")
        self._records_file = os.path.join(self._data_dir, "certificates.json")
        self._parser = CertificateParser()

        # Ensure directories exist
        for d in [self._data_dir, self._cert_dir, self._account_dir]:
            os.makedirs(d, exist_ok=True)

        # Load existing records
        self._records: Dict[str, CertificateRecord] = {}
        self._load_records()

    def _load_records(self) -> None:
        """Load certificate records from the local database file."""
        if os.path.exists(self._records_file):
            try:
                with open(self._records_file, "r") as f:
                    data = json.load(f)
                for record_data in data.get("certificates", []):
                    record = CertificateRecord(**record_data)
                    self._records[record.domain] = record
                logger.info(f"Loaded {len(self._records)} certificate records")
            except Exception as e:
                logger.error(f"Failed to load certificate records: {e}")
                self._records = {}

    def _save_records(self) -> None:
        """Save certificate records to the local database file."""
        try:
            data = {
                "version": "1.0",
                "certificates": [r.dict() for r in self._records.values()],
            }
            with open(self._records_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
            logger.debug("Certificate records saved")
        except Exception as e:
            logger.error(f"Failed to save certificate records: {e}")

    def get_record(self, domain: str) -> Optional[CertificateRecord]:
        """Get a certificate record by domain.

        Args:
            domain: The domain name.

        Returns:
            CertificateRecord or None if not found.
        """
        return self._records.get(domain)

    def list_records(self) -> List[CertificateRecord]:
        """List all managed certificate records.

        Returns:
            List of all CertificateRecord objects.
        """
        return list(self._records.values())

    def issue(
        self,
        domains: List[str],
        ca: str = "letsencrypt",
        dns_provider: str = "manual",
        dns_config: Optional[Dict[str, Any]] = None,
        key_type: str = "rsa2048",
        email: Optional[str] = None,
        challenge_type: str = "dns-01",
        deployer=None,
        notifier=None,
        staging: bool = False,
        auto_renew: bool = True,
        renew_days: int = 30,
    ) -> Optional[CertificateRecord]:
        """Issue a new certificate for the given domains.

        Args:
            domains: List of domain names (first is primary).
            ca: Certificate authority identifier.
            dns_provider: DNS provider for challenge verification.
            dns_config: DNS provider configuration.
            key_type: Private key type.
            email: Contact email for ACME account.
            challenge_type: ACME challenge type ('dns-01' or 'http-01').
            deployer: Deployer instance for certificate deployment.
            notifier: Notifier instance for notifications.
            staging: Use staging CA environment.
            auto_renew: Enable automatic renewal.
            renew_days: Days before expiry to trigger renewal.

        Returns:
            CertificateRecord if successful, None otherwise.
        """
        if not domains:
            logger.error("No domains specified")
            return None

        primary_domain = domains[0]

        # Create certificate record
        record = CertificateRecord(
            domain=primary_domain,
            san_domains=domains[1:],
            status=CertificateStatus.PENDING,
            key_type=key_type,
            ca_provider=ca,
            dns_provider=dns_provider,
            auto_renew=auto_renew,
            renew_days_before=renew_days,
        )
        self._records[primary_domain] = record
        self._save_records()

        try:
            # Step 1: Generate private key
            logger.info(f"Generating {key_type} private key for {primary_domain}")
            private_key = generate_private_key(key_type)

            # Step 2: Create CSR
            logger.info(f"Creating CSR for: {', '.join(domains)}")
            csr = create_csr(private_key, domains)
            csr_der = csr.public_bytes(
                __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
            )

            # Step 3: Initialize ACME client
            logger.info(f"Connecting to {ca}")
            acme = ACMEClient(
                ca=ca,
                account_dir=self._account_dir,
                email=email,
                staging=staging,
            )

            # Step 4: Register account
            acme.register(email)

            # Step 5: Create order
            order = acme.create_order(domains)

            # Step 6: Fulfill challenges
            if challenge_type == "dns-01":
                success = self._fulfill_dns_challenges(
                    acme, order, dns_provider, dns_config, domains
                )
            else:
                success = self._fulfill_http_challenges(acme, order, domains)

            if not success:
                record.status = CertificateStatus.ERROR
                record.error_message = "Challenge fulfillment failed"
                self._save_records()
                return None

            # Step 7: Finalize order
            cert_pem, order_url = acme.finalize_order(order["finalize"], csr_der)

            # Step 8: Save certificate files
            domain_dir = os.path.join(self._cert_dir, primary_domain)
            os.makedirs(domain_dir, exist_ok=True)

            cert_path = os.path.join(domain_dir, "cert.pem")
            key_path = os.path.join(domain_dir, "key.pem")
            fullchain_path = os.path.join(domain_dir, "fullchain.pem")

            save_certificate_to_file(cert_pem, cert_path)
            save_private_key_to_file(private_key, key_path)

            # Save fullchain (cert only for now, chain can be added)
            save_certificate_to_file(cert_pem, fullchain_path)

            # Step 9: Parse and validate certificate
            cert_info = self._parser.parse_pem(cert_pem)
            security_issues = self._parser.check_security(cert_info)

            if security_issues:
                logger.warning(f"Certificate security issues: {security_issues}")

            # Step 10: Update record
            record.status = CertificateStatus.ISSUED
            record.cert_path = cert_path
            record.key_path = key_path
            record.fullchain_path = fullchain_path
            record.issued_at = datetime.now()
            record.expires_at = cert_info.not_after
            record.order_url = order_url
            record.updated_at = datetime.now()
            self._save_records()

            # Step 11: Deploy certificate
            if deployer:
                try:
                    deployer.deploy(
                        domain=primary_domain,
                        cert_path=cert_path,
                        key_path=key_path,
                        fullchain_path=fullchain_path,
                    )
                    logger.info(f"Certificate deployed for {primary_domain}")
                except Exception as e:
                    logger.error(f"Deployment failed: {e}")

            # Step 12: Send notification
            if notifier:
                try:
                    from certpilot.notifiers.base import NotificationEvent
                    notifier.send(NotificationEvent(
                        event_type="issued",
                        domain=primary_domain,
                        message=f"Certificate issued for {primary_domain}, "
                                f"expires {cert_info.not_after.strftime('%Y-%m-%d')}",
                        details={
                            "domains": domains,
                            "expires_at": str(cert_info.not_after),
                            "days_to_expiry": cert_info.days_to_expiry,
                        },
                    ))
                except Exception as e:
                    logger.error(f"Notification failed: {e}")

            logger.info(f"Certificate issued successfully for {primary_domain}")
            return record

        except ACMEError as e:
            record.status = CertificateStatus.ERROR
            record.error_message = str(e)
            self._save_records()
            logger.error(f"ACME error during issuance: {e}")
            return None
        except Exception as e:
            record.status = CertificateStatus.ERROR
            record.error_message = str(e)
            self._save_records()
            logger.error(f"Certificate issuance failed: {e}")
            return None

    def _fulfill_dns_challenges(
        self,
        acme: ACMEClient,
        order: Dict[str, Any],
        provider_name: str,
        provider_config: Optional[Dict[str, Any]],
        domains: List[str],
    ) -> bool:
        """Fulfill DNS-01 challenges for all authorizations.

        Args:
            acme: The ACME client.
            order: The order dictionary.
            provider_name: DNS provider name.
            provider_config: DNS provider configuration.
            domains: List of domains.

        Returns:
            True if all challenges were fulfilled successfully.
        """
        provider = get_dns_provider(provider_name, provider_config)
        created_records: List[Tuple[str, str, str]] = []

        try:
            for auth_url in order.get("authorizations", []):
                auth = acme.get_authorization(auth_url)
                challenge = acme.get_dns_challenge(auth)

                if not challenge:
                    logger.error("No DNS-01 challenge found in authorization")
                    return False

                # Get the identifier (domain) for this authorization
                identifier = auth.get("identifier", {}).get("value", "")
                token = challenge.get("token", "")

                # Compute the challenge value
                challenge_value = ACMEClient.compute_dns_challenge_value(
                    token, acme._account_key_jwk
                )

                # Create the DNS record
                record_name = f"_acme-challenge.{identifier}"
                provider.create_txt_record(identifier, record_name, challenge_value)
                created_records.append((identifier, record_name, challenge_value))

                # Request challenge validation
                acme.request_challenge(challenge["url"])

            # Wait for all authorizations to be valid
            for auth_url in order.get("authorizations", []):
                acme.poll_authorization(auth_url)

            return True

        except Exception as e:
            logger.error(f"DNS challenge fulfillment failed: {e}")
            # Clean up created DNS records
            for domain, record_name, record_value in created_records:
                try:
                    provider.delete_txt_record(domain, record_name, record_value)
                except Exception:
                    pass
            return False
        finally:
            # Clean up DNS records after successful validation
            for domain, record_name, record_value in created_records:
                try:
                    provider.delete_txt_record(domain, record_name, record_value)
                except Exception as cleanup_err:
                    logger.warning(f"Failed to clean up DNS record: {cleanup_err}")

    def _fulfill_http_challenges(
        self,
        acme: ACMEClient,
        order: Dict[str, Any],
        domains: List[str],
    ) -> bool:
        """Fulfill HTTP-01 challenges for all authorizations.

        Note: HTTP-01 challenge requires a running web server on port 80.
        This is a simplified implementation that creates the challenge files.

        Args:
            acme: The ACME client.
            order: The order dictionary.
            domains: List of domains.

        Returns:
            True if all challenges were fulfilled successfully.
        """
        challenge_dir = os.path.join(self._data_dir, "challenges")
        os.makedirs(challenge_dir, exist_ok=True)

        try:
            for auth_url in order.get("authorizations", []):
                auth = acme.get_authorization(auth_url)
                challenge = acme.get_http_challenge(auth)

                if not challenge:
                    logger.error("No HTTP-01 challenge found in authorization")
                    return False

                identifier = auth.get("identifier", {}).get("value", "")
                token = challenge.get("token", "")

                # Compute key authorization
                key_auth = ACMEClient.compute_http_challenge_value(
                    token, acme._account_key_jwk
                )

                # Write challenge file
                challenge_file = os.path.join(challenge_dir, token)
                with open(challenge_file, "w") as f:
                    f.write(key_auth)

                logger.info(
                    f"HTTP-01 challenge file created: {challenge_file}\n"
                    f"Ensure your web server serves this file at:\n"
                    f"http://{identifier}/.well-known/acme-challenge/{token}"
                )

                # Request challenge validation
                acme.request_challenge(challenge["url"])

            # Wait for all authorizations
            for auth_url in order.get("authorizations", []):
                acme.poll_authorization(auth_url)

            return True

        except Exception as e:
            logger.error(f"HTTP challenge fulfillment failed: {e}")
            return False
        finally:
            # Clean up challenge files
            try:
                import shutil
                if os.path.exists(challenge_dir):
                    shutil.rmtree(challenge_dir)
            except Exception:
                pass

    def renew(
        self,
        domain: str,
        deployer=None,
        notifier=None,
        staging: bool = False,
    ) -> Optional[CertificateRecord]:
        """Renew a certificate.

        Args:
            domain: The domain to renew.
            deployer: Optional deployer for certificate deployment.
            notifier: Optional notifier for notifications.
            staging: Use staging CA environment.

        Returns:
            Renewed CertificateRecord, or None if renewal failed.
        """
        record = self.get_record(domain)
        if not record:
            logger.error(f"No certificate record found for {domain}")
            return None

        if record.status == CertificateStatus.REVOKED:
            logger.error(f"Cannot renew revoked certificate for {domain}")
            return None

        # Build DNS config from record
        dns_config = {}
        if record.dns_provider:
            dns_config = {"provider": record.dns_provider}

        # Collect all domains
        all_domains = record.all_domains

        logger.info(f"Renewing certificate for {domain}")

        # Mark as renewing
        record.status = CertificateStatus.RENEWING
        record.updated_at = datetime.now()
        self._save_records()

        # Re-issue the certificate
        new_record = self.issue(
            domains=all_domains,
            ca=record.ca_provider,
            dns_provider=record.dns_provider,
            dns_config=dns_config,
            key_type=record.key_type,
            challenge_type="dns-01",
            deployer=deployer,
            notifier=notifier,
            staging=staging,
            auto_renew=record.auto_renew,
            renew_days=record.renew_days_before,
        )

        if new_record:
            # Send renewal notification
            if notifier:
                try:
                    from certpilot.notifiers.base import NotificationEvent
                    notifier.send(NotificationEvent(
                        event_type="renewed",
                        domain=domain,
                        message=f"Certificate renewed for {domain}",
                        details={
                            "expires_at": str(new_record.expires_at),
                        },
                    ))
                except Exception:
                    pass

        return new_record

    def revoke(
        self,
        domain: str,
        notifier=None,
    ) -> bool:
        """Revoke a certificate.

        Args:
            domain: The domain whose certificate should be revoked.
            notifier: Optional notifier for notifications.

        Returns:
            True if revocation was successful.
        """
        record = self.get_record(domain)
        if not record:
            logger.error(f"No certificate record found for {domain}")
            return False

        if not record.cert_path or not os.path.exists(record.cert_path):
            logger.error(f"Certificate file not found: {record.cert_path}")
            return False

        try:
            with open(record.cert_path, "rb") as f:
                cert_pem = f.read()

            acme = ACMEClient(
                ca=record.ca_provider,
                account_dir=self._account_dir,
            )

            success = acme.revoke_certificate(cert_pem)

            if success:
                record.status = CertificateStatus.REVOKED
                record.revoked_at = datetime.now()
                record.updated_at = datetime.now()
                self._save_records()

                if notifier:
                    try:
                        from certpilot.notifiers.base import NotificationEvent
                        notifier.send(NotificationEvent(
                            event_type="revoked",
                            domain=domain,
                            message=f"Certificate revoked for {domain}",
                        ))
                    except Exception:
                        pass

                logger.info(f"Certificate revoked for {domain}")
                return True
            else:
                return False

        except Exception as e:
            logger.error(f"Failed to revoke certificate for {domain}: {e}")
            return False

    def import_certificate(
        self,
        domain: str,
        cert_path: str,
        key_path: str,
        chain_path: Optional[str] = None,
        auto_renew: bool = False,
    ) -> Optional[CertificateRecord]:
        """Import an existing certificate.

        Args:
            domain: The primary domain.
            cert_path: Path to the certificate file.
            key_path: Path to the private key file.
            chain_path: Path to the certificate chain file.
            auto_renew: Whether to enable auto-renewal.

        Returns:
            Imported CertificateRecord, or None if import failed.
        """
        try:
            # Parse the certificate
            with open(cert_path, "rb") as f:
                cert_pem = f.read()

            cert_info = self._parser.parse_pem(cert_pem)

            # Copy files to cert directory
            domain_dir = os.path.join(self._cert_dir, domain)
            os.makedirs(domain_dir, exist_ok=True)

            import shutil
            new_cert_path = os.path.join(domain_dir, "cert.pem")
            new_key_path = os.path.join(domain_dir, "key.pem")

            shutil.copy2(cert_path, new_cert_path)
            shutil.copy2(key_path, new_key_path)
            os.chmod(new_key_path, 0o600)

            new_chain_path = None
            if chain_path and os.path.exists(chain_path):
                new_chain_path = os.path.join(domain_dir, "chain.pem")
                shutil.copy2(chain_path, new_chain_path)

            # Create record
            record = CertificateRecord(
                domain=domain,
                san_domains=[d for d in cert_info.subject_alt_names if d != domain],
                status=CertificateStatus.ISSUED if not cert_info.is_expired else CertificateStatus.EXPIRED,
                cert_path=new_cert_path,
                key_path=new_key_path,
                chain_path=new_chain_path,
                issued_at=cert_info.not_before,
                expires_at=cert_info.not_after,
                auto_renew=auto_renew,
            )

            self._records[domain] = record
            self._save_records()

            logger.info(f"Certificate imported for {domain}")
            return record

        except Exception as e:
            logger.error(f"Failed to import certificate: {e}")
            return None

    def export_certificate(
        self,
        domain: str,
        output_format: str = "pem",
        output_path: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Optional[str]:
        """Export a certificate in the specified format.

        Args:
            domain: The domain to export.
            output_format: Export format ('pem', 'pfx', 'jks').
            output_path: Output file path (auto-generated if None).
            password: Password for encrypted formats (PFX).

        Returns:
            Path to the exported file, or None if export failed.
        """
        record = self.get_record(domain)
        if not record:
            logger.error(f"No certificate record found for {domain}")
            return None

        if not record.cert_path or not os.path.exists(record.cert_path):
            logger.error(f"Certificate file not found for {domain}")
            return None

        try:
            if output_format == "pem":
                return self._export_pem(record, output_path)
            elif output_format == "pfx" or output_format == "pkcs12":
                return self._export_pfx(record, output_path, password)
            elif output_format == "jks":
                logger.error("JKS export requires Java keytool. Use PFX format instead.")
                return None
            else:
                logger.error(f"Unsupported export format: {output_format}")
                return None

        except Exception as e:
            logger.error(f"Failed to export certificate: {e}")
            return None

    def _export_pem(self, record: CertificateRecord, output_path: Optional[str]) -> Optional[str]:
        """Export certificate as PEM.

        Args:
            record: The certificate record.
            output_path: Output file path.

        Returns:
            Path to the exported file.
        """
        if not output_path:
            output_path = os.path.join(
                os.getcwd(),
                f"{record.domain}_certificate.pem",
            )

        with open(record.cert_path, "rb") as f:
            cert_data = f.read()

        with open(output_path, "wb") as f:
            f.write(cert_data)

        logger.info(f"Certificate exported to {output_path}")
        return output_path

    def _export_pfx(
        self,
        record: CertificateRecord,
        output_path: Optional[str],
        password: Optional[str],
    ) -> Optional[str]:
        """Export certificate as PKCS12/PFX.

        Args:
            record: The certificate record.
            output_path: Output file path.
            password: Password for the PFX file.

        Returns:
            Path to the exported file.
        """
        if not output_path:
            output_path = os.path.join(
                os.getcwd(),
                f"{record.domain}_certificate.pfx",
            )

        if not password:
            logger.warning("No password provided for PFX export. Using empty password.")

        from cryptography.hazmat.primitives.serialization import pkcs12
        from certpilot.utils.crypto import load_private_key

        # Load certificate and key
        with open(record.cert_path, "rb") as f:
            cert_data = f.read()
        cert = __import__("cryptography.x509", fromlist=["load_pem_x509_certificate"]).load_pem_x509_certificate(cert_data)

        with open(record.key_path, "rb") as f:
            key_data = f.read()
        key = load_private_key(key_data)

        # Build CA certificates list
        ca_certs = []
        if record.chain_path and os.path.exists(record.chain_path):
            from certpilot.core.cert_parser import CertificateParser
            parser = CertificateParser()
            chain = parser.parse_chain(
                open(record.chain_path, "rb").read()
            )
            for intermediate in chain.intermediates:
                ca_certs.append(
                    __import__("cryptography.x509", fromlist=["load_pem_x509_certificate"]).load_pem_x509_certificate(
                        open(intermediate, "rb").read() if isinstance(intermediate, str) else intermediate
                    )
                )

        pfx_data = pkcs12.serialize_key_and_certificates(
            name=record.domain.encode("utf-8"),
            key=key,
            cert=cert,
            cas=ca_certs,
            encryption_algorithm=(
                pkcs12.BestAvailableEncryption(password.encode("utf-8"))
                if password
                else pkcs12.NoEncryption()
            ),
        )

        with open(output_path, "wb") as f:
            f.write(pfx_data)

        logger.info(f"Certificate exported as PFX to {output_path}")
        return output_path

    def check_renewals(self) -> List[CertificateRecord]:
        """Check all certificates and return those that need renewal.

        Returns:
            List of CertificateRecord objects that need renewal.
        """
        needs_renewal = []
        for record in self._records.values():
            if record.needs_renewal and record.status not in (
                CertificateStatus.REVOKED,
                CertificateStatus.PENDING,
            ):
                needs_renewal.append(record)
        return needs_renewal

    def get_status(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get detailed status of a certificate.

        Args:
            domain: The domain to check.

        Returns:
            Dictionary with certificate status information, or None.
        """
        record = self.get_record(domain)
        if not record:
            return None

        status = {
            "domain": record.domain,
            "san_domains": record.san_domains,
            "status": record.status.value,
            "ca": record.ca_provider,
            "dns_provider": record.dns_provider,
            "auto_renew": record.auto_renew,
            "issued_at": str(record.issued_at) if record.issued_at else None,
            "expires_at": str(record.expires_at) if record.expires_at else None,
            "renewed_at": str(record.renewed_at) if record.renewed_at else None,
            "cert_path": record.cert_path,
            "key_path": record.key_path,
            "error": record.error_message,
        }

        # Parse certificate for detailed info
        if record.cert_path and os.path.exists(record.cert_path):
            try:
                cert_info = self._parser.parse_file(record.cert_path)
                status["days_to_expiry"] = cert_info.days_to_expiry
                status["is_expired"] = cert_info.is_expired
                status["issuer"] = cert_info.issuer_cn
                status["serial"] = cert_info.serial_number
                status["fingerprint_sha256"] = cert_info.fingerprint_sha256
                status["signature_algorithm"] = cert_info.signature_algorithm
                status["security_issues"] = self._parser.check_security(cert_info)
            except Exception as e:
                status["parse_error"] = str(e)

        return status
