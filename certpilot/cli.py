"""CertPilot CLI - Main entry point.

Provides the command-line interface for certificate management
using the Click framework with Rich output formatting.
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import Optional

import click
from rich.console import Console

from certpilot import __version__

console = Console()

# Configure logging
def setup_logging(level: str = "INFO") -> None:
    """Configure the logging framework.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
    """
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Suppress noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)


def get_cert_manager(config_path: Optional[str] = None):
    """Create a CertificateManager instance from config.

    Args:
        config_path: Optional path to config file.

    Returns:
        Tuple of (CertificateManager, ConfigManager).
    """
    from certpilot.config.manager import ConfigManager
    from certpilot.core.cert_manager import CertificateManager

    config_mgr = ConfigManager(config_path)

    data_dir = None
    cert_dir = None
    account_dir = None

    try:
        if config_mgr.exists():
            cfg = config_mgr.load()
            gc = cfg.global_config
            data_dir = gc.data_dir
            cert_dir = gc.cert_dir
            account_dir = gc.account_dir
    except Exception:
        pass

    mgr = CertificateManager(
        data_dir=data_dir,
        cert_dir=cert_dir,
        account_dir=account_dir,
    )
    return mgr, config_mgr


@click.group()
@click.version_option(version=__version__, prog_name="certpilot")
@click.option("--config", "-c", "config_path", default=None,
              help="Path to configuration file.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable verbose output.")
@click.option("--debug", is_flag=True, default=False,
              help="Enable debug logging.")
@click.pass_context
def cli(ctx, config_path, verbose, debug):
    """CertPilot - Lightweight SSL Certificate Intelligent Management Engine.

    A fully self-developed CLI tool for managing SSL/TLS certificates
    with support for multiple ACME providers, DNS providers, and
    deployment targets.
    """
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["verbose"] = verbose

    log_level = "DEBUG" if debug else ("DEBUG" if verbose else "INFO")
    setup_logging(log_level)


@cli.command()
@click.option("--domain", "-d", required=True, help="Primary domain name.")
@click.option("--san", multiple=True, default=[], help="SAN domains.")
@click.option("--dns", "dns_provider", default="manual",
              help="DNS provider (cloudflare, aliyun, tencent, manual).")
@click.option("--ca", default="letsencrypt",
              help="Certificate authority (letsencrypt, zerossl, buypass).")
@click.option("--key-type", default="rsa2048",
              help="Key type (rsa2048, rsa4096, ecdsa_p256, ecdsa_p384).")
@click.option("--email", default=None, help="ACME account email.")
@click.option("--staging", is_flag=True, default=False,
              help="Use staging CA environment.")
@click.option("--challenge", "challenge_type", default="dns-01",
              help="Challenge type (dns-01, http-01).")
@click.pass_context
def issue(ctx, domain, san, dns_provider, ca, key_type, email, staging, challenge_type):
    """Issue a new SSL certificate."""
    from certpilot.utils.output import (
        print_banner, print_error, print_step, print_success,
    )

    print_banner()

    # Validate domain
    from certpilot.utils.validation import validate_domain
    is_valid, error = validate_domain(domain)
    if not is_valid:
        print_error(f"Invalid domain: {error}")
        sys.exit(1)

    # Validate SAN domains
    all_domains = [domain] + list(san)
    if san:
        from certpilot.utils.validation import validate_domains
        all_valid, errors = validate_domains(all_domains)
        if not all_valid:
            for err in errors:
                print_error(err)
            sys.exit(1)

    # Validate key type
    from certpilot.utils.validation import validate_key_type
    is_valid, error = validate_key_type(key_type)
    if not is_valid:
        print_error(error)
        sys.exit(1)

    total_steps = 7
    print_step(1, total_steps, f"Generating {key_type} private key")
    print_step(2, total_steps, f"Creating CSR for {', '.join(all_domains)}")
    print_step(3, total_steps, f"Connecting to {ca}")
    print_step(4, total_steps, "Registering ACME account")
    print_step(5, total_steps, f"Creating certificate order")
    print_step(6, total_steps, f"Fulfilling {challenge_type} challenges")
    print_step(7, total_steps, "Downloading and saving certificate")
    console.print()

    mgr, config_mgr = get_cert_manager(ctx.obj["config_path"])

    # Get deployer and notifier from config
    deployer = None
    notifier = None
    try:
        if config_mgr.exists():
            cfg = config_mgr.load()
            deploy_cfg = config_mgr.get_deployer_config(domain)
            notify_cfg = config_mgr.get_notifier_config(domain)

            from certpilot.deployers.base import get_deployer
            from certpilot.notifiers.base import get_notifier
            deployer = get_deployer(deploy_cfg.get("deployer", "file"), deploy_cfg)
            notifier = get_notifier(notify_cfg.get("notifier", "console"), notify_cfg)
    except Exception:
        pass

    # Get DNS config
    dns_config = {}
    try:
        if config_mgr.exists():
            dns_config = config_mgr.get_dns_config(domain)
            # Override with CLI options
            dns_config["provider"] = dns_provider
    except Exception:
        dns_config = {"provider": dns_provider}

    record = mgr.issue(
        domains=all_domains,
        ca=ca,
        dns_provider=dns_provider,
        dns_config=dns_config,
        key_type=key_type,
        email=email,
        challenge_type=challenge_type,
        deployer=deployer,
        notifier=notifier,
        staging=staging,
    )

    if record:
        print_success(
            f"Certificate issued successfully for {domain}! "
            f"Expires: {record.expires_at.strftime('%Y-%m-%d') if record.expires_at else 'N/A'}"
        )
    else:
        print_error("Certificate issuance failed. Check logs for details.")
        sys.exit(1)


@cli.command()
@click.option("--domain", "-d", required=True, help="Domain to renew.")
@click.option("--staging", is_flag=True, default=False,
              help="Use staging CA environment.")
@click.pass_context
def renew(ctx, domain, staging):
    """Renew an SSL certificate."""
    from certpilot.utils.output import print_error, print_success

    mgr, config_mgr = get_cert_manager(ctx.obj["config_path"])

    deployer = None
    notifier = None
    try:
        if config_mgr.exists():
            deploy_cfg = config_mgr.get_deployer_config(domain)
            notify_cfg = config_mgr.get_notifier_config(domain)
            from certpilot.deployers.base import get_deployer
            from certpilot.notifiers.base import get_notifier
            deployer = get_deployer(deploy_cfg.get("deployer", "file"), deploy_cfg)
            notifier = get_notifier(notify_cfg.get("notifier", "console"), notify_cfg)
    except Exception:
        pass

    record = mgr.renew(
        domain=domain,
        deployer=deployer,
        notifier=notifier,
        staging=staging,
    )

    if record:
        print_success(
            f"Certificate renewed for {domain}. "
            f"New expiry: {record.expires_at.strftime('%Y-%m-%d') if record.expires_at else 'N/A'}"
        )
    else:
        print_error(f"Certificate renewal failed for {domain}")
        sys.exit(1)


@cli.command()
@click.option("--domain", "-d", required=True, help="Domain to revoke.")
@click.pass_context
def revoke(ctx, domain):
    """Revoke an SSL certificate."""
    from certpilot.utils.output import print_error, print_success

    mgr, config_mgr = get_cert_manager(ctx.obj["config_path"])

    notifier = None
    try:
        if config_mgr.exists():
            notify_cfg = config_mgr.get_notifier_config(domain)
            from certpilot.notifiers.base import get_notifier
            notifier = get_notifier(notify_cfg.get("notifier", "console"), notify_cfg)
    except Exception:
        pass

    success = mgr.revoke(domain=domain, notifier=notifier)

    if success:
        print_success(f"Certificate revoked for {domain}")
    else:
        print_error(f"Failed to revoke certificate for {domain}")
        sys.exit(1)


@cli.command(name="list")
@click.pass_context
def list_certs(ctx):
    """List all managed certificates."""
    from certpilot.utils.output import print_certificate_table, print_info

    mgr, _ = get_cert_manager(ctx.obj["config_path"])
    records = mgr.list_records()

    if not records:
        print_info("No managed certificates found.")
        return

    table_data = []
    for record in records:
        days_left = "N/A"
        if record.expires_at:
            delta = (record.expires_at - datetime.now()).days
            days_left = max(0, delta)

        table_data.append({
            "domain": record.domain,
            "status": record.status.value,
            "expires_at": record.expires_at,
            "days_left": days_left,
            "ca": record.ca_provider,
            "auto_renew": record.auto_renew,
        })

    print_certificate_table(table_data)


@cli.command()
@click.option("--domain", "-d", required=True, help="Domain to check.")
@click.pass_context
def status(ctx, domain):
    """Check detailed certificate status."""
    from certpilot.utils.output import print_certificate_detail, print_error

    mgr, _ = get_cert_manager(ctx.obj["config_path"])
    cert_status = mgr.get_status(domain)

    if not cert_status:
        print_error(f"No certificate found for {domain}")
        sys.exit(1)

    # Format for display
    display_info = {
        "Domain": cert_status.get("domain", "N/A"),
        "Status": cert_status.get("status", "N/A"),
        "CA": cert_status.get("ca", "N/A"),
        "DNS Provider": cert_status.get("dns_provider", "N/A"),
        "Auto-Renew": str(cert_status.get("auto_renew", False)),
        "Issued At": cert_status.get("issued_at", "N/A"),
        "Expires At": cert_status.get("expires_at", "N/A"),
        "Days to Expiry": str(cert_status.get("days_to_expiry", "N/A")),
        "Expired": str(cert_status.get("is_expired", False)),
        "Issuer": cert_status.get("issuer", "N/A"),
        "Serial": cert_status.get("serial", "N/A"),
        "Signature Algorithm": cert_status.get("signature_algorithm", "N/A"),
        "SHA-256 Fingerprint": cert_status.get("fingerprint_sha256", "N/A"),
        "Certificate Path": cert_status.get("cert_path", "N/A"),
        "Key Path": cert_status.get("key_path", "N/A"),
    }

    security_issues = cert_status.get("security_issues", [])
    if security_issues:
        display_info["Security Issues"] = "\n".join(f"  - {issue}" for issue in security_issues)

    if cert_status.get("error"):
        display_info["Error"] = cert_status["error"]

    print_certificate_detail(display_info)


@cli.command()
@click.option("--domain", "-d", required=True, help="Domain to check.")
@click.option("--ci", is_flag=True, default=False,
              help="CI mode: output JSON for machine parsing.")
@click.pass_context
def check(ctx, domain, ci):
    """Check domain certificate status (CI-friendly)."""
    from certpilot.utils.output import print_error, print_json_output

    mgr, _ = get_cert_manager(ctx.obj["config_path"])
    cert_status = mgr.get_status(domain)

    if not cert_status:
        if ci:
            print_json_output({"domain": domain, "status": "not_found", "healthy": False})
        else:
            print_error(f"No certificate found for {domain}")
        sys.exit(1)

    # Determine health
    is_healthy = (
        cert_status.get("status") == "issued"
        and not cert_status.get("is_expired", True)
        and cert_status.get("days_to_expiry", 0) > 0
    )

    if ci:
        output = {
            "domain": domain,
            "status": cert_status.get("status"),
            "healthy": is_healthy,
            "days_to_expiry": cert_status.get("days_to_expiry"),
            "is_expired": cert_status.get("is_expired", False),
            "expires_at": cert_status.get("expires_at"),
            "issuer": cert_status.get("issuer"),
        }
        security_issues = cert_status.get("security_issues", [])
        if security_issues:
            output["security_issues"] = security_issues
        print_json_output(output)
    else:
        if is_healthy:
            from certpilot.utils.output import print_success
            print_success(
                f"{domain}: Certificate is valid, "
                f"expires in {cert_status.get('days_to_expiry', 'N/A')} days"
            )
        else:
            from certpilot.utils.output import print_warning
            print_warning(
                f"{domain}: Certificate needs attention "
                f"(status: {cert_status.get('status')}, "
                f"days left: {cert_status.get('days_to_expiry', 'N/A')})"
            )
            sys.exit(1)


@cli.command()
@click.pass_context
def sync(ctx):
    """Sync all certificates from configuration file."""
    from certpilot.utils.output import print_error, print_info, print_success, print_summary

    config_path = ctx.obj["config_path"]
    from certpilot.config.manager import ConfigManager
    config_mgr = ConfigManager(config_path)

    if not config_mgr.exists():
        print_error("Configuration file not found. Run 'certpilot config --init' first.")
        sys.exit(1)

    try:
        cfg = config_mgr.load()
    except Exception as e:
        print_error(f"Failed to load configuration: {e}")
        sys.exit(1)

    domains = config_mgr.get_all_domains()
    if not domains:
        print_info("No domains configured in config file.")
        return

    print_info(f"Syncing {len(domains)} domain(s) from configuration...")

    mgr, _ = get_cert_manager(config_path)
    success_count = 0
    error_count = 0

    for domain_cfg in domains:
        domain = domain_cfg.domain
        print_info(f"Processing {domain}...")

        # Check if certificate exists and needs renewal
        record = mgr.get_record(domain)
        if record and record.status == "issued" and not record.needs_renewal:
            print_info(f"  Skipping {domain} (certificate valid, {record.days_to_expiry} days to expiry)")
            success_count += 1
            continue

        # Get domain-specific config
        dns_config = config_mgr.get_dns_config(domain)
        deploy_config = config_mgr.get_deployer_config(domain)
        notify_config = config_mgr.get_notifier_config(domain)

        deployer = None
        notifier = None
        try:
            from certpilot.deployers.base import get_deployer
            from certpilot.notifiers.base import get_notifier
            deployer = get_deployer(deploy_config.get("deployer", "file"), deploy_config)
            notifier = get_notifier(notify_config.get("notifier", "console"), notify_config)
        except Exception:
            pass

        all_domains = [domain] + list(domain_cfg.san_domains)

        new_record = mgr.issue(
            domains=all_domains,
            ca=domain_cfg.ca.value,
            dns_provider=dns_config.get("provider", "manual"),
            dns_config=dns_config,
            key_type=domain_cfg.key_type,
            challenge_type=domain_cfg.challenge.value,
            deployer=deployer,
            notifier=notifier,
        )

        if new_record:
            print_success(f"  {domain}: Certificate issued/renewed")
            success_count += 1
        else:
            print_error(f"  {domain}: Failed")
            error_count += 1

    print_summary(success_count, error_count)


@cli.command()
@click.option("--test", "test_mode", is_flag=True, default=False,
              help="Send a test notification.")
@click.pass_context
def notify(ctx, test_mode):
    """Test notification channels."""
    from certpilot.utils.output import print_error, print_success

    config_path = ctx.obj["config_path"]
    from certpilot.config.manager import ConfigManager
    config_mgr = ConfigManager(config_path)

    if not config_mgr.exists():
        print_error("Configuration file not found. Run 'certpilot config --init' first.")
        sys.exit(1)

    try:
        notify_cfg = config_mgr.get_notifier_config()
    except Exception as e:
        print_error(f"Failed to load notification config: {e}")
        sys.exit(1)

    notifier_type = notify_cfg.get("notifier", "console")

    try:
        from certpilot.notifiers.base import get_notifier
        notifier = get_notifier(notifier_type, notify_cfg)

        if test_mode:
            success = notifier.send_test()
        else:
            from certpilot.notifiers.base import NotificationEvent
            success = notifier.send(NotificationEvent(
                event_type="test",
                domain="certpilot-test",
                message="Manual notification from CertPilot.",
            ))

        if success:
            print_success(f"Notification sent via {notifier_type}")
        else:
            print_error(f"Failed to send notification via {notifier_type}")
            sys.exit(1)

    except Exception as e:
        print_error(f"Notification error: {e}")
        sys.exit(1)


@cli.command()
@click.option("--init", "init_config", is_flag=True, default=False,
              help="Initialize default configuration file.")
@click.option("--force", is_flag=True, default=False,
              help="Overwrite existing configuration.")
@click.pass_context
def config(ctx, init_config, force):
    """Initialize or manage configuration file."""
    from certpilot.utils.output import print_error, print_info, print_success

    config_path = ctx.obj["config_path"]
    from certpilot.config.manager import ConfigManager
    config_mgr = ConfigManager(config_path)

    if init_config:
        try:
            path = config_mgr.init_default(force=force)
            print_success(f"Configuration file created: {path}")
            print_info("Edit the configuration file to set up your DNS provider, deployer, and notifications.")
        except FileExistsError as e:
            print_error(str(e))
            sys.exit(1)
    else:
        # Show current config location
        if config_mgr.exists():
            print_info(f"Configuration file: {config_mgr.config_path}")
            try:
                cfg = config_mgr.load()
                gc = cfg.global_config
                print_info(f"  CA: {gc.ca.value}")
                print_info(f"  Challenge: {gc.challenge.value}")
                print_info(f"  Key Type: {gc.key_type}")
                print_info(f"  Auto-Renew: {gc.auto_renew}")
                print_info(f"  Configured Domains: {len(cfg.domains)}")
            except Exception as e:
                print_error(f"Failed to read config: {e}")
        else:
            print_info("No configuration file found. Run 'certpilot config --init' to create one.")


@cli.command()
@click.option("--start", "start_scheduler", is_flag=True, default=False,
              help="Start the auto-renewal scheduler.")
@click.option("--stop", "stop_scheduler", is_flag=True, default=False,
              help="Stop the auto-renewal scheduler.")
@click.option("--status", "check_status", is_flag=True, default=False,
              help="Check scheduler status.")
@click.pass_context
def schedule(ctx, start_scheduler, stop_scheduler, check_status):
    """Manage the auto-renewal scheduler daemon."""
    from certpilot.utils.output import print_error, print_info, print_success

    if not any([start_scheduler, stop_scheduler, check_status]):
        print_info("Use --start, --stop, or --status to manage the scheduler.")
        return

    config_path = ctx.obj["config_path"]
    from certpilot.config.manager import ConfigManager
    config_mgr = ConfigManager(config_path)

    # Load config for scheduler settings
    check_hour = 3
    check_minute = 0
    notify_days = [30, 14, 7, 1]

    try:
        if config_mgr.exists():
            cfg = config_mgr.load()
            gc = cfg.global_config
            check_hour = gc.schedule_hour
            check_minute = gc.schedule_minute
            notify_days = gc.notify_before_days
    except Exception:
        pass

    mgr, _ = get_cert_manager(config_path)

    from certpilot.core.scheduler import CertPilotScheduler
    scheduler = CertPilotScheduler(
        cert_manager=mgr,
        check_hour=check_hour,
        check_minute=check_minute,
        notify_days=notify_days,
    )

    if start_scheduler:
        if scheduler.start():
            print_success(
                f"Scheduler started. Daily check at {check_hour:02d}:{check_minute:02d}"
            )
            print_info("Press Ctrl+C to stop.")
            try:
                import time
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                scheduler.stop()
                print_info("Scheduler stopped.")
        else:
            print_error("Failed to start scheduler")
            sys.exit(1)

    elif stop_scheduler:
        if scheduler.stop():
            print_success("Scheduler stopped")
        else:
            print_error("Scheduler is not running")
            sys.exit(1)

    elif check_status:
        status = scheduler.get_status()
        if status["running"]:
            print_success("Scheduler is running")
        else:
            print_info("Scheduler is not running")
        print_info(f"  Check time: {status['check_hour']:02d}:{status['check_minute']:02d}")
        print_info(f"  Notify days before expiry: {status['notify_days']}")
        for job in status.get("jobs", []):
            print_info(f"  Job '{job['name']}': next run at {job.get('next_run', 'N/A')}")


@cli.command()
@click.option("--path", "-p", required=True, type=click.Path(exists=True),
              help="Path to certificate directory or file.")
@click.pass_context
def import_certs(ctx, path):
    """Import existing certificates."""
    from certpilot.utils.output import print_error, print_info, print_success

    mgr, _ = get_cert_manager(ctx.obj["config_path"])

    target_path = os.path.abspath(path)

    if os.path.isfile(target_path):
        # Import single certificate
        cert_path = target_path
        key_path = target_path.replace(".pem", ".key")
        if not os.path.exists(key_path):
            print_error(f"Key file not found: {key_path}")
            sys.exit(1)

        # Extract domain from certificate
        from certpilot.core.cert_parser import CertificateParser
        parser = CertificateParser()
        try:
            cert_info = parser.parse_file(cert_path)
            domain = cert_info.subject_cn
        except Exception as e:
            print_error(f"Failed to parse certificate: {e}")
            sys.exit(1)

        record = mgr.import_certificate(
            domain=domain,
            cert_path=cert_path,
            key_path=key_path,
        )

        if record:
            print_success(f"Imported certificate for {domain}")
        else:
            print_error(f"Failed to import certificate for {domain}")
            sys.exit(1)

    elif os.path.isdir(target_path):
        # Import all certificates from directory
        imported = 0
        errors = 0

        for filename in os.listdir(target_path):
            if filename.endswith(".pem") and not filename.endswith("key.pem"):
                cert_path = os.path.join(target_path, filename)
                key_path = cert_path.replace(".pem", ".key")

                if not os.path.exists(key_path):
                    key_path = os.path.join(
                        target_path, filename.replace("cert.pem", "key.pem")
                    )

                if not os.path.exists(key_path):
                    continue

                try:
                    from certpilot.core.cert_parser import CertificateParser
                    parser = CertificateParser()
                    cert_info = parser.parse_file(cert_path)
                    domain = cert_info.subject_cn

                    record = mgr.import_certificate(
                        domain=domain,
                        cert_path=cert_path,
                        key_path=key_path,
                    )
                    if record:
                        print_success(f"  Imported: {domain}")
                        imported += 1
                    else:
                        errors += 1
                except Exception:
                    errors += 1

        print_info(f"Import complete: {imported} imported, {errors} errors")
    else:
        print_error(f"Invalid path: {path}")
        sys.exit(1)


@cli.command()
@click.option("--domain", "-d", required=True, help="Domain to export.")
@click.option("--format", "output_format", default="pem",
              type=click.Choice(["pem", "pfx"], case_sensitive=False),
              help="Export format (pem, pfx).")
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--password", default=None, help="Password for PFX export.")
@click.pass_context
def export(ctx, domain, output_format, output, password):
    """Export a certificate in various formats."""
    from certpilot.utils.output import print_error, print_success

    mgr, _ = get_cert_manager(ctx.obj["config_path"])

    result_path = mgr.export_certificate(
        domain=domain,
        output_format=output_format,
        output_path=output,
        password=password,
    )

    if result_path:
        print_success(f"Certificate exported to: {result_path}")
    else:
        print_error(f"Failed to export certificate for {domain}")
        sys.exit(1)


# Main entry point
if __name__ == "__main__":
    cli()
