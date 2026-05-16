"""Email notifier for CertPilot.

Sends certificate notifications via SMTP email.
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from certpilot.notifiers.base import BaseNotifier, NotificationEvent

logger = logging.getLogger(__name__)


class EmailNotifier(BaseNotifier):
    """Email notification channel using SMTP.

    Supports TLS-encrypted SMTP connections for secure email delivery.
    Compatible with Gmail, Outlook, and other SMTP providers.

    Configuration:
        smtp_host: SMTP server hostname (default: smtp.gmail.com)
        smtp_port: SMTP server port (default: 587)
        smtp_tls: Whether to use TLS (default: True)
        smtp_username: SMTP authentication username
        smtp_password: SMTP authentication password
        from_address: Sender email address
        to_addresses: List of recipient email addresses
        subject_template: Subject line template with {action} and {domain} placeholders
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the email notifier.

        Args:
            config: Email notifier configuration.
        """
        super().__init__(config)
        self._smtp_host = self._config.get("smtp_host", "smtp.gmail.com")
        self._smtp_port = self._config.get("smtp_port", 587)
        self._smtp_tls = self._config.get("smtp_tls", True)
        self._smtp_username = self._config.get("smtp_username", "")
        self._smtp_password = self._config.get("smtp_password", "")
        self._from_address = self._config.get("from_address", self._smtp_username)
        self._to_addresses: List[str] = self._config.get("to_addresses", [])
        self._subject_template = self._config.get(
            "subject_template", "[CertPilot] {action} - {domain}"
        )

    def _build_email(
        self,
        event: NotificationEvent,
    ) -> MIMEMultipart:
        """Build an email message for the notification event.

        Args:
            event: The notification event.

        Returns:
            A MIMEMultipart email message.
        """
        msg = MIMEMultipart("alternative")
        msg["From"] = self._from_address
        msg["To"] = ", ".join(self._to_addresses)

        # Build subject
        subject = self._subject_template.format(
            action=event.event_type.title(),
            domain=event.domain,
        )
        msg["Subject"] = subject

        # Build plain text body
        text_body = self._build_text_body(event)
        msg.attach(MIMEText(text_body, "plain", "utf-8"))

        # Build HTML body
        html_body = self._build_html_body(event)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        return msg

    def _build_text_body(self, event: NotificationEvent) -> str:
        """Build a plain text email body.

        Args:
            event: The notification event.

        Returns:
            Plain text email body.
        """
        lines = [
            f"CertPilot Notification",
            f"{'=' * 40}",
            f"",
            f"Event: {event.event_type}",
            f"Domain: {event.domain}",
            f"Time: {event.timestamp}",
            f"",
            f"{event.message}",
            f"",
        ]

        if event.details:
            lines.append("Details:")
            for key, value in event.details.items():
                lines.append(f"  {key}: {value}")
            lines.append("")

        lines.append("--")
        lines.append("CertPilot - Lightweight SSL Certificate Management Engine")

        return "\n".join(lines)

    def _build_html_body(self, event: NotificationEvent) -> str:
        """Build an HTML email body.

        Args:
            event: The notification event.

        Returns:
            HTML email body.
        """
        details_html = ""
        if event.details:
            rows = ""
            for key, value in event.details.items():
                rows += f"<tr><td><b>{key}</b></td><td>{value}</td></tr>"
            details_html = f"<table>{rows}</table>"

        # Color based on event type
        colors = {
            "issued": "#28a745",
            "renewed": "#28a745",
            "expiring": "#ffc107",
            "expired": "#dc3545",
            "revoked": "#dc3545",
            "error": "#dc3545",
            "test": "#17a2b8",
        }
        color = colors.get(event.event_type, "#6c757d")

        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="background: {color}; color: white; padding: 15px 20px; border-radius: 5px 5px 0 0;">
    <h2 style="margin: 0;">CertPilot - {event.event_type.title()}</h2>
  </div>
  <div style="border: 1px solid #ddd; padding: 20px; border-top: none;">
    <p><strong>Domain:</strong> {event.domain}</p>
    <p><strong>Time:</strong> {event.timestamp}</p>
    <p>{event.message}</p>
    {details_html}
  </div>
  <div style="color: #999; font-size: 12px; text-align: center; margin-top: 20px;">
    CertPilot - Lightweight SSL Certificate Management Engine
  </div>
</body>
</html>"""
        return html

    def send(self, event: NotificationEvent) -> bool:
        """Send an email notification.

        Args:
            event: The notification event to send.

        Returns:
            True if the email was sent successfully.
        """
        if not self._to_addresses:
            self._logger.error("No recipient email addresses configured")
            return False

        if not self._smtp_username or not self._smtp_password:
            self._logger.error("SMTP credentials not configured")
            return False

        try:
            msg = self._build_email(event)

            if self._smtp_tls:
                server = smtplib.SMTP(self._smtp_host, self._smtp_port)
                server.ehlo()
                server.starttls()
                server.ehlo()
            else:
                server = smtplib.SMTP(self._smtp_host, self._smtp_port)

            server.login(self._smtp_username, self._smtp_password)
            server.sendmail(self._from_address, self._to_addresses, msg.as_string())
            server.quit()

            self._logger.info(
                f"Email notification sent to {len(self._to_addresses)} recipient(s)"
            )
            return True

        except smtplib.SMTPAuthenticationError as e:
            self._logger.error(f"SMTP authentication failed: {e}")
            return False
        except smtplib.SMTPException as e:
            self._logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            self._logger.error(f"Failed to send email notification: {e}")
            return False

    def test_config(self) -> bool:
        """Test email configuration by checking required fields.

        Returns:
            True if all required configuration is present.
        """
        required = ["smtp_host", "smtp_username", "smtp_password", "from_address"]
        for field in required:
            if not self._config.get(field):
                self._logger.error(f"Missing required email config: {field}")
                return False

        if not self._to_addresses:
            self._logger.error("No recipient addresses configured")
            return False

        return True
