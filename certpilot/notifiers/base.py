"""Base notifier interface for CertPilot.

All notifiers must implement this interface to support
sending notifications about certificate events.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class NotificationEvent:
    """Represents a notification event."""

    def __init__(
        self,
        event_type: str,
        domain: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a notification event.

        Args:
            event_type: Type of event (e.g., 'issued', 'renewed', 'expiring', 'error').
            domain: The domain this event relates to.
            message: Human-readable message.
            details: Optional additional details dictionary.
        """
        self.event_type = event_type
        self.domain = domain
        self.message = message
        self.details = details or {}
        self.timestamp = None
        try:
            from datetime import datetime
            self.timestamp = datetime.now()
        except Exception:
            pass

    @property
    def subject(self) -> str:
        """Generate a subject line for the notification."""
        type_labels = {
            "issued": "Certificate Issued",
            "renewed": "Certificate Renewed",
            "expiring": "Certificate Expiring",
            "expired": "Certificate Expired",
            "revoked": "Certificate Revoked",
            "error": "Certificate Error",
            "test": "Test Notification",
        }
        label = type_labels.get(self.event_type, self.event_type.title())
        return f"[CertPilot] {label} - {self.domain}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary.

        Returns:
            Dictionary representation of the event.
        """
        return {
            "event_type": self.event_type,
            "domain": self.domain,
            "message": self.message,
            "details": self.details,
            "subject": self.subject,
            "timestamp": str(self.timestamp) if self.timestamp else None,
        }


class BaseNotifier(ABC):
    """Abstract base class for notification channels.

    Notifiers are responsible for sending notifications about certificate
    lifecycle events such as issuance, renewal, expiry warnings, and errors.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the notifier.

        Args:
            config: Notifier-specific configuration dictionary.
        """
        self._config = config or {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def send(self, event: NotificationEvent) -> bool:
        """Send a notification.

        Args:
            event: The notification event to send.

        Returns:
            True if the notification was sent successfully, False otherwise.
        """
        ...

    def send_test(self) -> bool:
        """Send a test notification.

        Returns:
            True if the test notification was sent successfully.
        """
        test_event = NotificationEvent(
            event_type="test",
            domain="example.com",
            message="This is a test notification from CertPilot. "
                    "If you received this, your notification channel is working correctly.",
            details={"test": True},
        )
        return self.send(test_event)

    def test_config(self) -> bool:
        """Test the notifier configuration.

        Returns:
            True if the configuration appears valid.
        """
        return True

    @property
    def name(self) -> str:
        """Return the notifier name."""
        return self.__class__.__name__

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"


def get_notifier(
    notifier_type: str,
    config: Optional[Dict[str, Any]] = None,
) -> BaseNotifier:
    """Factory function to create a notifier instance.

    Args:
        notifier_type: The notifier type identifier.
        config: Notifier-specific configuration.

    Returns:
        An instance of the requested notifier.

    Raises:
        ValueError: If the notifier type is not supported.
    """
    notifier_type = notifier_type.lower().strip()

    if notifier_type == "email":
        from certpilot.notifiers.email import EmailNotifier
        return EmailNotifier(config)
    elif notifier_type == "webhook":
        from certpilot.notifiers.webhook import WebhookNotifier
        return WebhookNotifier(config)
    elif notifier_type == "console":
        from certpilot.notifiers.console import ConsoleNotifier
        return ConsoleNotifier(config)
    else:
        raise ValueError(
            f"Unsupported notifier: {notifier_type}. "
            f"Supported: email, webhook, console"
        )
