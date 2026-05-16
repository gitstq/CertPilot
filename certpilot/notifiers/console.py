"""Console notifier for CertPilot.

Outputs certificate notifications to the terminal using Rich.
"""

import logging
from typing import Any, Dict, Optional

from certpilot.notifiers.base import BaseNotifier, NotificationEvent

logger = logging.getLogger(__name__)


class ConsoleNotifier(BaseNotifier):
    """Console notification channel.

    Outputs notifications to the terminal with Rich formatting.
    Useful for development, testing, and environments without
    external notification infrastructure.

    Configuration:
        verbose: Whether to show detailed event information (default: True)
        color: Whether to use colored output (default: True)
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the console notifier.

        Args:
            config: Console notifier configuration.
        """
        super().__init__(config)
        self._verbose = self._config.get("verbose", True)
        self._color = self._config.get("color", True)

    def send(self, event: NotificationEvent) -> bool:
        """Output a notification to the console.

        Args:
            event: The notification event to display.

        Returns:
            Always True (console output cannot fail).
        """
        try:
            from certpilot.utils.output import (
                console,
                print_error,
                print_info,
                print_success,
                print_warning,
            )
        except ImportError:
            # Fallback to plain print
            print(f"[CertPilot] {event.subject}: {event.message}")
            return True

        # Choose output style based on event type
        event_styles = {
            "issued": print_success,
            "renewed": print_success,
            "expiring": print_warning,
            "expired": print_error,
            "revoked": print_error,
            "error": print_error,
            "test": print_info,
        }

        print_fn = event_styles.get(event.event_type, print_info)
        print_fn(f"{event.subject}: {event.message}")

        # Show details if verbose mode is enabled
        if self._verbose and event.details:
            console.print("  Details:", style="dim")
            for key, value in event.details.items():
                console.print(f"    {key}: {value}", style="dim")

        return True

    def test_config(self) -> bool:
        """Console notifier always works.

        Returns:
            Always True.
        """
        return True
