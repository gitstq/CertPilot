"""Webhook notifier for CertPilot.

Sends certificate notifications via HTTP webhooks.
Compatible with Slack, DingTalk, Feishu, and custom webhooks.
"""

import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional

import requests

from certpilot.notifiers.base import BaseNotifier, NotificationEvent

logger = logging.getLogger(__name__)


class WebhookNotifier(BaseNotifier):
    """Webhook notification channel.

    Sends JSON payloads to HTTP endpoints. Supports custom headers,
    body templates, and HMAC signature verification.

    Compatible with:
    - Slack incoming webhooks
    - DingTalk (钉钉) robot webhooks
    - Feishu (飞书) robot webhooks
    - Custom HTTP endpoints

    Configuration:
        url: Webhook URL (required)
        method: HTTP method (default: POST)
        headers: Custom HTTP headers dictionary
        body_template: Optional JSON body template string
        secret: Optional HMAC secret for signature verification
    """

    # Pre-configured templates for common platforms
    PLATFORM_TEMPLATES = {
        "slack": {
            "content_type": "application/json",
            "build_body": lambda event: json.dumps({
                "text": f"[CertPilot] {event.subject}\n{event.message}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{event.subject}*\n{event.message}",
                        },
                    }
                ],
            }),
        },
        "dingtalk": {
            "content_type": "application/json",
            "build_body": lambda event: json.dumps({
                "msgtype": "text",
                "text": {
                    "content": f"[CertPilot] {event.subject}\n{event.message}",
                },
            }),
        },
        "feishu": {
            "content_type": "application/json",
            "build_body": lambda event: json.dumps({
                "msg_type": "text",
                "content": {
                    "text": f"[CertPilot] {event.subject}\n{event.message}",
                },
            }),
        },
        "generic": {
            "content_type": "application/json",
            "build_body": lambda event: json.dumps(event.to_dict()),
        },
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the webhook notifier.

        Args:
            config: Webhook notifier configuration.
        """
        super().__init__(config)
        self._url = self._config.get("url", "")
        self._method = self._config.get("method", "POST").upper()
        self._headers: Dict[str, str] = self._config.get("headers", {})
        self._body_template = self._config.get("body_template")
        self._secret = self._config.get("secret")
        self._platform = self._config.get("platform", "generic")
        self._timeout = self._config.get("timeout", 30)
        self._session = requests.Session()

    def _detect_platform(self) -> str:
        """Auto-detect the webhook platform from the URL.

        Returns:
            Platform identifier string.
        """
        url = self._url.lower()
        if "hooks.slack.com" in url:
            return "slack"
        elif "oapi.dingtalk.com" in url:
            return "dingtalk"
        elif "open.feishu.cn" in url or "open.larksuite.com" in url:
            return "feishu"
        return "generic"

    def _build_body(self, event: NotificationEvent) -> str:
        """Build the webhook request body.

        Args:
            event: The notification event.

        Returns:
            JSON string body.
        """
        # Use custom template if provided
        if self._body_template:
            try:
                event_dict = event.to_dict()
                return self._body_template.format(**event_dict)
            except (KeyError, ValueError) as e:
                self._logger.warning(f"Body template error: {e}, using default")

        # Use platform-specific template
        platform = self._platform or self._detect_platform()
        template = self.PLATFORM_TEMPLATES.get(platform, self.PLATFORM_TEMPLATES["generic"])
        return template["build_body"](event)

    def _sign_request(self, body: str) -> Dict[str, str]:
        """Generate HMAC signature headers for the request.

        Args:
            body: The request body string.

        Returns:
            Dictionary of signature headers to add.
        """
        if not self._secret:
            return {}

        headers = {}
        timestamp = str(int(__import__("time").time()))
        sign_str = f"{timestamp}\n{body}"
        signature = hmac.new(
            self._secret.encode("utf-8"),
            sign_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        headers["X-CertPilot-Signature"] = f"sha256={signature}"
        headers["X-CertPilot-Timestamp"] = timestamp

        return headers

    def send(self, event: NotificationEvent) -> bool:
        """Send a webhook notification.

        Args:
            event: The notification event to send.

        Returns:
            True if the webhook was sent successfully.
        """
        if not self._url:
            self._logger.error("Webhook URL not configured")
            return False

        try:
            body = self._build_body(event)
            headers = {"Content-Type": "application/json"}
            headers.update(self._headers)
            headers.update(self._sign_request(body))

            response = self._session.request(
                method=self._method,
                url=self._url,
                data=body.encode("utf-8"),
                headers=headers,
                timeout=self._timeout,
            )

            if response.status_code >= 200 and response.status_code < 300:
                self._logger.info(
                    f"Webhook notification sent successfully "
                    f"(status: {response.status_code})"
                )
                return True
            else:
                self._logger.error(
                    f"Webhook request failed with status {response.status_code}: "
                    f"{response.text}"
                )
                return False

        except requests.Timeout:
            self._logger.error(f"Webhook request timed out ({self._timeout}s)")
            return False
        except requests.RequestException as e:
            self._logger.error(f"Webhook request failed: {e}")
            return False

    def test_config(self) -> bool:
        """Test webhook configuration by checking required fields.

        Returns:
            True if the URL is configured.
        """
        if not self._url:
            self._logger.error("Webhook URL not configured")
            return False

        is_valid, _ = __import__(
            "certpilot.utils.validation", fromlist=["validate_url"]
        ).validate_url(self._url)
        return is_valid
