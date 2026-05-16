"""Auto-renewal scheduler for CertPilot.

Uses APScheduler to periodically check certificates and
renew those approaching expiry.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)


class CertPilotScheduler:
    """Certificate auto-renewal scheduler.

    Runs in the background and periodically checks managed certificates
    for upcoming expiry. Triggers renewal and sends notifications
    at configured intervals before expiry.
    """

    def __init__(
        self,
        cert_manager=None,
        notifier=None,
        deployer=None,
        check_hour: int = 3,
        check_minute: int = 0,
        notify_days: Optional[List[int]] = None,
    ):
        """Initialize the scheduler.

        Args:
            cert_manager: CertificateManager instance for renewal operations.
            notifier: Notifier instance for expiry notifications.
            deployer: Deployer instance for certificate deployment.
            check_hour: Hour of day to run checks (0-23, default: 3 AM).
            check_minute: Minute of hour to run checks (0-59, default: 0).
            notify_days: Days before expiry to send notifications.
        """
        self._cert_manager = cert_manager
        self._notifier = notifier
        self._deployer = deployer
        self._check_hour = check_hour
        self._check_minute = check_minute
        self._notify_days = notify_days or [30, 14, 7, 1]
        self._scheduler = BackgroundScheduler(
            timezone="Asia/Shanghai",
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": 3600,
            },
        )
        self._is_running = False
        self._pid_file = os.path.expanduser("~/.certpilot/scheduler.pid")

    @property
    def is_running(self) -> bool:
        """Check if the scheduler is currently running.

        Returns:
            True if the scheduler is active.
        """
        return self._is_running

    def start(self) -> bool:
        """Start the auto-renewal scheduler.

        Returns:
            True if the scheduler was started successfully.
        """
        if self._is_running:
            logger.warning("Scheduler is already running")
            return True

        if not self._cert_manager:
            logger.error("Certificate manager not configured")
            return False

        try:
            # Add daily certificate check job
            self._scheduler.add_job(
                self._daily_check,
                CronTrigger(
                    hour=self._check_hour,
                    minute=self._check_minute,
                ),
                id="daily_cert_check",
                name="Daily Certificate Check",
                replace_existing=True,
            )

            # Add hourly notification check
            self._scheduler.add_job(
                self._check_expiry_notifications,
                CronTrigger(minute=0),
                id="expiry_notification_check",
                name="Expiry Notification Check",
                replace_existing=True,
            )

            self._scheduler.start()
            self._is_running = True

            # Write PID file
            self._write_pid_file()

            logger.info(
                f"Scheduler started. Daily check at {self._check_hour:02d}:{self._check_minute:02d}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to start scheduler: {e}")
            return False

    def stop(self) -> bool:
        """Stop the auto-renewal scheduler.

        Returns:
            True if the scheduler was stopped successfully.
        """
        if not self._is_running:
            logger.warning("Scheduler is not running")
            return True

        try:
            self._scheduler.shutdown(wait=True)
            self._is_running = False
            self._remove_pid_file()
            logger.info("Scheduler stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop scheduler: {e}")
            return False

    def run_once(self) -> Dict[str, Any]:
        """Run a single check cycle immediately.

        Useful for testing or manual triggering.

        Returns:
            Dictionary with check results.
        """
        if not self._cert_manager:
            return {"error": "Certificate manager not configured"}

        results = {
            "checked_at": str(datetime.now()),
            "total_certificates": 0,
            "needs_renewal": 0,
            "renewed": 0,
            "renewal_errors": 0,
            "notifications_sent": 0,
            "details": [],
        }

        try:
            records = self._cert_manager.list_records()
            results["total_certificates"] = len(records)
            needs_renewal = self._cert_manager.check_renewals()
            results["needs_renewal"] = len(needs_renewal)

            for record in needs_renewal:
                logger.info(f"Renewing certificate for {record.domain}")
                new_record = self._cert_manager.renew(
                    domain=record.domain,
                    deployer=self._deployer,
                    notifier=self._notifier,
                )

                if new_record:
                    results["renewed"] += 1
                    results["details"].append({
                        "domain": record.domain,
                        "status": "renewed",
                    })
                else:
                    results["renewal_errors"] += 1
                    results["details"].append({
                        "domain": record.domain,
                        "status": "error",
                    })

        except Exception as e:
            logger.error(f"Check cycle failed: {e}")
            results["error"] = str(e)

        return results

    def _daily_check(self) -> None:
        """Perform the daily certificate check and renewal.

        This is the main job executed by the scheduler.
        """
        logger.info("Starting daily certificate check")
        results = self.run_once()
        logger.info(
            f"Daily check complete: {results.get('renewed', 0)} renewed, "
            f"{results.get('renewal_errors', 0)} errors"
        )

    def _check_expiry_notifications(self) -> None:
        """Check for certificates approaching expiry and send notifications.

        Sends notifications at configured intervals (e.g., 30, 14, 7, 1 days
        before expiry).
        """
        if not self._cert_manager or not self._notifier:
            return

        try:
            records = self._cert_manager.list_records()
            now = datetime.now()

            for record in records:
                if not record.expires_at or record.status in ("revoked", "pending"):
                    continue

                days_left = (record.expires_at - now).days

                # Check if we should notify at this threshold
                if days_left in self._notify_days:
                    event_type = "expired" if days_left <= 0 else "expiring"

                    try:
                        from certpilot.notifiers.base import NotificationEvent
                        self._notifier.send(NotificationEvent(
                            event_type=event_type,
                            domain=record.domain,
                            message=(
                                f"Certificate for {record.domain} "
                                f"{'has expired' if days_left <= 0 else f'expires in {days_left} days'}. "
                                f"Expiry date: {record.expires_at.strftime('%Y-%m-%d')}"
                            ),
                            details={
                                "days_to_expiry": days_left,
                                "expires_at": str(record.expires_at),
                                "auto_renew": record.auto_renew,
                            },
                        ))
                        logger.info(
                            f"Expiry notification sent for {record.domain} "
                            f"({days_left} days remaining)"
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to send notification for {record.domain}: {e}"
                        )

        except Exception as e:
            logger.error(f"Expiry notification check failed: {e}")

    def _write_pid_file(self) -> None:
        """Write the scheduler PID to a file."""
        try:
            os.makedirs(os.path.dirname(self._pid_file), exist_ok=True)
            with open(self._pid_file, "w") as f:
                f.write(str(os.getpid()))
        except OSError as e:
            logger.warning(f"Failed to write PID file: {e}")

    def _remove_pid_file(self) -> None:
        """Remove the scheduler PID file."""
        try:
            if os.path.exists(self._pid_file):
                os.remove(self._pid_file)
        except OSError:
            pass

    def get_status(self) -> Dict[str, Any]:
        """Get the current scheduler status.

        Returns:
            Dictionary with scheduler status information.
        """
        jobs = []
        if self._scheduler.running:
            for job in self._scheduler.get_jobs():
                jobs.append({
                    "id": job.id,
                    "name": job.name,
                    "next_run": str(job.next_run_time) if job.next_run_time else None,
                })

        return {
            "running": self._is_running,
            "check_hour": self._check_hour,
            "check_minute": self._check_minute,
            "notify_days": self._notify_days,
            "jobs": jobs,
        }
