"""Rich output formatting utilities for CertPilot.

Provides beautiful terminal output using the Rich library,
including tables, panels, progress bars, and status displays.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

logger = logging.getLogger(__name__)

# Global console instance
console = Console()


def get_console() -> Console:
    """Get the global Rich console instance.

    Returns:
        The shared Console object.
    """
    return console


def print_banner() -> None:
    """Print the CertPilot ASCII art banner."""
    banner_text = Text()
    banner_text.append("\n")
    banner_text.append("  ██████╗ ██████╗ ██████╗ ███████╗\n", style="bold cyan")
    banner_text.append(" ██╔════╝██╔═══██╗██╔══██╗██╔════╝\n", style="bold cyan")
    banner_text.append(" ██║     ██║   ██║██║  ██║█████╗  \n", style="bold cyan")
    banner_text.append(" ██║     ██║   ██║██║  ██║██╔══╝  \n", style="bold cyan")
    banner_text.append(" ╚██████╗╚██████╔╝██████╔╝███████╗\n", style="bold cyan")
    banner_text.append("  ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝\n", style="bold cyan")
    banner_text.append("    Lightweight SSL Certificate Management\n", style="dim")
    banner_text.append("    ", style="dim")
    banner_text.append("v1.0.0", style="bold yellow")
    banner_text.append("\n", style="dim")

    panel = Panel(
        banner_text,
        border_style="cyan",
        padding=(0, 2),
    )
    console.print(panel)


def print_success(message: str) -> None:
    """Print a success message with a green checkmark.

    Args:
        message: The success message to display.
    """
    console.print(f"[bold green][OK][/bold green] {message}")


def print_error(message: str) -> None:
    """Print an error message with a red cross.

    Args:
        message: The error message to display.
    """
    console.print(f"[bold red][ERROR][/bold red] {message}")


def print_warning(message: str) -> None:
    """Print a warning message with a yellow triangle.

    Args:
        message: The warning message to display.
    """
    console.print(f"[bold yellow][WARN][/bold yellow] {message}")


def print_info(message: str) -> None:
    """Print an informational message.

    Args:
        message: The info message to display.
    """
    console.print(f"[bold blue][INFO][/bold blue] {message}")


def print_certificate_table(records: List[Dict[str, Any]]) -> None:
    """Print a table of certificate records.

    Args:
        records: List of certificate record dictionaries with keys:
            - domain: Primary domain
            - status: Certificate status
            - expires_at: Expiry datetime or string
            - days_left: Days until expiry
            - ca: Certificate authority
            - auto_renew: Whether auto-renewal is enabled
    """
    table = Table(
        title="Managed Certificates",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
    )
    table.add_column("Domain", style="bold", min_width=25)
    table.add_column("Status", min_width=12)
    table.add_column("Expires", min_width=12)
    table.add_column("Days Left", justify="right", min_width=10)
    table.add_column("CA", min_width=15)
    table.add_column("Auto-Renew", justify="center", min_width=11)

    for record in records:
        domain = record.get("domain", "N/A")
        status = record.get("status", "unknown")
        expires_at = record.get("expires_at", "N/A")
        days_left = record.get("days_left", "N/A")
        ca = record.get("ca", "N/A")
        auto_renew = record.get("auto_renew", False)

        # Color-code status
        status_style = {
            "issued": "[green]Issued[/green]",
            "expired": "[red]Expired[/red]",
            "revoked": "[red]Revoked[/red]",
            "pending": "[yellow]Pending[/yellow]",
            "renewing": "[blue]Renewing[/blue]",
            "error": "[red]Error[/red]",
        }.get(status, f"[dim]{status}[/dim]")

        # Color-code days left
        if isinstance(days_left, int):
            if days_left <= 7:
                days_style = f"[bold red]{days_left}[/bold red]"
            elif days_left <= 30:
                days_style = f"[yellow]{days_left}[/yellow]"
            else:
                days_style = f"[green]{days_left}[/green]"
        else:
            days_style = str(days_left)

        # Format expiry date
        if isinstance(expires_at, datetime):
            expires_str = expires_at.strftime("%Y-%m-%d")
        else:
            expires_str = str(expires_at)

        auto_renew_str = "[green]Yes[/green]" if auto_renew else "[dim]No[/dim]"

        table.add_row(
            domain,
            status_style,
            expires_str,
            days_style,
            ca,
            auto_renew_str,
        )

    console.print(table)


def print_certificate_detail(info: Dict[str, Any]) -> None:
    """Print detailed certificate information in a panel.

    Args:
        info: Dictionary with certificate details.
    """
    table = Table(
        title="Certificate Details",
        show_header=False,
        border_style="cyan",
        box=None,
        padding=(0, 1),
    )
    table.add_column("Field", style="bold cyan", min_width=20)
    table.add_column("Value", min_width=40)

    for key, value in info.items():
        if value is None or value == "":
            value = "[dim]N/A[/dim]"
        elif isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        table.add_row(key, str(value))

    console.print(Panel(table, border_style="cyan"))


def print_domain_tree(domains: List[str], title: str = "Domains") -> None:
    """Print a tree view of domains.

    Args:
        domains: List of domain names.
        title: Tree title.
    """
    tree = Tree(f"[bold cyan]{title}[/bold cyan]")
    for domain in domains:
        if domain.startswith("*."):
            tree.add(f"[yellow]{domain}[/yellow] (wildcard)")
        else:
            tree.add(f"[green]{domain}[/green]")
    console.print(tree)


def create_progress() -> Progress:
    """Create a Rich progress bar for long-running operations.

    Returns:
        A Progress instance with standard columns.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


def print_step(step_num: int, total: int, description: str) -> None:
    """Print a numbered step indicator.

    Args:
        step_num: Current step number (1-based).
        total: Total number of steps.
        description: Step description.
    """
    console.print(
        f"[bold cyan][Step {step_num}/{total}][/bold cyan] {description}"
    )


def print_json_output(data: Dict[str, Any]) -> None:
    """Print JSON output for CI/machine-readable mode.

    Args:
        data: Dictionary to serialize as JSON.
    """
    import json

    json_str = json.dumps(data, indent=2, default=str, ensure_ascii=False)
    console.print_json(json_str)


def print_panel(
    content: str,
    title: str = "",
    border_style: str = "cyan",
    subtitle: str = "",
) -> None:
    """Print content in a styled panel.

    Args:
        content: Panel content text.
        title: Panel title.
        border_style: Rich border style.
        subtitle: Panel subtitle.
    """
    panel = Panel(
        content,
        title=title if title else None,
        subtitle=subtitle if subtitle else None,
        border_style=border_style,
    )
    console.print(panel)


def print_dns_instructions(challenge_fqdn: str, challenge_value: str) -> None:
    """Print DNS record creation instructions for manual verification.

    Args:
        challenge_fqdn: The FQDN for the TXT record.
        challenge_value: The TXT record value.
    """
    instructions = Text()
    instructions.append("Please create the following DNS record:\n\n", style="bold")
    instructions.append("  Type:  ", style="cyan")
    instructions.append("TXT\n", style="bold")
    instructions.append("  Name:  ", style="cyan")
    instructions.append(f"{challenge_fqdn}\n", style="bold yellow")
    instructions.append("  Value: ", style="cyan")
    instructions.append(f"{challenge_value}\n", style="bold green")
    instructions.append("\n", style="dim")
    instructions.append(
        "Note: DNS propagation may take a few minutes.\n"
        "Press Enter after you have added the DNS record...",
        style="dim",
    )

    console.print(Panel(instructions, title="DNS Verification Required", border_style="yellow"))


def print_summary(success_count: int, error_count: int, warnings: List[str] = None) -> None:
    """Print an operation summary.

    Args:
        success_count: Number of successful operations.
        error_count: Number of failed operations.
        warnings: Optional list of warning messages.
    """
    summary_parts = []
    if success_count > 0:
        summary_parts.append(f"[green]{success_count} succeeded[/green]")
    if error_count > 0:
        summary_parts.append(f"[red]{error_count} failed[/red]")

    summary_text = ", ".join(summary_parts) if summary_parts else "No operations performed"
    console.print(f"\n[bold]Summary:[/bold] {summary_text}")

    if warnings:
        for warning in warnings:
            print_warning(warning)
