"""Validation utility functions for CertPilot.

Provides domain name validation, email validation, file permission checks,
and other validation helpers.
"""

import os
import re
import socket
import stat
from typing import List, Optional, Tuple
from urllib.parse import urlparse


# Domain name regex (RFC 1035 compliant)
_DOMAIN_REGEX = re.compile(
    r"^(?:\*\.)?"  # optional wildcard
    r"(?:[a-zA-Z0-9]"  # first char of label
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"  # rest of label
    r"\.)+"  # labels separated by dots
    r"[a-zA-Z]{2,}$"  # TLD
)

# Email regex (basic validation)
_EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)

# IP address regex
_IPv4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def validate_domain(domain: str) -> Tuple[bool, str]:
    """Validate a domain name.

    Args:
        domain: The domain name to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not domain:
        return False, "Domain name cannot be empty"

    domain = domain.strip().lower()

    if domain.startswith("."):
        return False, "Domain name cannot start with a dot"

    if domain.endswith("."):
        domain = domain.rstrip(".")

    if len(domain) > 253:
        return False, "Domain name exceeds 253 character limit"

    if domain.startswith("*"):
        # Wildcard domain validation
        if not domain.startswith("*."):
            return False, "Wildcard must be in the format *.example.com"
        base = domain[2:]
        if not _DOMAIN_REGEX.match(base):
            return False, f"Invalid wildcard base domain: {base}"
        return True, ""

    if not _DOMAIN_REGEX.match(domain):
        return False, f"Invalid domain name: {domain}"

    return True, ""


def validate_domains(domains: List[str]) -> Tuple[bool, List[str]]:
    """Validate a list of domain names.

    Args:
        domains: List of domain names to validate.

    Returns:
        Tuple of (all_valid, list_of_error_messages).
    """
    errors: List[str] = []
    seen = set()

    for domain in domains:
        domain = domain.strip().lower()
        if not domain:
            continue

        is_valid, error = validate_domain(domain)
        if not is_valid:
            errors.append(error)
            continue

        if domain in seen:
            errors.append(f"Duplicate domain: {domain}")
            continue

        seen.add(domain)

    return len(errors) == 0, errors


def validate_email(email: str) -> Tuple[bool, str]:
    """Validate an email address.

    Args:
        email: The email address to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not email:
        return False, "Email address cannot be empty"

    if not _EMAIL_REGEX.match(email):
        return False, f"Invalid email address: {email}"

    return True, ""


def validate_port(port: int) -> Tuple[bool, str]:
    """Validate a network port number.

    Args:
        port: The port number to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not isinstance(port, int):
        return False, "Port must be an integer"
    if port < 1 or port > 65535:
        return False, "Port must be between 1 and 65535"
    return True, ""


def validate_url(url: str) -> Tuple[bool, str]:
    """Validate a URL.

    Args:
        url: The URL to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not url:
        return False, "URL cannot be empty"

    try:
        result = urlparse(url)
        if result.scheme not in ("http", "https"):
            return False, f"Unsupported URL scheme: {result.scheme}"
        if not result.netloc:
            return False, "URL must contain a hostname"
        return True, ""
    except Exception as e:
        return False, f"Invalid URL: {e}"


def validate_file_permissions(filepath: str, required_mode: int = 0o600) -> Tuple[bool, str]:
    """Check if a file has the required permissions.

    Args:
        filepath: Path to the file.
        required_mode: Required permission bits (e.g., 0o600 for owner-only read/write).

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not os.path.exists(filepath):
        return False, f"File does not exist: {filepath}"

    try:
        st = os.stat(filepath)
        file_mode = stat.S_IMODE(st.st_mode)

        # Check if file permissions are too open
        if required_mode == 0o600:
            # For private keys: only owner should have read/write
            if file_mode & stat.S_IRGRP or file_mode & stat.S_IROTH:
                return False, (
                    f"File {filepath} has overly permissive permissions "
                    f"(0{file_mode:o}). Expected 0o600 (owner read/write only)."
                )
        elif required_mode == 0o644:
            # For certificates: owner read/write, others read
            if file_mode & stat.S_IWGRP or file_mode & stat.S_IWOTH:
                return False, (
                    f"File {filepath} has overly permissive write permissions "
                    f"(0{file_mode:o})."
                )

        return True, ""
    except OSError as e:
        return False, f"Cannot check file permissions: {e}"


def validate_directory_writable(dirpath: str) -> Tuple[bool, str]:
    """Check if a directory exists and is writable.

    Args:
        dirpath: Path to the directory.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not os.path.exists(dirpath):
        try:
            os.makedirs(dirpath, exist_ok=True)
        except OSError as e:
            return False, f"Cannot create directory {dirpath}: {e}"

    if not os.path.isdir(dirpath):
        return False, f"Path is not a directory: {dirpath}"

    if not os.access(dirpath, os.W_OK):
        return False, f"Directory is not writable: {dirpath}"

    return True, ""


def validate_key_type(key_type: str) -> Tuple[bool, str]:
    """Validate a key type identifier.

    Args:
        key_type: The key type to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    valid_types = ("rsa2048", "rsa4096", "ecdsa_p256", "ecdsa_p384", "p256", "p384")
    if key_type.lower() not in valid_types:
        return False, (
            f"Invalid key type: {key_type}. "
            f"Supported: {', '.join(valid_types)}"
        )
    return True, ""


def is_wildcard_domain(domain: str) -> bool:
    """Check if a domain is a wildcard domain.

    Args:
        domain: The domain name to check.

    Returns:
        True if the domain starts with '*.'.
    """
    return domain.strip().lower().startswith("*.")


def get_base_domain(wildcard_domain: str) -> str:
    """Extract the base domain from a wildcard domain.

    Args:
        wildcard_domain: A wildcard domain like '*.example.com'.

    Returns:
        The base domain like 'example.com'.
    """
    domain = wildcard_domain.strip().lower()
    if domain.startswith("*."):
        return domain[2:]
    return domain


def resolve_domain(domain: str) -> List[str]:
    """Resolve a domain name to IP addresses.

    Args:
        domain: The domain name to resolve.

    Returns:
        List of IP addresses, or empty list if resolution fails.
    """
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(r[4][0] for r in results))
        return ips
    except socket.gaierror:
        return []


def sanitize_filename(filename: str) -> str:
    """Sanitize a string to be used as a safe filename.

    Args:
        filename: The filename to sanitize.

    Returns:
        A sanitized filename string.
    """
    # Replace characters that are unsafe in filenames
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    return sanitized or "unnamed"
