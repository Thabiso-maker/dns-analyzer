from __future__ import annotations
import ipaddress
import re
from pathlib import Path
from typing import Any
from dns_analyzer.utils.exceptions import InvalidDomainError, InvalidIPAddressError, InvalidScanOptionsError, ValidationError

_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$|^[a-zA-Z0-9]$")
_ALLOWED_REPORT_FORMATS = frozenset({"html", "pdf", "json"})
_RESERVED = [ipaddress.ip_network(n) for n in ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16"]]

def validate_domain(raw: str, *, allow_wildcard: bool = False) -> str:
    if not raw or not isinstance(raw, str):
        raise InvalidDomainError(str(raw), reason="Domain must be a non-empty string.")
    domain = raw.strip().lower().rstrip(".")
    if domain.startswith("*."):
        if not allow_wildcard:
            raise InvalidDomainError(domain, reason="Wildcard domains not permitted here.")
        domain_to_validate = domain[2:]
    else:
        domain_to_validate = domain
    if not domain_to_validate or len(domain_to_validate) > 253:
        raise InvalidDomainError(domain, reason="Invalid domain length.")
    labels = domain_to_validate.split(".")
    if len(labels) < 2:
        raise InvalidDomainError(domain, reason="Domain must have at least two labels.")
    for label in labels:
        if not label or len(label) > 63:
            raise InvalidDomainError(domain, reason=f"Invalid label: {label!r}")
        if not _LABEL_RE.match(label):
            raise InvalidDomainError(domain, reason=f"Label {label!r} contains invalid characters.")
    return domain

def validate_domain_list(raw_domains: list[str]) -> list[str]:
    if not raw_domains:
        raise ValidationError("Domain list cannot be empty.")
    if len(raw_domains) > 500:
        raise ValidationError(f"Too many domains (max 500).")
    return [validate_domain(d) for d in raw_domains]

def validate_ip(raw: str, *, allow_reserved: bool = False) -> str:
    if not raw or not isinstance(raw, str):
        raise InvalidIPAddressError(str(raw))
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise InvalidIPAddressError(raw)
    if not allow_reserved:
        for network in _RESERVED:
            if addr in network:
                raise ValidationError(f"IP {raw!r} is in a reserved range.")
    return str(addr)

def validate_report_format(fmt: str) -> str:
    normalized = fmt.strip().lower()
    if normalized not in _ALLOWED_REPORT_FORMATS:
        raise InvalidScanOptionsError(f"Invalid format: {fmt!r}. Use html, pdf, or json.")
    return normalized

def validate_monitor_interval(hours: Any) -> int:
    try:
        h = int(hours)
    except (TypeError, ValueError):
        raise InvalidScanOptionsError(f"Interval must be an integer.")
    if h < 1 or h > 168:
        raise InvalidScanOptionsError(f"Interval must be 1–168 hours.")
    return h

def validate_domains_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise ValidationError(f"File not found: {path!r}")
    content = p.read_text(encoding="utf-8")
    raw = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not raw:
        raise ValidationError(f"File is empty: {path!r}")
    return validate_domain_list(raw)

def is_valid_domain(raw: str) -> bool:
    try:
        validate_domain(raw)
        return True
    except:
        return False

def is_valid_ip(raw: str) -> bool:
    try:
        ipaddress.ip_address(raw.strip())
        return True
    except ValueError:
        return False

def is_private_ip(raw: str) -> bool:
    try:
        addr = ipaddress.ip_address(raw.strip())
        return any(addr in net for net in _RESERVED)
    except ValueError:
        return False

def extract_registrable_domain(domain: str) -> str:
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    raise InvalidDomainError(domain, reason="Could not extract registrable domain.")
