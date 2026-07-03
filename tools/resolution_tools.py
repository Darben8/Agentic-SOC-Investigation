from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse


def parse_url(url: str):
    cleaned = url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    return urlparse(cleaned)


def extract_hostname(value: str) -> str | None:
    parsed = parse_url(value)
    return parsed.hostname


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def resolve_dns(hostname: str) -> dict[str, Any]:
    a_records: list[str] = []
    aaaa_records: list[str] = []
    cname: str | None = None
    error: str | None = None

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            flags=socket.AI_CANONNAME,
        )

        for family, _, _, canonname, sockaddr in results:
            if canonname and canonname != hostname and cname is None:
                cname = canonname

            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in a_records:
                a_records.append(ip)
            elif family == socket.AF_INET6 and ip not in aaaa_records:
                aaaa_records.append(ip)
    except socket.gaierror as exc:
        error = str(exc)

    primary_ip = a_records[0] if a_records else aaaa_records[0] if aaaa_records else None
    return {
        "hostname": hostname,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "primary_ip": primary_ip,
        "cname": cname,
        "resolved": primary_ip is not None,
        "error": error,
    }
