from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from state import Entities

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
USER_PATTERN = re.compile(r"\buser(?:name)?[=: ]+([A-Za-z0-9._-]+)", re.IGNORECASE)
HOST_PATTERN = re.compile(r"\bhost[=: ]+([A-Za-z0-9._-]+)", re.IGNORECASE)
PORT_PATTERN = re.compile(r"\b(?:port|dpt|spt)[=: ]+(\d{1,5})", re.IGNORECASE)
PLAIN_PORT_LIST_PATTERN = re.compile(r"\bports?\b\s+([0-9,\sand]+?)\s+(?:from|to|were|was)\b", re.IGNORECASE)
TIME_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?\b")


def _clean_token(value: Any) -> str:
    return str(value).strip().strip(".,;:)")


def _collect_text(payload: Any) -> str:
    if isinstance(payload, dict):
        return " ".join(_collect_text(value) for value in payload.values())
    if isinstance(payload, list):
        return " ".join(_collect_text(item) for item in payload)
    return str(payload)


def extract_entities(alert: dict[str, Any]) -> Entities:
    text = _collect_text(alert)

    ips = sorted(set(IP_PATTERN.findall(text)))
    urls = sorted(set(URL_PATTERN.findall(text)))
    domains = {_clean_token(value) for value in DOMAIN_PATTERN.findall(text)}
    domains.update(_clean_token(urlparse(url).hostname) for url in urls if urlparse(url).hostname)
    users = sorted({_clean_token(value) for value in USER_PATTERN.findall(text)})
    hosts = sorted({_clean_token(value) for value in HOST_PATTERN.findall(text)})
    ports = sorted(set(PORT_PATTERN.findall(text)))
    for match in PLAIN_PORT_LIST_PATTERN.findall(text):
        ports.extend(re.findall(r"\d{1,5}", match))
    timestamps = sorted(set(TIME_PATTERN.findall(text)))

    # Pick up common normalized fields even when regexes are sparse.
    for field in ["src_ip", "dst_ip", "ip", "source_ip", "destination_ip"]:
        value = alert.get(field)
        if value:
            ips.append(str(value))
    for field in ["url", "destination_url"]:
        value = alert.get(field)
        if value:
            urls.append(str(value))
    for field in ["domain", "destination_domain"]:
        value = alert.get(field)
        if value:
            domains.add(_clean_token(value))
    for field in ["user", "username"]:
        value = alert.get(field)
        if value:
            users.append(str(value))
    for field in ["host", "hostname"]:
        value = alert.get(field)
        if value:
            hosts.append(str(value))
    for field in ["destination_ports", "ports"]:
        value = alert.get(field, [])
        if isinstance(value, list):
            ports.extend(str(port) for port in value)

    return Entities(
        ips=sorted(set(ips)),
        urls=sorted(set(urls)),
        domains=sorted(domain for domain in domains if domain),
        users=sorted(set(users)),
        hosts=sorted(set(hosts)),
        ports=sorted(set(ports)),
        timestamps=timestamps,
    )
