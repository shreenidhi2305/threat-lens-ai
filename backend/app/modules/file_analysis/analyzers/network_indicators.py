"""Embedded URL / IP / domain extraction for static analysis.

Pulls network indicators of compromise (IOCs) straight out of the file bytes.
Private / link-local / loopback IPs are dropped since they are not useful IOCs.
"""

import ipaddress
import re

_URL_RE = re.compile(rb'\b(?:https?|ftp)://[^\s"\'<>)\]}]{4,2048}', re.IGNORECASE)
_IPV4_RE = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DOMAIN_RE = re.compile(
    rb'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    rb'(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|us|uk|de|br|in)\b',
    re.IGNORECASE,
)
_MAX_PER_CATEGORY = 100


def _decode(values: set[bytes]) -> list[str]:
    return sorted({v.decode('utf-8', 'replace') for v in values})[:_MAX_PER_CATEGORY]


def _is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def extract_network_indicators(data: bytes) -> dict[str, list[str]]:
    urls = _decode(set(_URL_RE.findall(data)))
    ips = sorted({m.decode() for m in _IPV4_RE.findall(data) if _is_public_ip(m.decode())})[
        :_MAX_PER_CATEGORY
    ]

    url_hosts = {re.sub(r'^\w+://', '', u).split('/')[0].split(':')[0].lower() for u in urls}
    domains = sorted(
        {
            d.decode('utf-8', 'replace').lower()
            for d in _DOMAIN_RE.findall(data)
        }
        - url_hosts
    )[:_MAX_PER_CATEGORY]

    return {'urls': urls, 'ips': ips, 'domains': domains}
