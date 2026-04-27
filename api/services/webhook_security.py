from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

BLOCKED_HOSTS = {"localhost", "localhost.localdomain"}
BLOCKED_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # cloud metadata services
    ipaddress.ip_address("100.100.100.200"),  # Alibaba metadata service
}


class UnsafeWebhookURLError(ValueError):
    pass


def _is_blocked_ip(address: ipaddress._BaseAddress) -> bool:
    return (
        address in BLOCKED_IPS
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def validate_webhook_url(webhook_url: str) -> str:
    parsed = urlsplit(webhook_url)
    if parsed.scheme != "https":
        raise UnsafeWebhookURLError("webhook_url must use https")
    if parsed.username or parsed.password:
        raise UnsafeWebhookURLError("webhook_url must not embed credentials")
    if not parsed.hostname or parsed.hostname.lower() in BLOCKED_HOSTS:
        raise UnsafeWebhookURLError("webhook_url host is not allowed")
    if parsed.port and parsed.port not in {443}:
        raise UnsafeWebhookURLError("webhook_url port is not allowed")

    try:
        literal_ip = ipaddress.ip_address(parsed.hostname)
        if _is_blocked_ip(literal_ip):
            raise UnsafeWebhookURLError("webhook_url host is not allowed")
    except ValueError:
        pass

    try:
        resolved = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeWebhookURLError("webhook_url host cannot be resolved") from exc

    for _, _, _, _, sockaddr in resolved:
        address = ipaddress.ip_address(sockaddr[0])
        if _is_blocked_ip(address):
            raise UnsafeWebhookURLError("webhook_url resolves to a blocked network")
    return webhook_url


def validate_webhook_redirect(location: str) -> None:
    raise UnsafeWebhookURLError(f"Webhook redirects are disabled; rejected redirect to {location[:120]}")
