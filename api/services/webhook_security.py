from __future__ import annotations

import json
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

BLOCKED_HOSTS = {"localhost", "localhost.localdomain"}
BLOCKED_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # cloud metadata services
    ipaddress.ip_address("100.100.100.200"),  # Alibaba metadata service
}


class UnsafeWebhookURLError(ValueError):
    pass


class WebhookDeliveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidatedWebhookEndpoint:
    original_url: str
    hostname: str
    host_header: str
    port: int
    address: str
    request_target: str


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
    prepare_webhook_endpoint(webhook_url)
    return webhook_url


def prepare_webhook_endpoint(webhook_url: str) -> ValidatedWebhookEndpoint:
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

    selected_address = None
    for _, _, _, _, sockaddr in resolved:
        address = ipaddress.ip_address(sockaddr[0])
        if _is_blocked_ip(address):
            raise UnsafeWebhookURLError("webhook_url resolves to a blocked network")
        selected_address = str(address)
    if selected_address is None:
        raise UnsafeWebhookURLError("webhook_url host cannot be resolved")

    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    return ValidatedWebhookEndpoint(
        original_url=webhook_url,
        hostname=parsed.hostname,
        host_header=parsed.netloc,
        port=parsed.port or 443,
        address=selected_address,
        request_target=request_target,
    )


def validate_webhook_redirect(location: str) -> None:
    raise UnsafeWebhookURLError(f"Webhook redirects are disabled; rejected redirect to {location[:120]}")


def post_validated_webhook(endpoint: ValidatedWebhookEndpoint, payload: dict, timeout: float = 10.0) -> int:
    body = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
    context = ssl.create_default_context()
    with socket.create_connection((endpoint.address, endpoint.port), timeout=timeout) as raw_socket:
        raw_socket.settimeout(timeout)
        with context.wrap_socket(raw_socket, server_hostname=endpoint.hostname) as tls_socket:
            request = "\r\n".join(
                [
                    f"POST {endpoint.request_target} HTTP/1.1",
                    f"Host: {endpoint.host_header}",
                    "User-Agent: CVEAgentNet-Webhook/1.0",
                    "Content-Type: application/json",
                    "Accept: application/json",
                    f"Content-Length: {len(body)}",
                    "Connection: close",
                    "",
                    "",
                ]
            ).encode("ascii")
            tls_socket.sendall(request + body)
            response = tls_socket.makefile("rb")
            status_line = response.readline(4096).decode("iso-8859-1", errors="replace").strip()
            parts = status_line.split()
            if len(parts) < 2 or not parts[1].isdigit():
                raise WebhookDeliveryError("Webhook response did not contain a valid HTTP status")
            status_code = int(parts[1])
            header_bytes = 0
            while True:
                line = response.readline(8192)
                header_bytes += len(line)
                if header_bytes > 65536:
                    raise WebhookDeliveryError("Webhook response headers exceeded 64 KiB")
                if line in {b"", b"\r\n", b"\n"}:
                    break
            if 300 <= status_code < 400:
                validate_webhook_redirect("")
            if status_code >= 400:
                raise WebhookDeliveryError(f"Webhook returned HTTP {status_code}")
            return status_code
