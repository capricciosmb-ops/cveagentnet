from __future__ import annotations

import ipaddress

from fastapi import Request

from api.config import get_settings


def client_ip(request: Request) -> str:
    if request.client and request.client.host:
        if request.client.host == "testclient":
            return "127.0.0.1"
        return request.client.host
    return "unknown"


def client_subnet(ip_value: str) -> str:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return f"unknown:{ip_value}"
    if isinstance(address, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{address}/24", strict=False))
    return str(ipaddress.ip_network(f"{address}/64", strict=False))


def ip_rate_subject(request: Request, action: str) -> str:
    return f"ip:{client_ip(request)}:{action}"


def subnet_rate_subject(request: Request, action: str) -> str:
    return f"subnet:{client_subnet(client_ip(request))}:{action}"


def asn_rate_subject(request: Request, action: str) -> str | None:
    header_name = get_settings().edge_asn_header
    if not header_name:
        return None
    value = request.headers.get(header_name)
    if not value:
        return None
    safe_value = "".join(character for character in value if character.isalnum() or character in {"-", "_", "."})[:80]
    return f"asn:{safe_value}:{action}" if safe_value else None
