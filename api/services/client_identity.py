from __future__ import annotations

import ipaddress

from fastapi import Request

from api.config import get_settings


def _is_trusted_proxy(ip_value: str) -> bool:
    settings = get_settings()
    if not settings.trusted_proxy_cidr_list:
        return False
    try:
        address = ipaddress.ip_address(ip_value)
        return any(address in ipaddress.ip_network(cidr, strict=False) for cidr in settings.trusted_proxy_cidr_list)
    except ValueError:
        return False


def _first_forwarded_for(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if not forwarded_for:
        return None
    candidate = forwarded_for.split(",", 1)[0].strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def client_ip(request: Request) -> str:
    if request.client and request.client.host:
        if request.client.host == "testclient":
            return "127.0.0.1"
        if _is_trusted_proxy(request.client.host):
            forwarded_ip = _first_forwarded_for(request)
            if forwarded_ip:
                return forwarded_ip
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
