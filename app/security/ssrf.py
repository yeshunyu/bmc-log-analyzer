"""SSRF protection with short-TTL DNS cache (5 minutes).

Blocks DNS rebinding attacks by re-resolving the hostname at request time,
not just at config time. Caches resolved IPs with a 5-minute TTL.
"""
import ipaddress
import socket
import time
from typing import Optional

# Cache: {hostname: (resolved_ip, timestamp)}
_dns_cache: dict[str, tuple[str, float]] = {}
_DNS_CACHE_TTL = 300  # 5 minutes


def _is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address is private/reserved/multicast."""
    try:
        ip = ipaddress.ip_address(str(ip_str))
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
    except ValueError:
        return True  # Invalid IP should be blocked


def validate_ssrf(api_base: str) -> None:
    """Re-validate URL to prevent DNS rebinding attacks.

    Validates DNS resolution at request time (not just config time) to block
    DNS rebinding attacks where a domain initially resolves to a safe IP but
    later changes to an internal IP.

    Raises:
        ValueError: if the hostname resolves to a private/reserved IP.
    """
    if not api_base:
        return

    from urllib.parse import urlparse
    parsed = urlparse(api_base)
    hostname = parsed.hostname
    if not hostname:
        return

    now = time.time()
    # Check cache first
    if hostname in _dns_cache:
        cached_ip, cached_time = _dns_cache[hostname]
        if now - cached_time < _DNS_CACHE_TTL:
            if _is_ip_blocked(cached_ip):
                raise ValueError(f"api_base 域名解析到内网地址（DNS 缓存）: {hostname}→{cached_ip}")
            return

    # Re-resolve DNS and validate
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return
        # Check all resolved IPs
        for family, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            if _is_ip_blocked(ip):
                raise ValueError(f"api_base 域名解析到内网地址: {hostname}→{ip}")
        # Cache the first valid IP (prefer IPv4 for consistency)
        for family, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            if not _is_ip_blocked(ip):
                _dns_cache[hostname] = (ip, now)
                break
    except socket.gaierror:
        # DNS resolution failed — let the actual request fail with a clearer error
        pass


def clear_dns_cache() -> None:
    """Clear the DNS cache. Useful for testing."""
    _dns_cache.clear()
