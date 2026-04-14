"""Subnet definitions and fast IP matching for MegaFon peering detection."""

from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Optional


# ---------------------------------------------------------------------------
# Полные списки подсетей провайдеров (MegaFon peering отмечены комментарием)
# ---------------------------------------------------------------------------

SELECTEL_SUBNETS = (
    "185.91.54.0/24,188.68.218.0/24,185.91.53.0/24,87.228.101.0/24,185.91.52.0/24,"
    "31.184.215.0/24,82.202.249.0/24,37.9.4.0/24,82.202.197.0/24,82.202.247.0/24,"
    "5.188.113.0/24,82.202.252.0/24,82.202.231.0/24,82.202.218.0/24,185.91.55.0/24,"
    "82.202.233.0/24,188.68.219.0/24,82.202.251.0/24,82.202.220.0/24,82.202.216.0/24,"
    "82.202.211.0/24,82.202.240.0/24,82.202.195.0/24,92.53.74.0/24,82.202.255.0/24,"
    "82.202.222.0/24,82.202.239.0/24,82.202.194.0/24,82.202.208.0/24,82.202.210.0/24,"
    "82.202.227.0/24,82.202.236.0/24,82.202.245.0/24,82.202.250.0/24,82.202.217.0/24,"
    "82.202.193.0/24,82.202.234.0/24,82.202.235.0/24,82.202.200.0/24,82.202.242.0/24,"
    "46.148.227.0/24,82.202.215.0/24,82.202.241.0/24,92.53.68.0/24,46.148.234.0/24,"
    "45.90.244.0/24,92.53.77.0/24,94.26.224.0/24,31.41.157.0/24,212.92.101.0/24,"
    "212.41.17.0/24,46.21.248.0/24,188.68.221.0/24,94.26.248.0/24,84.38.182.0/24,"
    "5.101.51.0/24,45.92.176.0/24,45.92.177.0/24,45.131.40.0/24,91.206.14.0/24,"
    "80.249.147.0/24,77.223.114.0/24,80.93.187.0/24,188.68.203.0/24,31.184.211.0/24,"
    "31.184.254.0/24,37.9.13.0/24,46.148.235.0/24,95.213.172.0/24,5.101.50.0/24,"
    "94.26.228.0/24,92.53.66.0/24,5.188.158.0/24,92.53.64.0/24,212.92.98.0/24,"
    "5.188.119.0/24,84.38.181.0/24,5.188.159.0/24,94.26.246.0/24,5.189.239.0/24,"
    "84.38.185.0/24,31.184.253.0/24,31.184.218.0/24,5.188.118.0/24,95.213.211.0/24,"
    "95.213.204.0/24,185.151.243.0/24,188.68.222.0/24,77.244.217.0/24,"
    "95.213.236.0/24,5.188.56.0/24,92.53.90.0/24,95.213.158.0/24,"
    "80.249.145.0/24,80.249.146.0/24,46.182.24.0/24,95.213.195.0/24,89.248.192.0/24,"
    "89.248.193.0/24,5.178.85.0/24,81.163.22.0/24,81.163.23.0/24,5.188.114.0/24,"
    "82.202.206.0/24,82.202.244.0/24,82.202.207.0/24,5.188.115.0/24,82.202.230.0/24,"
    "82.202.225.0/24,109.71.12.0/24,109.71.13.0/24,5.188.112.0/24,82.202.199.0/24,"
    "82.202.224.0/24,82.202.228.0/24,82.202.254.0/24,82.202.237.0/24,82.202.198.0/24,"
    "82.202.223.0/24,82.202.248.0/24,82.202.238.0/24,82.202.202.0/24,82.202.219.0/24,"
    "82.202.243.0/24,82.202.205.0/24,82.202.213.0/24,82.202.253.0/24,82.202.209.0/24,"
    "82.202.192.0/24,82.202.214.0/24,82.202.212.0/24,82.202.201.0/24,82.202.196.0/24,"
    "82.202.246.0/24,82.202.226.0/24,82.202.204.0/24,82.202.221.0/24,80.93.181.0/24,"
    "45.130.11.0/24,92.53.91.0/24,87.242.108.0/24,82.202.203.0/24,95.213.232.0/24,"
    "95.213.167.0/24,78.155.192.0/24,80.93.182.0/24,77.244.215.0/24,31.172.128.0/24,"
    "92.53.78.0/24,185.143.174.0/24,"
    "31.133.42.0/24,"  # MegaFon peering
    "81.163.16.0/24,81.163.17.0/24,81.163.18.0/24,81.163.19.0/24"
)

TIMEWEB_SUBNETS = (
    "81.200.148.0/24,81.200.149.0/24,81.200.150.0/24,81.200.151.0/24,"
    "94.228.117.0/24,185.200.242.0/24,"
    "109.73.201.0/24"  # MegaFon peering
)

REGRU_SUBNETS = (
    "79.174.91.0/24,79.174.92.0/24,79.174.93.0/24,79.174.94.0/24,79.174.95.0/24,"
    "31.31.198.0/24,"  # MegaFon peering
    "37.140.192.0/24,37.140.193.0/24"
)

# Маппинг провайдер → строка подсетей
PROVIDER_SUBNETS: dict[str, str] = {
    "selectel": SELECTEL_SUBNETS,
    "timeweb": TIMEWEB_SUBNETS,
    "regru": REGRU_SUBNETS,
}


def parse_subnets(raw: str) -> set[IPv4Network]:
    """Parse comma-separated CIDR string into a set of IPv4Network objects.

    Args:
        raw: Comma-separated CIDR notation string, e.g. "10.0.0.0/24,192.168.1.0/24"

    Returns:
        Set of IPv4Network objects.
    """
    result: set[IPv4Network] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if chunk:
            result.add(ip_network(chunk, strict=False))
    return result


def _build_lookup(
    subnet_set: set[IPv4Network],
) -> tuple[set[IPv4Network], list[IPv4Network]]:
    """Split subnets into /24 hash-set and non-/24 fallback list.

    Returns:
        Tuple of (set of /24 networks for O(1) lookup, list of non-/24 networks).
    """
    fast: set[IPv4Network] = set()
    slow: list[IPv4Network] = []
    for net in subnet_set:
        if net.prefixlen == 24:
            fast.add(net)
        else:
            slow.append(net)
    return fast, slow


# Кэш разделённых структур по frozenset содержимого
_cache: dict[frozenset, tuple[set[IPv4Network], list[IPv4Network]]] = {}


def fast_match(ip_str: str, subnet_set: set[IPv4Network]) -> Optional[str]:
    """Check if ip_str belongs to any subnet in the set using fast O(1) lookup.

    Algorithm:
        1. Compute the /24 network containing the IP and check the hash set (O(1)).
        2. Fallback: iterate only non-/24 subnets (usually very few).

    Args:
        ip_str: Dotted-quad IPv4 address string.
        subnet_set: Pre-parsed set of IPv4Network from parse_subnets().

    Returns:
        Matching subnet as string (e.g. "31.133.42.0/24") or None.
    """
    cache_key = frozenset(subnet_set)
    if cache_key not in _cache:
        _cache[cache_key] = _build_lookup(subnet_set)
    fast_set, slow_list = _cache[cache_key]

    try:
        addr = IPv4Address(ip_str)
    except ValueError:
        return None

    # Быстрый путь: проверка /24
    candidate_24 = ip_network(f"{ip_str}/24", strict=False)
    if candidate_24 in fast_set:
        return str(candidate_24)

    # Медленный fallback для не-/24 подсетей
    for net in slow_list:
        if addr in net:
            return str(net)

    return None
