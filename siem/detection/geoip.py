"""
Lightweight, fully-offline GeoIP lookup used for the "impossible travel"
detection rule.

NOTE (portfolio disclosure): this ships a small static table of sample IP
ranges so the project runs anywhere with zero external dependencies or API
keys. In a production deployment this module would be swapped for a real
GeoIP database (MaxMind GeoLite2/GeoIP2, ipinfo.io, or an internal IPAM/geo
feed) behind the exact same `locate(ip) -> GeoPoint` interface -- nothing
downstream (the rule engine) needs to change.
"""
from dataclasses import dataclass
from math import radians, sin, cos, sqrt, atan2
from typing import Optional
import ipaddress

EARTH_RADIUS_KM = 6371.0


@dataclass
class GeoPoint:
    ip: str
    country: str
    city: str
    lat: float
    lon: float


# Sample static "geo feed" -- CIDR -> location. Enough ranges to make the
# bundled sample logs (see scripts/generate_sample_logs.py) resolve to
# realistic, geographically distant points for the demo scenarios.
_GEO_TABLE = [
    ("10.0.0.0/8", GeoPoint("10.0.0.0/8", "US", "Baltimore (Corporate HQ)", 39.2904, -76.6122)),
    ("192.168.0.0/16", GeoPoint("192.168.0.0/16", "US", "Baltimore (Corporate HQ)", 39.2904, -76.6122)),
    ("203.0.113.0/24", GeoPoint("203.0.113.0/24", "RU", "Moscow", 55.7558, 37.6173)),
    ("198.51.100.0/24", GeoPoint("198.51.100.0/24", "CN", "Beijing", 39.9042, 116.4074)),
    ("185.220.101.0/24", GeoPoint("185.220.101.0/24", "DE", "Frankfurt (Known Tor Exit)", 50.1109, 8.6821),),
    ("45.155.204.0/24", GeoPoint("45.155.204.0/24", "NL", "Amsterdam", 52.3676, 4.9041)),
    ("103.21.244.0/24", GeoPoint("103.21.244.0/24", "IN", "Mumbai", 19.0760, 72.8777)),
    ("172.16.0.0/12", GeoPoint("172.16.0.0/12", "US", "Baltimore (Corporate HQ)", 39.2904, -76.6122)),
]
_PARSED_TABLE = [(ipaddress.ip_network(cidr), point) for cidr, point in _GEO_TABLE]


def locate(ip: str) -> Optional[GeoPoint]:
    """Return the GeoPoint for an IP, or None if not in the sample table."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for network, point in _PARSED_TABLE:
        if addr in network:
            return point
    return None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points, in kilometers."""
    lat1, lon1, lat2, lon2 = map(radians, (lat1, lon1, lat2, lon2))
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return EARTH_RADIUS_KM * 2 * atan2(sqrt(a), sqrt(1 - a))


def implied_speed_kmh(p1: GeoPoint, p2: GeoPoint, seconds_between: float) -> float:
    """Speed required to travel between two GeoPoints in the given time."""
    if seconds_between <= 0:
        return float("inf")
    distance_km = haversine_km(p1.lat, p1.lon, p2.lat, p2.lon)
    hours = seconds_between / 3600
    return distance_km / hours if hours > 0 else float("inf")
