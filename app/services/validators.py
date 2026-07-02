from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def normalize_ioc(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def infer_supported_ioc_type(ioc: str) -> str:
    text = normalize_ioc(ioc)
    if not text:
        return ""

    parsed = urlparse(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"

    host, sep, port_text = text.rpartition(":")
    if sep and host and port_text.isdigit():
        try:
            ipaddress.ip_address(host)
            port = int(port_text)
            if 1 <= port <= 65535:
                return "ip_port"
        except ValueError:
            pass

    try:
        ipaddress.ip_address(text)
        return "unsupported_ip"
    except ValueError:
        pass

    if DOMAIN_RE.fullmatch(text):
        return "domain"
    return "unsupported"


def split_port(ioc: str) -> str:
    ioc_type = infer_supported_ioc_type(ioc)
    if ioc_type != "ip_port":
        return ""
    return ioc.rpartition(":")[2]
