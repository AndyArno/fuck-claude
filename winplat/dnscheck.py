"""DNS 检查薄层：fake-ip 生效检测、DoH 解析。

按 docs/02-architecture.md §2.2：
- fake-ip：socket.getaddrinfo 解析 claude.ai，检查返回是否落在 fakeip_range
- DoH：https://1.1.1.1/dns-query?name=X&type=A（JSON，RFC 8484 语义）
所有调用带超时，异常捕获后返回明确失败结构。
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass

import requests

DOH_TIMEOUT_SEC = 15
DOH_URL = "https://1.1.1.1/dns-query"


@dataclass(frozen=True)
class FakeIpResult:
    """fake-ip 生效检测结果。ok=False 时 error 说明原因。"""

    ok: bool
    resolved_ips: tuple[str, ...]
    in_fakeip_range: bool
    error: str | None = None


@dataclass(frozen=True)
class DohResult:
    """DoH 解析结果。ok=False 时 addresses 为空、error 说明原因。"""

    ok: bool
    addresses: tuple[str, ...]
    error: str | None = None


def getaddrinfo_ips(hostname: str) -> tuple[str, ...]:
    """getaddrinfo 解析主机名的全部唯一 IP（A+AAAA）。纯解析辅助，可注入测试。"""
    results: list[str] = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(hostname, None, family)
        except socket.gaierror:
            continue
        for info in infos:
            results.append(info[4][0])
    # 保序去重
    seen: set[str] = set()
    unique = []
    for ip in results:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return tuple(unique)


def check_fakeip(
    hostname: str,
    fakeip_range: str = "198.18.0.0/15",
    resolver=None,
) -> FakeIpResult:
    """检测 fake-ip 是否生效：解析结果任一落在 fakeip_range 内即算生效。

    resolver 可注入（默认 socket.getaddrinfo），便于离线测试。
    """
    try:
        net = ipaddress.ip_network(fakeip_range)
    except ValueError as exc:
        return FakeIpResult(ok=False, resolved_ips=(), in_fakeip_range=False, error=f"bad fakeip_range: {exc}")

    if resolver is None:
        resolver = getaddrinfo_ips
    try:
        ips = resolver(hostname)
    except OSError as exc:
        return FakeIpResult(ok=False, resolved_ips=(), in_fakeip_range=False, error=f"resolve failed: {exc}")

    if not ips:
        return FakeIpResult(ok=False, resolved_ips=(), in_fakeip_range=False, error="no addresses resolved")

    in_range = any(ipaddress.ip_address(ip) in net for ip in ips if _parseable(ip))
    return FakeIpResult(
        ok=True,
        resolved_ips=ips,
        in_fakeip_range=in_range,
    )


def _parseable(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def doh_resolve(hostname: str, record_type: str = "A", url: str = DOH_URL,
                timeout: float = DOH_TIMEOUT_SEC) -> DohResult:
    """通过 DoH（Cloudflare 1.1.1.1，JSON API）解析域名。

    请求符合规范：Accept: application/dns-json；type 为 A/AAAA。
    """
    headers = {
        "accept": "application/dns-json",
        # Cloudflare JSON API 要求可识别的 UA（RFC 8484 本身不强制 UA，
        # 1.1.1.1 文档要求非浏览器客户端提供 UA 以便联系）
        "user-agent": "claude-guard/1.0 (+https://github.com/local)",
    }
    try:
        resp = requests.get(
            url,
            params={"name": hostname, "type": record_type},
            headers=headers,
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
        return DohResult(ok=False, addresses=(), error=f"{url}: {exc}")

    if payload.get("Status") != 0:
        status = payload.get("Status")
        return DohResult(ok=False, addresses=(), error=f"dns status={status}")

    addresses = tuple(
        answer["data"]
        for answer in payload.get("Answer", [])
        if answer.get("type") in (1, 28) and _parseable(answer.get("data", ""))
    )
    if not addresses:
        return DohResult(ok=False, addresses=(), error="no A/AAAA answers")
    return DohResult(ok=True, addresses=addresses)


if __name__ == "__main__":
    with open("config.json", encoding="utf-8") as f:
        cfg = json.load(f)

    domain = cfg["claude_domains"][0]
    print("=== fake-ip 生效检测 ===")
    result = check_fakeip(domain, cfg["fakeip_range"])
    print(f"domain={domain}  ok={result.ok}  in_range={result.in_fakeip_range}  ips={result.resolved_ips}")
    if result.error:
        print(f"error={result.error}")

    print("\n=== DoH 解析 ===")
    for d in cfg["claude_domains"]:
        r = doh_resolve(d)
        print(f"{d}: ok={r.ok} addresses={r.addresses} error={r.error}")
