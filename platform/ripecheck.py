"""RIPE 漂移数据查询薄层：AS399358 announced-prefixes。

按 docs/02-architecture.md §2.2：requests + 15s 超时，
异常捕获后返回明确失败结构。
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

RIPE_TIMEOUT_SEC = 15
RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
_RIPE_USER_AGENT = "claude-guard/1.0 (+https://github.com/local)"


@dataclass(frozen=True)
class RipeResult:
    """RIPE 查询结果。ok=False 时 prefixes 为空集、error 说明原因。"""

    ok: bool
    prefixes: frozenset[str] = field(default=frozenset())
    error: str | None = None


def parse_prefixes(payload: dict) -> frozenset[str]:
    """从 RIPE data.json 响应提取 announced 前缀集合（离线可测纯函数）。

    响应结构：{"data": {"prefixes": [{"prefix": "1.2.3.0/24", ...}, ...]}}
    """
    data = payload.get("data") or {}
    prefixes = set()
    for item in data.get("prefixes") or []:
        prefix = item.get("prefix") if isinstance(item, dict) else None
        if isinstance(prefix, str) and prefix:
            prefixes.add(prefix)
    return frozenset(prefixes)


def fetch_announced_prefixes(asn: str = "AS399358", url: str = RIPE_URL,
                             timeout: float = RIPE_TIMEOUT_SEC) -> RipeResult:
    """查询指定 ASN 的 announced 前缀集合。"""
    try:
        resp = requests.get(
            url,
            params={"resource": asn},
            headers={"User-Agent": _RIPE_USER_AGENT},
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        return RipeResult(ok=False, prefixes=frozenset(), error=f"{url}: {exc}")

    try:
        prefixes = parse_prefixes(payload)
    except (AttributeError, TypeError) as exc:
        return RipeResult(ok=False, prefixes=frozenset(), error=f"unexpected payload: {exc}")

    if not prefixes:
        return RipeResult(ok=False, prefixes=frozenset(), error="no announced prefixes returned")
    return RipeResult(ok=True, prefixes=prefixes)


if __name__ == "__main__":
    import json

    with open("config.json", encoding="utf-8") as f:
        cfg = json.load(f)

    print("=== RIPE announced-prefixes 查询 ===")
    asn = cfg["asn"]
    result = fetch_announced_prefixes(asn)
    if result.ok:
        print(f"asn={asn}  ok=True  prefixes={sorted(result.prefixes)}")
    else:
        print(f"asn={asn}  ok=False  error={result.error}")
