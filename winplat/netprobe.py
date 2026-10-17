"""网络探测薄层：echo 双端点探测、mihomo 进程检测、TUN 网卡检测。

按 docs/02-architecture.md §2.2：所有网络调用带超时，异常捕获后
返回明确的失败结构，调用方无需 try/except。
"""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import psutil
import requests

# B-7：慢路径 echo 探测运行在 tick 内，端点不可达时超时直接决定慢轮
# 耗时上限。双端点并发（probe_echo_endpoints 线程池）后 wall time ≈
# 单个 timeout 而非 2×（坏网络实测 ~6s → ~3s）。DIRTY 判定仍基于本轮
# 最新探测结果。
ECHO_TIMEOUT_SEC = 3

# 备端点：纯文本 IP
IPSB_URL = "https://api.ip.sb/ip"

_ECHO_USER_AGENT = "claude-guard/1.0 (+https://github.com/local)"


@dataclass(frozen=True)
class EchoResult:
    """echo 探测结果。ok=False 时 endpoint 为 None，error 说明原因。"""

    ok: bool
    ip: str | None
    endpoint: str | None
    error: str | None = None


@dataclass(frozen=True)
class LocalEnvResult:
    """mihomo 进程 + TUN 网卡检测结果。"""

    mihomo_running: bool
    tun_present: bool
    tun_name: str | None = None
    error: str | None = None


def parse_trace_ip(text: str) -> str | None:
    """从 Cloudflare trace 文本解析 `ip=` 行，返回 IP 字符串。

    离线纯函数，便于单测。格式：
        ip=203.0.113.7
    """
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("ip="):
            value = line[len("ip="):].strip()
            if value:
                return value
    return None


def parse_ip_sb(text: str) -> str | None:
    """从 api.ip.sb/ip 纯文本响应解析 IP（容忍首尾空白/换行）。

    离线纯函数，便于单测。
    """
    value = text.strip()
    if not value:
        return None
    # 响应应为单个 IP；多行/多余内容视为无效
    if "\n" in value:
        return None
    return value


def _looks_like_ip(text: str | None) -> bool:
    """校验解析结果是否为合法 IPv4/IPv6 字面量。"""
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _probe_one(url: str, timeout: float) -> EchoResult:
    """探测单个 echo 端点（任何异常都吞进 EchoResult，供线程池安全使用）。

    按路径特征分发：任何 /cdn-cgi/trace 端点（cloudflare.com、
    chatgpt.com、api.openai.com 等 CF 代理域）都用 trace 解析。
    分发前剥 query/fragment 并 lower（P3-4）。"""
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": _ECHO_USER_AGENT})
        resp.raise_for_status()
    except requests.RequestException as exc:
        return EchoResult(ok=False, ip=None, endpoint=None, error=f"{url}: {exc}")
    except Exception as exc:  # 防御：解析期异常不炸线程池
        return EchoResult(ok=False, ip=None, endpoint=None, error=f"{url}: {exc}")

    path = url.split("://", 1)[-1].split("?", 1)[0].split("#", 1)[0].rstrip("/").lower()
    if path.endswith("/cdn-cgi/trace"):
        ip = parse_trace_ip(resp.text)
        parser_name = "trace"
    else:
        ip = parse_ip_sb(resp.text)
        parser_name = "text"

    if not _looks_like_ip(ip):
        return EchoResult(ok=False, ip=None, endpoint=None,
                          error=f"{url}: unparseable response ({parser_name})")
    return EchoResult(ok=True, ip=ip, endpoint=url)


def probe_echo_endpoints(endpoints: list[str], timeout: float = ECHO_TIMEOUT_SEC) -> EchoResult:
    """并发探测 echo 端点，按列表顺序取第一个可用结果。

    主备语义保持（列表顺序优先），但不再串行等待：主端点超时期间备端点
    同时在跑，wall time = 最慢端点而非总和（双端点各 3s 超时场景
    ~6s → ~3s）。全部失败时 error 汇总各端点原因。"""
    if not endpoints:
        return EchoResult(ok=False, ip=None, endpoint=None,
                          error="no endpoints configured")
    if len(endpoints) == 1:
        return _probe_one(endpoints[0], timeout)
    with ThreadPoolExecutor(max_workers=len(endpoints),
                            thread_name_prefix="echo-probe") as ex:
        results = list(ex.map(lambda u: _probe_one(u, timeout), endpoints))
    for res in results:  # ex.map 保序 → 列表顺序优先
        if res.ok:
            return res
    return EchoResult(ok=False, ip=None, endpoint=None,
                      error="; ".join(r.error or "?" for r in results))


def check_mihomo_process(process_name: str) -> bool:
    """按进程名（不区分大小写）检测 mihomo 是否在运行。"""
    if not process_name:
        return False
    target = process_name.lower()
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if name == target:
            return True
    return False


TUN_KEYWORDS_DEFAULT = ["mihomo", "clash", "utun", "verge"]


def check_tun_adapter(
    keywords: list[str] | None = None,
    fakeip_range: str = "198.18.0.0/15",
) -> tuple[bool, str | None]:
    """检测 TUN 虚拟网卡是否存在。

    匹配规则（任一命中即认为存在）：
    1. 网卡名称含关键词（默认 mihomo/clash/utun/verge）
    2. 网卡绑定了 fake-ip 段（198.18.0.0/15）内的地址
    返回 (present, matched_name)。
    """
    keywords = [k.lower() for k in (keywords if keywords is not None else TUN_KEYWORDS_DEFAULT)]
    try:
        fakeip_net = ipaddress.ip_network(fakeip_range)
    except ValueError:
        fakeip_net = None

    try:
        addrs = psutil.net_if_addrs()
    except Exception:  # pragma: no cover - psutil 内部错误防御
        return False, None

    for ifname, if_addrs in addrs.items():
        lowered = ifname.lower()
        if any(k in lowered for k in keywords):
            return True, ifname
        if fakeip_net is not None:
            for addr in if_addrs:
                try:
                    ip = ipaddress.ip_address(addr.address)
                except ValueError:
                    continue
                if ip.version == fakeip_net.version and ip in fakeip_net:
                    return True, ifname
    return False, None


def check_local_env(config) -> LocalEnvResult:
    """快路径检查：mihomo 进程 + TUN 网卡（使用 config 中的配置字段）。"""
    process_name = getattr(config, "mihomo_process", "") or ""
    keywords = getattr(config, "tun_adapter_keywords", None) or TUN_KEYWORDS_DEFAULT
    fakeip_range = getattr(config, "fakeip_range", "198.18.0.0/15") or "198.18.0.0/15"

    mihomo_ok = check_mihomo_process(process_name)
    tun_ok, tun_name = check_tun_adapter(keywords, fakeip_range)
    return LocalEnvResult(
        mihomo_running=mihomo_ok,
        tun_present=tun_ok,
        tun_name=tun_name,
        error=None if (mihomo_ok and tun_ok) else "mihomo process or TUN adapter missing",
    )


if __name__ == "__main__":
    import json

    with open("config.json", encoding="utf-8") as f:
        cfg = json.load(f)

    print("=== echo 探测（双端点） ===")
    echo = probe_echo_endpoints(cfg["echo_endpoints"])
    if echo.ok:
        print(f"ok=True  ip={echo.ip}  endpoint={echo.endpoint}")
    else:
        print(f"ok=False error={echo.error}")

    print("\n=== mihomo 进程检测 ===")
    name = cfg["mihomo_process"]
    print(f"process={name}  running={check_mihomo_process(name)}")

    print("\n=== TUN 网卡检测 ===")
    tun_ok, tun_name = check_tun_adapter(cfg.get("tun_adapter_keywords"), cfg["fakeip_range"])
    print(f"present={tun_ok}  interface={tun_name}")
