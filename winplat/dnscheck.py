"""DNS 检查薄层：fake-ip 生效检测、DoH 解析、DNS 出口探针。

按 docs/02-architecture.md §2.2：
- fake-ip：socket.getaddrinfo 解析 claude.ai，检查返回是否落在 fakeip_range
- DoH：https://1.1.1.1/dns-query?name=X&type=A（JSON，RFC 8484 语义）
- 出口探针：向 whoami.ds.akahelp.net 发 TXT 查询，`ns`/`ip` 串给出实际递归出口 IP
所有调用带超时，异常捕获后返回明确失败结构。
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import socket
import struct
from collections.abc import Iterable
from dataclasses import dataclass

import requests
import threading
import time

DOH_TIMEOUT_SEC = 15
DOH_URL = "https://1.1.1.1/dns-query"
GEO_TIMEOUT_SEC = 5
GEO_URL = "https://api.country.is/"
# /24 缓存（IPv4）：同段出口不重复查询（慢路径每 ~18s 一次，geo 服务
# 无鉴权/配额，但没必要打）。TTL 1h 平衡节点换段后的时效性。
_GEO_CACHE_TTL_SEC = 3600.0
# 失败负缓存（country=None）用短 TTL：瞬时故障不该被放大为最长 1h 的
# UNREACHABLE→确认窗升级阻断（P2-2）。
_GEO_FAIL_TTL_SEC = 60.0
_geo_cache: dict[str, tuple[float, str | None]] = {}
_geo_lock = threading.Lock()


def lookup_country(ip: str) -> str | None:
    """查询 IP 归属国（ISO 3166-1 alpha-2，如 'US'）。失败返回 None。

    按 /24（IPv6 按 /64）缓存 1 小时。requests 异常/非 200/解析失败
    一律 None——调用方按"无法确认"处理，绝不猜。
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    cache_key = str(
        ipaddress.ip_network(f"{addr}/{prefix}", strict=False).network_address)
    now = time.monotonic()
    with _geo_lock:
        hit = _geo_cache.get(cache_key)
        if hit is not None:
            ttl = _GEO_CACHE_TTL_SEC if hit[1] is not None else _GEO_FAIL_TTL_SEC
            if now - hit[0] < ttl:
                return hit[1]
    country: str | None = None
    try:
        resp = requests.get(GEO_URL + ip, timeout=GEO_TIMEOUT_SEC)
        resp.raise_for_status()
        data = resp.json()
        code = data.get("country")
        if isinstance(code, str) and len(code) == 2 and code.isalpha():
            country = code.upper()
    except Exception:
        country = None
    with _geo_lock:
        # 写入时顺带清理过期项（成功项 1h、失败项 60s 各自按 TTL 判定），
        # 避免 _geo_cache 只增不减。
        for key, (ts, val) in list(_geo_cache.items()):
            ttl = _GEO_CACHE_TTL_SEC if val is not None else _GEO_FAIL_TTL_SEC
            if now - ts >= ttl:
                del _geo_cache[key]
        _geo_cache[cache_key] = (now, country)
    return country


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


@dataclass(frozen=True)
class DnsEgressResult:
    """DNS 出口探针结果。

    ok=True 表示拿到 TXT 回答；ok=False 时 error 说明原因（超时/无回答）。
    egress_ip 为 whoami 递归出口 IP；TXT 正文不含可解析 IP 时为 None。
    """

    ok: bool
    egress_ip: str | None = None
    records: tuple[str, ...] = ()
    error: str | None = None


def getaddrinfo_a(hostname: str) -> tuple[str, ...]:
    """getaddrinfo 仅查 A 记录。纯解析辅助，可注入测试。

    不查 AAAA：fake-ip 判定是 IPv4 概念（198.18.0.0/15），AAAA 结果
    永不落在段内，纯浪费；且显式 AAAA 查询在 fake-ip 环境下会绕过
    mihomo 本地应答走上游递归，用户网络实测单发 stall 8-11s（慢轮
    间隔 17.5s 的隐藏成本）。"""
    results: list[str] = []
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
    except socket.gaierror:
        return ()
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
        resolver = getaddrinfo_a
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


# ---- DNS 出口探针（检查⑤）------------------------------------------------
# 选型说明：不用 getaddrinfo（查不了 TXT）、不加 dnspython 依赖、
# 不用 nslookup 子进程（并发 tick 下进程开销 + 文本解析脆弱）。
# 用 Windows 自带 dnsapi.dll 的 DnsQuery_A 查 TXT：零依赖、
# 超时由 resolver 自身控制；查询走系统 resolver，TUN 模式下 UDP 53
# 出站被 mihomo 截获，与 echo 探测同一条路由，阻断态下依然可达
# （fail-closed 不死锁）。

DNS_TYPE_TXT = 16
DNS_RECORD_FREE_TYPE = 0  # DnsRecordListFree 的 FreeType（DnsFreeRecordList）

# 实测（x64 dnsapi）：DNS_RECORD 的 Data 联合从头部第 32 字节开始；TXT 分支为
# DNS_TXT_DATAA { DWORD dwStringCount; PSTR pStringArray[]; }——pStringArray 是
# 内联的指针柔性数组（紧跟在 StringCount 后，无中间指针），不是指向指针数组的
# 指针。字符串本体为 NUL 结尾的窄字符（ANSI，akahelp 的 ns/ip 均为 ASCII）。
# 因此这里用 DnsQuery_A + 手工按 8 字节读指针（头 4 字节 StringCount、第 4-8
# 字节是填充）。
_TXT_HEADER_SIZE = 32
_STRINGCOUNT_OFFSET = 0
_STRINGARRAY_OFFSET = 8
# _DnsRecordHead.Data 拷贝的字节数上限
_TXT_DATA_SIZE = 64


class _DnsRecordHead(ctypes.Structure):
    """DNS_RECORDA 头部（不含 Data 联合，按字节偏移手工读 TXT 数据）。"""
    _fields_ = [
        ("pNext", ctypes.c_void_p),
        ("pName", ctypes.c_char_p),
        ("wType", ctypes.c_uint16),
        ("wDataLength", ctypes.c_uint16),
        ("Flags", ctypes.c_uint32),
        ("dwTtl", ctypes.c_uint32),
        ("dwReserved", ctypes.c_uint32),
        ("Data", ctypes.c_ubyte * 64),
    ]


def parse_txt_records(texts: Iterable[str]) -> tuple[str, ...]:
    """把 TXT 字符串数组去引号/空白后归并为 record 元组。纯函数，可离线测试。"""
    cleaned = []
    for t in texts:
        if t is None:
            continue
        s = t.strip().strip('"').strip("'").strip()
        if s:
            cleaned.append(s)
    return tuple(cleaned)


def parse_egress_ip(records: Iterable[str]) -> str | None:
    """从 whoami TXT 正文提取递归出口 IP。

    akahelp 格式：一条 record 形如 ``ns`` + ``198.51.100.20``（两串），
    也可能合并为 ``ns 1.2.3.4`` 或只有 ``1.2.3.4``。取第一个可解析的 IPv4/IPv6。
    纯函数，可离线测试（含乱码/无 IP 样本）。
    """
    for rec in records:
        for token in rec.replace(",", " ").replace(";", " ").split():
            try:
                ipaddress.ip_address(token)
                return token
            except ValueError:
                continue
    return None


def parse_ecs_cidr(records: Iterable[str]) -> str | None:
    """提取 ECS（EDNS Client Subnet）网段——威胁模型的核心证据字段。

    akahelp whoami 的 ecs record 形如 ``203.0.113.0/24/24``（网段/前缀/作用域，
    取第一段为 CIDR）。这是"权威 DNS 能看到的客户端网段"：真实链路下等于
    本地真实网段（泄漏），走代理时等于代理出口网段（干净）。纯函数可离线测试。
    """
    for rec in records:
        for token in rec.replace(",", " ").replace(";", " ").split():
            low = token.lower()
            if not (low.endswith("/24") or "/24/" in low or low.count("/") == 2):
                continue
            cidr = token.split("/")[0] + "/" + token.split("/")[1]
            try:
                ipaddress.ip_network(cidr, strict=False)
                return cidr
            except ValueError:
                continue
    return None


def _read_string_array(data: bytes, count: int) -> list[str]:
    """从 DNS_TXT_DATAA 原始字节读内联指针数组指向的 NUL 结尾窄字符串。

    count 由调用方保证不越界：Data 联合只拷贝 64 字节（实际为 wDataLength），
    每个 PSTR 指针占 8 字节，data 区从偏移 8 开始，故最多可读
    (64 - 8) // 8 = 7 个指针。TXT 记录字段语义上单 record 的字符串数
    远小于 7（akahelp 的 ns/ip/ecs 每条 1-3 串），超出视为异常响应
    截断处理，绝不 unpack_from 越界读（P3-3）。
    """
    texts: list[str] = []
    for i in range(count):
        (addr,) = struct.unpack_from("<Q", data, _STRINGARRAY_OFFSET + 8 * i)
        if addr:
            texts.append(ctypes.string_at(addr).decode("utf-8", "replace"))
    return texts


def query_txt_windows(hostname: str) -> DnsEgressResult:
    """通过 Windows dnsapi 的 DnsQuery_A 查询 TXT 记录（走系统 resolver）。

    阻断态下系统 resolver 的 UDP 53 出站仍被 mihomo TUN 截获（实测），
    因此探测路径与 echo 同路由，不会死锁。
    """
    if not hostname or not hostname.strip():
        return DnsEgressResult(ok=False, error="empty hostname")

    try:
        dnsapi = ctypes.WinDLL("dnsapi.dll", use_last_error=True)
    except OSError as exc:
        return DnsEgressResult(ok=False, error=f"load dnsapi: {exc}")

    results_ptr = ctypes.c_void_p()
    status = dnsapi.DnsQuery_A(
        ctypes.c_char_p(hostname.encode("idna")),
        ctypes.c_uint16(DNS_TYPE_TXT),
        ctypes.c_uint32(0),          # 默认：走 resolver，含缓存
        ctypes.c_void_p(),           # pServers: None → 用系统配置
        ctypes.byref(results_ptr),
        ctypes.c_void_p(),           # pReserved
    )
    if status != 0:
        return DnsEgressResult(ok=False, error=f"DnsQuery_A status={status}")

    texts: list[str] = []
    try:
        p = results_ptr.value
        while p:
            rec = ctypes.cast(p, ctypes.POINTER(_DnsRecordHead)).contents
            if rec.wType == DNS_TYPE_TXT:
                data = bytes(rec.Data)
                (count,) = struct.unpack_from("<I", data, _STRINGCOUNT_OFFSET)
                # P3-3：Data 只拷 64 字节，偏移 8 起每指针 8 字节 → 至多 7 个；
                # 超出的 count 一律按 7 截断，防止 unpack_from 越界 struct.error。
                count = min(count, (_TXT_DATA_SIZE - _STRINGARRAY_OFFSET) // 8)
                if 0 < count:
                    texts.extend(_read_string_array(data, count))
            p = rec.pNext
    finally:
        dnsapi.DnsRecordListFree(results_ptr, DNS_RECORD_FREE_TYPE)

    records = parse_txt_records(texts)
    if not records:
        return DnsEgressResult(ok=False, records=(), error="no TXT records parsed")
    return DnsEgressResult(ok=True, egress_ip=parse_egress_ip(records), records=records)


def check_dns_egress(domain: str, whitelist: list[str],
                     allowed_countries: list[str] | None = None,
                     ) -> tuple[str, DnsEgressResult]:
    """DNS 出口探针（检查⑤）：whoami TXT → ECS/出口 → 三分类。

    判定链（按优先级）：
    1. ECS/出口网段 ∈ whitelist 精确段 → CLEAN（逃生口：用户钉死特定
       段，如 ISP 段；国家判定的补充而非替代）
    2. ECS（无则递归出口 IP）归属国 ∈ allowed_countries → CLEAN。
       核心：DNS 链路走代理 → 出口在代理落地国；真实家宽段（CN）
       不在允许列表 → DIRTY。换同国节点免改配置。
    3. geo 查询失败 → UNREACHABLE（"暂时无法确认"，不误拦不假放）
    4. 无 ECS 且无出口 IP → DIRTY（fail-closed）
    allowed_countries 为空/None 时跳过判定2（仅段白名单）。
    返回 (verdict, probe)；UNREACHABLE = 探测失败，不劫持门禁。
    verdict 与 policy.CLEAN/DIRTY/UNREACHABLE 常量一致。
    """
    probe = query_txt_windows(domain)
    if not probe.ok:
        return "UNREACHABLE", probe
    wl_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in whitelist or []:
        try:
            wl_nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue

    # 判定依据：ECS 网段优先（权威 DNS 实际收到的客户端网段），
    # 无 ECS（Cloudflare 递归默认不带）回退递归出口 IP。
    ecs = parse_ecs_cidr(probe.records)
    target_net = None
    if ecs is not None:
        try:
            target_net = ipaddress.ip_network(ecs, strict=False)
        except ValueError:
            target_net = None
    if target_net is None and probe.egress_ip is None:
        return "DIRTY", probe  # 无任何证据：fail-closed

    # 判定1：精确段白名单（ECS 网段或回退出口 IP 直配）
    if target_net is not None:
        for net in wl_nets:
            if target_net.version != net.version:
                continue
            if target_net == net or target_net.subnet_of(net):
                return "CLEAN", probe
    elif probe.egress_ip is not None:
        try:
            addr = ipaddress.ip_address(probe.egress_ip)
        except ValueError:
            addr = None
        if addr is not None:
            for net in wl_nets:
                if addr.version == net.version and addr in net:
                    return "CLEAN", probe

    # 判定2：归属国（geo_ip 取 ECS 网段首地址，或回退出口 IP）
    if allowed_countries:
        geo_ip = (str(target_net.network_address) if target_net is not None
                  else probe.egress_ip)
        country = lookup_country(geo_ip)
        if country is None:
            return "UNREACHABLE", probe  # geo 失败：无法确认
        if country.upper() in {c.upper() for c in allowed_countries}:
            return "CLEAN", probe
        return "DIRTY", probe

    # 无国家配置且段白名单未命中：fail-closed
    return "DIRTY", probe


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

    print("\n=== DNS 出口探针 ===")
    probe_domain = cfg.get("dns_probe_domain", "whoami.ds.akahelp.net")
    verdict, r = check_dns_egress(probe_domain, cfg["whitelist"])
    print(f"{probe_domain}: verdict={verdict} egress_ip={r.egress_ip} records={r.records} error={r.error}")
