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

    akahelp whoami 的 ecs record 形如 ``198.51.100.0/24/24``（网段/前缀/作用域，
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
    """从 DNS_TXT_DATAA 原始字节读内联指针数组指向的 NUL 结尾窄字符串。"""
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
                if 0 < count < 64:
                    texts.extend(_read_string_array(data, count))
            p = rec.pNext
    finally:
        dnsapi.DnsRecordListFree(results_ptr, DNS_RECORD_FREE_TYPE)

    records = parse_txt_records(texts)
    if not records:
        return DnsEgressResult(ok=False, records=(), error="no TXT records parsed")
    return DnsEgressResult(ok=True, egress_ip=parse_egress_ip(records), records=records)


def check_dns_egress(domain: str, whitelist: list[str]) -> tuple[str, DnsEgressResult]:
    """DNS 出口探针（检查⑤）：whoami TXT → ECS/出口 → 三分类。

    威胁模型（用户定义）：只关心 Anthropic 能否拿到真实网段，不在乎中间
    递归商（Google/Cloudflare/运营商）看到什么。因此判定依据按优先级：
    1. **ECS 网段**（权威 DNS 实际收到的客户端网段）∈ 白名单任一 IP 所在
       网段（/24 对 /24）→ CLEAN——递归出口是谁不重要，Anthropic 只能看到
       与你出口一致（或代理出口）的网段
    2. ECS 网段 = 白名单精确配置的 CIDR → CLEAN（允许用户直接配网段）
    3. 无 ECS 字段（Cloudflare 递归默认不带）→ 用递归出口 IP 判：∈ 白名单
       网段 → CLEAN，否则 DIRTY（fail-closed：看不到证据 ≠ 干净）
    返回 (verdict, probe)；UNREACHABLE = TXT 查询失败（第三方依赖不劫持门禁）。
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
    ecs = parse_ecs_cidr(probe.records)
    if ecs is not None:
        try:
            ecs_net = ipaddress.ip_network(ecs, strict=False)
        except ValueError:
            ecs_net = None
        if ecs_net is not None:
            # 判定1/2：ECS 网段与白名单网段的身份比对
            for net in wl_nets:
                if ecs_net == net:
                    return "CLEAN", probe
                if ecs_net.version != net.version:
                    continue
                # /24 比对：同出口网段
                if (ecs_net.supernet(new_prefix=min(24, ecs_net.prefixlen)) ==
                        net.supernet(new_prefix=min(24, net.prefixlen))):
                    return "CLEAN", probe
                # /16 归属比对：出口 IP 与 ECS 同属一个 ISP 前缀（实测：
                # 出口 203.0.113.x，ECS 报 198.51.100.0/24——同 Verizon 段
                # 但 /24 不同）。同 /16 = Anthropic 看到的仍是代理提供商
                # 网段而非本地运营商，无身份矛盾信号。
                try:
                    if (ecs_net.supernet(new_prefix=16) ==
                            net.supernet(new_prefix=16)):
                        return "CLEAN", probe
                except ValueError:
                    continue
    # 无 ECS：回退到递归出口 IP 判定（fail-closed）
    ip = probe.egress_ip
    if ip is None:
        return "DIRTY", probe
    for net in wl_nets:
        if ipaddress.ip_address(ip) in net:
            return "CLEAN", probe
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
