"""投递路径时钟审计（``GET /messages/{id}/routing-audit``）。

在**已归档根邮件**（path 为 ``""`` 的节点）上只读解析全部 ``Received``
头（RFC 5322 §3.6.7），重建邮件的实际投递路径并做确定性异常检测。
本模块不接触附件库、不回写任何记录，对历史归档数据同样适用；同一封
邮件重复请求结果逐字节稳定。

``Received`` 头由**中继 MTA 在接收时逐跳追加到信头顶端**，因此信头中
的物理顺序（``header_index``，0 基、自顶向下）与实际投递方向相反：
本模块把物理顺序**反转**得到自底向上的 hop 列表（``hop_index``，
0 基，最早一跳在前）。

每个头按 RFC 语法从 ``from`` / ``by`` / ``with`` 子句解析**来源主机、
接收主机与协议**，并取最后一个 ``;`` 之后的 **RFC 5322 带时区日期**
（保留 MTA 本地偏移，比较时换算为 UTC 时刻）。圆括号注释（如
``(root@localhost)``）在子句提取前剥离。

检测三类异常（均在投递序 hop 列表上进行）：

* ``CLOCK_REGRESSION``——相邻两跳都带可解析时间时，后一跳的 UTC 时刻
  **早于**前一跳（严格小于；相等不误报）；
* ``HOST_LOOP``——本跳接收主机（``by``，缺省回退 ``from`` 的规范化
  键）与路径上**更早的某一跳重复**（小写、去尾点、去 IP 字面方括号），
  detail 给出最早重复位置；
* ``UNPARSEABLE_HEADER``——头中既提取不到任何主机，或 ``;`` 后日期
  存在但无法解析。完全没有日期的老式头不算坏头：hop 保留、
  ``timestamp`` 为 ``null`` 且不参与时钟比较。

坏头不产生 422、也不改写归档数据：对应 hop 仍列入路径，坏头原文与
原因进入响应的 ``diagnostics``。``anomalies`` 按 hop 序稳定排序
（同一 hop 内固定 UNPARSEABLE_HEADER → CLOCK_REGRESSION →
HOST_LOOP），``first_anomaly_at`` 取列表首项的位置。
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from .related import json_loads_headers

# ---------------------------------------------------------------------------
# 稳定异常码
# ---------------------------------------------------------------------------

CODE_CLOCK_REGRESSION = "CLOCK_REGRESSION"
CODE_HOST_LOOP = "HOST_LOOP"
CODE_UNPARSEABLE_HEADER = "UNPARSEABLE_HEADER"

# 诊断原因（diagnostics[].reasons，可多个）
REASON_NO_HOST = "NO_HOST"
REASON_INVALID_DATE = "INVALID_DATE"

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
# RFC 5322 §4.3 的（废弃）命名时区，单位：相对 UTC 的分钟。
_NAMED_ZONES = {
    "ut": 0, "gmt": 0, "z": 0,
    "est": -5 * 60, "edt": -4 * 60,
    "cst": -6 * 60, "cdt": -5 * 60,
    "mst": -7 * 60, "mdt": -6 * 60,
    "pst": -8 * 60, "pdt": -7 * 60,
}

# RFC 5322 date-time：[星期 ","] 日 月名 年 时:分[:秒[.小数]] 时区
_DATE_RE = re.compile(
    r"^\s*(?:[A-Za-z]{3,9}\s*,\s*)?"
    r"(\d{1,2})\s+([A-Za-z]{3})\s+(\d{2,4})\s+"
    r"(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,6}))?)?\s*"
    r"([+-]\d{4}|[A-Za-z]{1,5})\s*$"
)

# from / by / with 子句起始：行首或空白之后（不匹配注释内的 "(from"）。
_CLAUSE_FROM = re.compile(r"(?:(?<=^)|(?<=\s))from\s+(\S+)", re.IGNORECASE)
_CLAUSE_BY = re.compile(r"(?:(?<=^)|(?<=\s))by\s+(\S+)", re.IGNORECASE)
_CLAUSE_WITH = re.compile(r"(?:(?<=^)|(?<=\s))with\s+(\S+)", re.IGNORECASE)

# 句末标点（注释已整体剥离，故不含 ')'；']' 是 IP 字面量的一部分）。
_TOKEN_TRAILING = ".,;"


# ---------------------------------------------------------------------------
# 日期解析（保留原始偏移；比较时用 UTC）
# ---------------------------------------------------------------------------


def parse_received_datetime(value: str) -> Optional[datetime]:
    """解析 Received 头 ``;`` 后的 RFC 5322 日期，返回**带原始偏移**的
    timezone-aware datetime；任何不合法（含不存在的日历日）返回 None。

    两位年份按 RFC 5322 obs-year：00–49 → 2000s，50–99 → 1900s；
    命名时区按 §4.3 折算为固定偏移。秒可带 1..6 位小数。
    """

    m = _DATE_RE.match(value)
    if not m:
        return None
    day, month_name, year, hour, minute, second, frac, zone = m.groups()
    month = _MONTHS.get(month_name.lower())
    if month is None:
        return None
    y = int(year)
    if y < 100:
        y += 2000 if y < 50 else 1900
    if zone.startswith(("+", "-")):
        sign = 1 if zone[0] == "+" else -1
        offset = sign * (int(zone[1:3]) * 60 + int(zone[3:5]))
        if abs(offset) > 24 * 60:
            return None
    else:
        offset = _NAMED_ZONES.get(zone.lower())
        if offset is None:
            return None
    microsecond = int(frac.ljust(6, "0")) if frac else 0
    try:
        return datetime(
            y, month, int(day), int(hour), int(minute), int(second or 0),
            microsecond, tzinfo=timezone(timedelta(minutes=offset)),
        )
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# 主机 / 子句提取
# ---------------------------------------------------------------------------


def _strip_comments(text: str) -> str:
    """剥离 RFC 5322 圆括号注释（支持嵌套），注释替换为单个空格。

    圆括号不平衡时，未闭合的 ``(`` 之后全部按注释处理（真实 MTA 写出的
    头总是平衡的，这里只做审计容错）。
    """

    out: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            if depth > 0:
                depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def _clean_token(token: str) -> str:
    return token.rstrip(_TOKEN_TRAILING).strip()


def normalize_host(token: str) -> str:
    """主机比较键：去 IP 字面方括号、去根点、小写、压缩线性空白。"""

    host = token.strip()
    if len(host) >= 2 and host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".").strip().lower()
    return re.sub(r"\s+", "", host)


@dataclass(frozen=True)
class ParsedReceived:
    """单个 Received 头的解析结果（物理序：信头自顶向下）。"""

    header_index: int
    raw: str
    from_host: Optional[str]
    by_host: Optional[str]
    protocol: Optional[str]
    timestamp: Optional[datetime]  # 带原始偏移；无日期或坏日期为 None
    timestamp_raw: Optional[str]  # ';' 后的原始日期串
    reasons: tuple[str, ...]  # 解析问题（NO_HOST / INVALID_DATE）

    @property
    def host(self) -> Optional[str]:
        """本跳身份主机：优先 ``by``（追加该头的 MTA），回退 ``from``。"""

        token = self.by_host or self.from_host
        if token is None:
            return None
        key = normalize_host(token)
        return key or None

    @property
    def is_bad(self) -> bool:
        return bool(self.reasons)


def parse_received_header(value: str, header_index: int) -> ParsedReceived:
    """解析一个已去折叠的 Received 头值为结构化 hop 信息。

    日期取**最后一个** ``;`` 之后的内容（RFC 5322：日期必为末段子句，
    前置 from/by/with 等子句不含分号）；无分号视为老式无日期头。
    """

    reasons: list[str] = []

    # 圆括号注释在子句/日期提取前整体剥离（日期后允许出现 obs-comment，
    # 如 ``... -0500 (EST)``）。
    cleaned = _strip_comments(value)
    semi = cleaned.rfind(";")
    if semi >= 0:
        stub = cleaned[:semi]
        date_raw = cleaned[semi + 1:].strip()
        ts = parse_received_datetime(date_raw) if date_raw else None
        if ts is None:
            # 有分号但日期为空/损坏：明确的坏头。
            reasons.append(REASON_INVALID_DATE)
    else:
        stub = cleaned
        date_raw = None
        ts = None

    def first(pattern: re.Pattern[str]) -> Optional[str]:
        m = pattern.search(stub)
        if m is None:
            return None
        token = _clean_token(m.group(1))
        return token or None

    from_host = first(_CLAUSE_FROM)
    by_host = first(_CLAUSE_BY)
    protocol = first(_CLAUSE_WITH)
    if protocol is not None:
        protocol = protocol.lower()

    if from_host is None and by_host is None:
        reasons.append(REASON_NO_HOST)

    return ParsedReceived(
        header_index=header_index,
        raw=value,
        from_host=from_host,
        by_host=by_host,
        protocol=protocol,
        timestamp=ts,
        timestamp_raw=date_raw,
        reasons=tuple(reasons),
    )


# ---------------------------------------------------------------------------
# 审计结果数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoutingHop:
    """投递序中的一跳（``hop_index`` 0 基，最早一跳在前）。"""

    hop_index: int
    header_index: int  # 该头在信头中的物理序（自顶向下，0 基）
    from_host: Optional[str]
    by_host: Optional[str]
    host: Optional[str]  # 规范化身份主机（by 优先）
    protocol: Optional[str]
    timestamp: Optional[str]  # ISO 8601（保留 MTA 原始偏移）
    timestamp_raw: Optional[str]
    bad: bool


@dataclass(frozen=True)
class RoutingAnomaly:
    code: str  # UNPARSEABLE_HEADER | CLOCK_REGRESSION | HOST_LOOP
    hop_index: int
    header_index: int
    detail: dict


@dataclass(frozen=True)
class RoutingDiagnostic:
    """一个坏 Received 头的诊断（不改写归档数据，仅此处可见）。"""

    header_index: int
    hop_index: int
    reasons: list[str]
    raw: str


@dataclass
class RoutingAudit:
    hops: list[RoutingHop] = field(default_factory=list)
    anomalies: list[RoutingAnomaly] = field(default_factory=list)
    diagnostics: list[RoutingDiagnostic] = field(default_factory=list)
    first_anomaly: Optional[RoutingAnomaly] = None

    @property
    def received_count(self) -> int:
        return len(self.hops)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def _root_headers(rows: list[sqlite3.Row]) -> list[tuple[str, str]]:
    """取根节点（path == ''）的全部头；无根节点时返回空。"""

    for row in rows:
        if row["path"] == "":
            return json_loads_headers(row["headers_json"])
    return []


def audit_routing(rows: list[sqlite3.Row]) -> RoutingAudit:
    """在一封已归档邮件的节点行上执行投递路径审计（纯只读）。

    ``rows`` 为 :func:`database.list_nodes` 的结果。只读取根节点
    ``Received`` 头（``message/rfc822`` 封装报文内部的投递路径不属
    本邮件根路径，不参与审计）。
    """

    received_values = [
        value
        for name, value in _root_headers(rows)
        if name.lower() == "received"
    ]

    # 物理序（信头自顶向下：最近一跳在前）→ 投递序（最早一跳在前）。
    parsed = [
        parse_received_header(value, idx)
        for idx, value in enumerate(received_values)
    ]
    delivery_order = list(reversed(parsed))

    hops: list[RoutingHop] = []
    anomalies: list[RoutingAnomaly] = []
    diagnostics: list[RoutingDiagnostic] = []

    seen_hosts: dict[str, int] = {}
    prev_ts: Optional[datetime] = None  # 前一带时间 hop 的 UTC 时刻
    prev_dt: Optional[datetime] = None  # 同一 hop 的原始偏移时刻（展示用）
    prev_hop_index: Optional[int] = None
    prev_ts_raw: Optional[str] = None

    for hop_index, p in enumerate(delivery_order):
        hops.append(
            RoutingHop(
                hop_index=hop_index,
                header_index=p.header_index,
                from_host=p.from_host,
                by_host=p.by_host,
                host=p.host,
                protocol=p.protocol,
                timestamp=p.timestamp.isoformat() if p.timestamp else None,
                timestamp_raw=p.timestamp_raw,
                bad=p.is_bad,
            )
        )

        # 同一 hop 内固定检测顺序：坏头 → 时钟倒退 → 主机回环。
        if p.is_bad:
            anomalies.append(
                RoutingAnomaly(
                    code=CODE_UNPARSEABLE_HEADER,
                    hop_index=hop_index,
                    header_index=p.header_index,
                    detail={"reasons": list(p.reasons), "raw": p.raw},
                )
            )
            diagnostics.append(
                RoutingDiagnostic(
                    header_index=p.header_index,
                    hop_index=hop_index,
                    reasons=list(p.reasons),
                    raw=p.raw,
                )
            )

        if p.timestamp is not None:
            utc_now = p.timestamp.astimezone(timezone.utc)
            if prev_ts is not None and utc_now < prev_ts:
                anomalies.append(
                    RoutingAnomaly(
                        code=CODE_CLOCK_REGRESSION,
                        hop_index=hop_index,
                        header_index=p.header_index,
                        detail={
                            "previous_hop_index": prev_hop_index,
                            "previous_timestamp": prev_dt.isoformat(),
                            "previous_timestamp_raw": prev_ts_raw,
                            "timestamp": p.timestamp.isoformat(),
                            "timestamp_raw": p.timestamp_raw,
                            "seconds_delta": (utc_now - prev_ts).total_seconds(),
                        },
                    )
                )
            # 基准前进：只在相邻两跳都带时间时比较，缺时间 hop 使链条断裂。
            prev_ts = utc_now
            prev_dt = p.timestamp
            prev_hop_index = hop_index
            prev_ts_raw = p.timestamp_raw
        else:
            prev_ts = None
            prev_dt = None
            prev_hop_index = None
            prev_ts_raw = None

        if p.host is not None:
            if p.host in seen_hosts:
                anomalies.append(
                    RoutingAnomaly(
                        code=CODE_HOST_LOOP,
                        hop_index=hop_index,
                        header_index=p.header_index,
                        detail={
                            "host": p.host,
                            "first_hop_index": seen_hosts[p.host],
                        },
                    )
                )
            else:
                seen_hosts[p.host] = hop_index

    # diagnostics 按物理头序给出（“第几个 Received 头坏了”）。
    diagnostics.sort(key=lambda d: d.header_index)

    return RoutingAudit(
        hops=hops,
        anomalies=anomalies,
        diagnostics=diagnostics,
        first_anomaly=anomalies[0] if anomalies else None,
    )
