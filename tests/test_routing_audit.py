"""投递路径时钟审计（GET /messages/{id}/routing-audit）测试。

覆盖：Received 头物理序反转为投递序、from/by/with 子句解析、带时区
日期（数字/命名/夏令时偏移、跨时区 UTC 换算、小数秒）、相邻 hop
时钟倒退、相等时间不误报、缺时间 hop 不跨空洞比较、重复主机回环
（大小写/尾点/IPv6 方括号规范化）、坏头（无主机、坏日期、坏日历日、
不平衡括号）诊断不报错不改写、首个异常位置与稳定排序、根 Received
与封装报文内部头的作用域、404、确定性。
"""

import json

from conftest import make_multipart


# ---------------------------------------------------------------------------
# 构造辅助
# ---------------------------------------------------------------------------


def received(value: str) -> bytes:
    return f"Received: {value}\r\n".encode()


def mail_with_received(values: list[str], *, extra: bytes = b"") -> bytes:
    head = b"Subject: route\r\n" + extra
    for v in values:
        head += received(v)
    return head + b"\r\nbody\r\n"


def post(client, data: bytes) -> int:
    r = client.post("/messages", content=data)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def fetch(client, mid: int):
    return client.get(f"/messages/{mid}/routing-audit")


def received_values(payload: dict) -> list[tuple[str, str]]:
    return [(h["hop_index"], h["header_index"]) for h in payload["hops"]]


# ---------------------------------------------------------------------------
# 路径重建与子句解析
# ---------------------------------------------------------------------------


def test_empty_path_when_no_received_headers(client):
    mid = post(client, b"Subject: none\r\n\r\nbody\r\n")
    r = fetch(client, mid)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["received_count"] == 0
    assert body["hops"] == []
    assert body["anomalies"] == []
    assert body["diagnostics"] == []
    assert body["first_anomaly_at"] is None


def test_physical_order_reversed_to_delivery_order(client):
    # 信头自顶向下是最近一跳在前；投递序（hops）必须反转为最早在前。
    mid = post(
        client,
        mail_with_received(
            [
                "from a.example.com by final.example.net with ESMTP;"
                " Mon, 22 Sep 2026 12:00:00 +0000",  # 物理序 0 / 最后一跳
                "from origin.example.org by a.example.com with SMTP;"
                " Mon, 22 Sep 2026 11:00:00 +0000",  # 物理序 1 / 第一跳
            ]
        ),
    )
    body = fetch(client, mid).json()
    assert body["received_count"] == 2
    assert received_values(body) == [(0, 1), (1, 0)]
    first, last = body["hops"]
    assert first["from_host"] == "origin.example.org"
    assert first["by_host"] == "a.example.com"
    assert first["protocol"] == "smtp"
    assert last["host"] == "final.example.net"
    assert last["protocol"] == "esmtp"
    assert body["anomalies"] == []
    assert body["first_anomaly_at"] is None


def test_only_by_clause_is_valid(client):
    mid = post(
        client,
        mail_with_received(
            ["by solo.example.net (Postfix); Mon, 22 Sep 2026 10:00:00 +0000"]
        ),
    )
    body = fetch(client, mid).json()
    hop = body["hops"][0]
    assert hop["from_host"] is None
    assert hop["by_host"] == "solo.example.net"
    assert hop["host"] == "solo.example.net"
    assert hop["bad"] is False


def test_by_without_host_falls_back_to_from(client):
    mid = post(
        client,
        mail_with_received(
            ["from relay.example.net with LMTP; Mon, 22 Sep 2026 10:00:00 +0000"]
        ),
    )
    hop = fetch(client, mid).json()["hops"][0]
    assert hop["by_host"] is None
    assert hop["host"] == "relay.example.net"
    assert hop["protocol"] == "lmtp"


def test_named_timezone_and_offset_preserved(client):
    # EST（命名时区，-0500）与 +0200 各自的偏移必须保留在输出里。
    mid = post(
        client,
        mail_with_received(
            [
                "from b by c with SMTP; Mon, 22 Sep 2026 17:00:00 +0200",
                "from a by b with SMTP; Mon, 22 Sep 2026 10:00:00 EST",
            ]
        ),
    )
    hops = fetch(client, mid).json()["hops"]
    assert hops[0]["timestamp"] == "2026-09-22T10:00:00-05:00"
    assert hops[1]["timestamp"] == "2026-09-22T17:00:00+02:00"
    # 10:00 EST == 15:00 UTC，17:00 +0200 == 15:00 UTC，相等不误报倒退。
    assert fetch(client, mid).json()["anomalies"] == []


def test_fractional_seconds_accepted(client):
    mid = post(
        client,
        mail_with_received(
            ["by h.example.net; Mon, 22 Sep 2026 10:00:00.123456 +0000"]
        ),
    )
    hop = fetch(client, mid).json()["hops"][0]
    assert hop["timestamp"] == "2026-09-22T10:00:00.123456+00:00"


def test_parenthesized_clauses_and_comments_stripped(client):
    mid = post(
        client,
        mail_with_received(
            [
                "from (comment first) mail.example.com (helo=old)"
                " by relay.example.net (Postfix) with ESMTP (TLS)"
                "; Mon, 22 Sep 2026 10:00:00 +0000 (UTC)"
            ]
        ),
    )
    hop = fetch(client, mid).json()["hops"][0]
    assert hop["from_host"] == "mail.example.com"
    assert hop["by_host"] == "relay.example.net"
    assert hop["protocol"] == "esmtp"
    assert hop["timestamp"] == "2026-09-22T10:00:00+00:00"


def test_ipv6_brackets_kept_raw_but_normalized_for_loop(client):
    mid = post(
        client,
        mail_with_received(
            [
                "from src by [2001:db8::1];"
                " Mon, 22 Sep 2026 12:00:00 +0000",  # hop 1
                "from origin by [2001:db8::1];"
                " Mon, 22 Sep 2026 11:00:00 +0000",  # hop 0
            ]
        ),
    )
    body = fetch(client, mid).json()
    # 原始值保留方括号
    assert body["hops"][0]["by_host"] == "[2001:db8::1]"
    # 规范化键剥掉方括号用于回环比较
    loop = [a for a in body["anomalies"] if a["code"] == "HOST_LOOP"]
    assert len(loop) == 1
    assert loop[0]["hop_index"] == 1
    assert loop[0]["detail"]["host"] == "2001:db8::1"
    assert loop[0]["detail"]["first_hop_index"] == 0


def test_clause_word_boundaries_not_fooled_by_hostnames(client):
    # "fromage"/"byzantium"/"without" 之类的主机名片段不能误匹配子句。
    mid = post(
        client,
        mail_with_received(
            ["from fromage.example.com by byzantium.example.com"
             " withtout ignored; Mon, 22 Sep 2026 10:00:00 +0000"]
        ),
    )
    hop = fetch(client, mid).json()["hops"][0]
    assert hop["from_host"] == "fromage.example.com"
    assert hop["by_host"] == "byzantium.example.com"
    assert hop["protocol"] is None


# ---------------------------------------------------------------------------
# 时钟倒退
# ---------------------------------------------------------------------------


def test_clock_regression_detected_between_adjacent_hops(client):
    mid = post(
        client,
        mail_with_received(
            [
                "from b by c; Mon, 22 Sep 2026 10:00:00 +0000",
                "from a by b; Mon, 22 Sep 2026 11:00:00 +0000",
            ]
        ),
    )
    body = fetch(client, mid).json()
    regressions = [a for a in body["anomalies"]
                   if a["code"] == "CLOCK_REGRESSION"]
    assert len(regressions) == 1
    a = regressions[0]
    assert a["hop_index"] == 1  # 后一跳（投递序）时间反而更早
    assert a["header_index"] == 0
    assert a["detail"]["previous_hop_index"] == 0
    assert a["detail"]["seconds_delta"] == -3600.0
    assert body["first_anomaly_at"] == {
        "code": "CLOCK_REGRESSION",
        "hop_index": 1,
        "header_index": 0,
    }


def test_clock_regression_uses_utc_equality_across_zones(client):
    # 12:00 +0000 与 14:00 +0200 是同一 UTC 时刻：相等，不报错。
    mid = post(
        client,
        mail_with_received(
            [
                "from b by c; Mon, 22 Sep 2026 12:00:00 +0000",
                "from a by b; Mon, 22 Sep 2026 14:00:00 +0200",
            ]
        ),
    )
    assert fetch(client, mid).json()["anomalies"] == []


def test_missing_timestamp_hop_breaks_comparison_chain(client):
    # 中间 hop 无日期：不跨空洞比较；第三跳相对“缺时间”跳也不报。
    mid = post(
        client,
        mail_with_received(
            [
                "from b by c; Mon, 22 Sep 2026 10:00:00 +0000",  # hop 2
                "from a by b with SMTP",                         # hop 1 无日期
                "from origin by a; Mon, 22 Sep 2026 08:00:00 +0000",  # hop 0
            ]
        ),
    )
    body = fetch(client, mid).json()
    assert [h["timestamp"] is not None for h in body["hops"]] == [
        True, False, True
    ]
    assert [a["code"] for a in body["anomalies"]] == []


def test_old_style_header_without_date_is_not_bad(client):
    mid = post(client, mail_with_received(["from a by b with SMTP"]))
    body = fetch(client, mid).json()
    hop = body["hops"][0]
    assert hop["timestamp"] is None
    assert hop["timestamp_raw"] is None
    assert hop["bad"] is False
    assert body["diagnostics"] == []


# ---------------------------------------------------------------------------
# 主机回环
# ---------------------------------------------------------------------------


def test_host_loop_case_and_trailing_dot_insensitive(client):
    mid = post(
        client,
        mail_with_received(
            [
                "from x by Relay.Example.COM.; Mon, 22 Sep 2026 12:00:00 +0000",
                "from y by relay.example.com; Mon, 22 Sep 2026 11:00:00 +0000",
            ]
        ),
    )
    body = fetch(client, mid).json()
    loops = [a for a in body["anomalies"] if a["code"] == "HOST_LOOP"]
    assert len(loops) == 1
    assert loops[0]["hop_index"] == 1
    assert loops[0]["detail"] == {
        "host": "relay.example.com",
        "first_hop_index": 0,
    }


def test_from_host_participates_in_loop_when_by_missing(client):
    mid = post(
        client,
        mail_with_received(
            [
                # hop 1：by 缺失，身份回退 from
                "from same.example.net; Mon, 22 Sep 2026 12:00:00 +0000",
                # hop 0：同一身份主机最早出现
                "from y by same.example.net; Mon, 22 Sep 2026 11:00:00 +0000",
            ]
        ),
    )
    loops = [a for a in fetch(client, mid).json()["anomalies"]
             if a["code"] == "HOST_LOOP"]
    assert len(loops) == 1
    assert loops[0]["hop_index"] == 1
    assert loops[0]["detail"]["host"] == "same.example.net"


def test_non_repeating_hosts_have_no_loop(client):
    mid = post(
        client,
        mail_with_received(
            [
                "from b by c; Mon, 22 Sep 2026 12:00:00 +0000",
                "from a by b; Mon, 22 Sep 2026 11:00:00 +0000",
            ]
        ),
    )
    assert all(a["code"] != "HOST_LOOP"
               for a in fetch(client, mid).json()["anomalies"])


# ---------------------------------------------------------------------------
# 坏头诊断
# ---------------------------------------------------------------------------


def test_unparseable_date_header_listed_as_diagnostic(client):
    bad = "from a by b; sometime next week"
    mid = post(client, mail_with_received([bad]))
    body = fetch(client, mid).json()
    hop = body["hops"][0]
    assert hop["bad"] is True
    assert hop["timestamp"] is None
    assert body["diagnostics"] == [
        {
            "header_index": 0,
            "hop_index": 0,
            "reasons": ["INVALID_DATE"],
            "raw": bad,
        }
    ]
    codes = [a["code"] for a in body["anomalies"]]
    assert codes == ["UNPARSEABLE_HEADER"]
    assert body["first_anomaly_at"]["code"] == "UNPARSEABLE_HEADER"


def test_impossible_calendar_date_is_bad(client):
    mid = post(
        client,
        mail_with_received(["from a by b; Mon, 30 Feb 2026 10:00:00 +0000"])
    )
    diag = fetch(client, mid).json()["diagnostics"]
    assert diag[0]["reasons"] == ["INVALID_DATE"]


def test_header_without_any_host_is_bad(client):
    value = "junk header without clauses; Mon, 22 Sep 2026 10:00:00 +0000"
    mid = post(client, mail_with_received([value]))
    body = fetch(client, mid).json()
    assert body["hops"][0]["host"] is None
    assert body["diagnostics"][0]["reasons"] == ["NO_HOST"]


def test_no_host_and_bad_date_reasons_combined(client):
    mid = post(client, mail_with_received(["totally broken; not a date either"]))
    body = fetch(client, mid).json()
    diag = body["diagnostics"][0]
    assert set(diag["reasons"]) == {"NO_HOST", "INVALID_DATE"}
    assert diag["raw"] == "totally broken; not a date either"


def test_empty_received_value_is_diagnostic_not_422(client):
    mid = post(client, b"Subject: x\r\nReceived:\r\n\r\nbody\r\n")
    r = fetch(client, mid)
    assert r.status_code == 200
    diag = r.json()["diagnostics"]
    assert len(diag) == 1
    assert "NO_HOST" in diag[0]["reasons"]


def test_bad_header_does_not_rewrite_archive(client):
    bad_mail = mail_with_received(["from a by b; garbage date"])
    mid = post(client, bad_mail)
    before = client.get(f"/messages/{mid}/nodes/").json()
    fetch(client, mid)
    after = client.get(f"/messages/{mid}/nodes/").json()
    assert before == after
    # 归档头原样保留（值未被审计改写）。
    received = [h for h in after["node"]["headers"] if h[0] == "Received"]
    assert received == [["Received", "from a by b; garbage date"]]
    # 重复请求字节级稳定。
    r1 = fetch(client, mid).json()
    r2 = fetch(client, mid).json()
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)


def test_folded_header_is_unfolded_before_parsing(client):
    raw = (
        b"Subject: x\r\n"
        b"Received: from a.example.com\r\n"
        b"        by b.example.net with ESMTP\r\n"
        b"        ; Mon, 22 Sep 2026 10:00:00 +0000\r\n"
        b"\r\nbody\r\n"
    )
    mid = post(client, raw)
    body = fetch(client, mid).json()
    assert body["diagnostics"] == []
    hop = body["hops"][0]
    assert hop["from_host"] == "a.example.com"
    assert hop["by_host"] == "b.example.net"


# ---------------------------------------------------------------------------
# 异常排序与首个异常位置
# ---------------------------------------------------------------------------


def test_anomalies_sorted_by_hop_and_stable_within_hop(client):
    mid = post(
        client,
        mail_with_received(
            [
                # 物理序 0 → hop 2：主机与 hop 0 重复（回环）
                "from b by host.loop with SMTP; Mon, 22 Sep 2026 09:00:00 +0000",
                # 物理序 1 → hop 1：坏头（坏日期 + 有主机）
                "from a by b; not-a-date",
                # 物理序 2 → hop 0：主机 host.loop
                "from origin by host.loop; Mon, 22 Sep 2026 10:00:00 +0000",
            ]
        ),
    )
    body = fetch(client, mid).json()
    anomalies = [(a["code"], a["hop_index"]) for a in body["anomalies"]]
    # hop 1 的坏头在前；hop 2 上时钟倒退（09:00 早于坏头之前的可比时间——
    # hop 1 无有效时间会断链，故无倒退）与回环同跳时固定顺序。
    assert anomalies[0] == ("UNPARSEABLE_HEADER", 1)
    assert ("HOST_LOOP", 2) in anomalies
    assert body["first_anomaly_at"] == {
        "code": "UNPARSEABLE_HEADER",
        "hop_index": 1,
        "header_index": 1,
    }
    # 坏头断链：hop 0 → hop 2 不相邻比较，不报时钟倒退。
    assert all(code != "CLOCK_REGRESSION" for code, _ in anomalies)


def test_multiple_anomaly_types_on_same_hop_keep_fixed_order(client):
    # hop 2 同时命中时钟倒退（相邻 hop 1 时间更晚）与主机回环
    # （dup.example.com 最早在 hop 0）；坏头单独位于 hop 3，验证整体
    # 排序先按 hop，同 hop 内固定 UNPARSEABLE → REGRESSION → LOOP。
    mid = post(
        client,
        mail_with_received(
            [
                "garbage; not a date either",                 # hop 3 坏头
                "from mid by other.example.net with SMTP;"
                " Mon, 22 Sep 2026 06:00:00 +0000",           # hop 2 倒退+回环
                "from dup.example.com by other.example.net;"
                " Mon, 22 Sep 2026 09:00:00 +0000",           # hop 1
                "from origin by dup.example.com;"
                " Mon, 22 Sep 2026 08:00:00 +0000",           # hop 0
            ]
        ),
    )
    codes = [(a["code"], a["hop_index"])
             for a in fetch(client, mid).json()["anomalies"]]
    assert codes == [
        ("CLOCK_REGRESSION", 2),
        ("HOST_LOOP", 2),
        ("UNPARSEABLE_HEADER", 3),
    ]


def test_first_anomaly_is_earliest_by_hop_index(client):
    mid = post(
        client,
        mail_with_received(
            [
                "from b by c; Mon, 22 Sep 2026 10:00:00 +0000",  # hop 1 倒退
                "from a by b; Mon, 22 Sep 2026 11:00:00 +0000",  # hop 0
            ]
        ),
    )
    body = fetch(client, mid).json()
    assert body["first_anomaly_at"]["hop_index"] == 1


# ---------------------------------------------------------------------------
# 作用域、404、确定性
# ---------------------------------------------------------------------------


def test_only_root_message_received_headers_are_audited(client):
    # 外层根无 Received；封装报文内部的 Received 不算根路径。
    inner = (
        b"Received: from inner.a by inner.b;"
        b" Mon, 22 Sep 2026 10:00:00 +0000\r\n"
        b"Subject: inner\r\n\r\ninner body\r\n"
    )
    wrapper_head = (
        b"Subject: wrapper\r\n"
        b"Content-Type: message/rfc822\r\n\r\n"
    )
    mid = post(client, wrapper_head + inner)
    body = fetch(client, mid).json()
    assert body["received_count"] == 0
    assert body["hops"] == []


def test_root_received_ignores_inner_but_root_ones_kept(client):
    inner = (
        b"Received: from inner.a by inner.b;"
        b" Mon, 22 Sep 2026 10:00:00 +0000\r\n\r\nx\r\n"
    )
    multipart = make_multipart(
        [
            b"Content-Type: text/plain\r\n\r\nouter text",
            b"Content-Type: message/rfc822\r\n\r\n" + inner,
        ],
        boundary="MIX",
    )
    raw = (
        b"Subject: outer\r\n"
        b"Received: from root.a by root.b;"
        b" Mon, 22 Sep 2026 12:00:00 +0000\r\n"
        b'Content-Type: multipart/mixed; boundary="MIX"\r\n\r\n' + multipart
    )
    mid = post(client, raw)
    body = fetch(client, mid).json()
    assert body["received_count"] == 1
    assert body["hops"][0]["by_host"] == "root.b"


def test_missing_message_returns_404(client):
    r = fetch(client, 9999)
    assert r.status_code == 404
    assert "9999" in r.json()["detail"]


def test_repeated_requests_byte_stable(client):
    mid = post(
        client,
        mail_with_received(
            [
                "from b by c; Mon, 22 Sep 2026 10:00:00 +0000",
                "from a by b; Mon, 22 Sep 2026 11:00:00 +0000",
            ]
        ),
    )
    r1 = fetch(client, mid).json()
    r2 = fetch(client, mid).json()
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)


# ---------------------------------------------------------------------------
# 解析单元测试
# ---------------------------------------------------------------------------


def test_parse_received_datetime_unit():
    from app.routing import parse_received_datetime

    assert parse_received_datetime("nonsense") is None
    assert parse_received_datetime("Mon, 31 Feb 2026 10:00:00 +0000") is None
    assert parse_received_datetime("Mon, 22 Sep 2026 25:00:00 +0000") is None
    assert parse_received_datetime("Mon, 22 Sep 2026 10:00:00 +9999") is None
    dt = parse_received_datetime("Tue, 22 Sep 26 10:00:00 GMT")
    assert dt is not None
    assert dt.year == 2026
    dt99 = parse_received_datetime("22 Sep 99 10:00:00 +0000")
    assert dt99 is not None and dt99.year == 1999


def test_normalize_host_unit():
    from app.routing import normalize_host

    assert normalize_host("RELAY.Example.COM.") == "relay.example.com"
    assert normalize_host("[IPv6:2001:db8::1]") == "ipv6:2001:db8::1"
    assert normalize_host("  h.x  ") == "h.x"
