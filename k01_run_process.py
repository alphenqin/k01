# -*- coding: utf-8 -*-
"""
K01 自动研判脚本。

读取 input/input.xlsx，结合 xmon、文件情报、wfy 及已确认规则生成：
- output/result.xlsx
- output/数据分析.xlsx
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import random
import re
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Lock, local
from typing import Any
from urllib.parse import quote, urlparse

import pandas as pd
import requests
from requests import Session
from requests.adapters import HTTPAdapter


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "input")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
RESULT_FILE = os.getenv("K01_RESULT_FILE", os.path.join(OUTPUT_DIR, "result.xlsx"))
ANALYSIS_FILE = os.getenv("K01_ANALYSIS_FILE", os.path.join(OUTPUT_DIR, "数据分析.xlsx"))

VENDOR = "360"

# ===== xmon 配置 =====
XMON_BASE_URL = "http://xmon.netlab.qihoo.net/api/iocmon-search/ioc/"
XMON_QUERY = "?ui_simple=true&pretick=false&model=false&trace=true&keep_no=false&inspect=true&other_source=false"
XMON_TAGMON_BASE_URL = "http://xmon.netlab.qihoo.net/api/tagmon-search/ioc/"
XMON_TAGMON_SUFFIX = "/limit/1000/?data_only=true"
XMON_TOKEN = os.getenv("K01_XMON_TOKEN", "6189ff22-21c8-49ab-8519-7ef85f396954")
XMON_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-AuthToken": XMON_TOKEN,
    "Pragma": "no-cache",
    "Referer": "http://xmon.netlab.qihoo.net/ui/iocmon/",
    "User-Agent": "Mozilla/5.0",
    "X-Requested-With": "XMLHttpRequest",
}
XMON_COOKIE = os.getenv("K01_XMON_COOKIE", "")
if XMON_COOKIE:
    XMON_HEADERS["Cookie"] = XMON_COOKIE

# ===== 文件情报配置 =====
HASH_API_URL = os.getenv("K01_HASH_API_URL", "https://api.ti.360.cn/v2/file")
API_KEY = os.getenv("K01_TI_API_KEY", "8d5ae25afc18d812a51cc1048b7ef57d")
SALT = os.getenv("K01_TI_SALT", "fc05b3246ed550cc0da9748e7002d676")

# ===== wfy 配置 =====
WFY_API_URL = os.getenv("K01_WFY_API_URL", "http://api.netlab.360.com/wfy/reputation/v1")
WFY_HEADERS = {
    "Content-Type": "application/json",
    "X-AuthToken": XMON_TOKEN,
}

# ===== wd 配置 =====
WD_SAFE_API_URL = os.getenv("K01_WD_SAFE_API_URL", "http://api.safe.qihoo.net/urls/std/v1/cloud_safe_info")
WD_SAFE_APPID = os.getenv("K01_WD_SAFE_APPID", "8caf5d038722624364c0")
WD_SAFE_SECRET = os.getenv("K01_WD_SAFE_SECRET", "2efeec4e0c3d9649629663174c91d7f8f565a6c8")
WD_HISTORY_API_URL = os.getenv("K01_WD_HISTORY_API_URL", "http://api.netlab.qihoo.net/urldb/v0/detail/")
WD_HISTORY_TOKEN = os.getenv("K01_WD_HISTORY_TOKEN", "e65cf226-ed6e-4761-b0e7-7a091621afb8")
WD_HISTORY_START = os.getenv("K01_WD_HISTORY_START", "2020-05-29 00:00:00")

# ===== custom tags 配置（SC 接口）=====
TAGS_API_URL = os.getenv(
    "K01_TAGS_API_URL",
    "https://api.ti.360.net/custom/intelligence/v1/tags",
)
SC_DEFAULT_CATEGORY = "domain"

# ===== 智能体证据链配置 =====
AI_QUICK_ANALYSIS_URL = os.getenv("K01_AI_QUICK_ANALYSIS_URL", "http://api.netlab.qihoo.net/ai/quick-analysis")
AI_QUICK_ANALYSIS_HEADERS = {
    "Content-Type": "application/json",
    "X-AuthToken": XMON_TOKEN,
}

# ===== 性能控制配置 =====
# 这些配置直接改脚本即可，不依赖环境变量。
REQUEST_TIMEOUT = 60
HTTP_POOL_CONNECTIONS = 100
HTTP_POOL_MAXSIZE = 100
XMON_WORKERS = 24
XMON_PROGRESS_INTERVAL = 100
XMON_TAGMON_ENABLED = True
XMON_TAGMON_RETRIES = 3
XMON_TAGMON_RETRY_SLEEP = 3.0
HASH_WORKERS = 8
HASH_PROGRESS_INTERVAL = 200
WFY_WORKERS = 16
WFY_PROGRESS_INTERVAL = 100
SC_WORKERS = 12
SC_PROGRESS_INTERVAL = 100
WD_WORKERS = 12
WD_PROGRESS_INTERVAL = 100
AI_WORKERS = 20
AI_PROGRESS_INTERVAL = 100
AI_RETRIES = 3
AI_RETRY_SLEEP_SECONDS = 2.0
SLEEP_SECONDS = 0.05
LIMIT = 0
XMON_MIN_SEVERITY = 30
# 调试指定 IOC 时填入集合，例如 {"5235ffews.icu"}；不需要时改成空集合 set()。
DEBUG_IOCS = set()

RESULT_COLUMNS = [
    "IOC",
    "端口",
    "厂商",
    "外联日期",
    "研判结果",
    "存活状态",
    "文件特征值",
    "文件大小",
    "文件类型",
    "影响操作系统",
    "创建时间",
    "相关进程ID及文件名称",
    "ICP连接记录",
    "HTTP访问记录",
    "流量特征",
    "其他文件特征",
    "补充信息",
    "误报原因",
    "命中规则",
]

ANALYSIS_COLUMNS = ["ioc外联目标", "端口", "厂商", "ioc", "生产方归属", "能否解决", "相关解决方案"]
ANALYSIS_SUMMARY_COLUMNS = ["序号", "统计信息"]

BLACK_RISKS = {"critical", "high", "medium", "low"}
WHITE_RISKS = {"safe"}
OWNER_PRIORITY = ["atateam", "siyubo", "wd", "netlab", "unknown"]
XMON_FAILED_IOCS: list[str] = []
TAGMON_FAILED_IOCS: list[str] = []
TAGMON_FAILED_LOCK = Lock()
HASH_FAILED_QUERIES: list[str] = []
HASH_FAILED_LOCK = Lock()
WFY_FAILED_QUERIES: list[str] = []
SC_FAILED_IOCS: list[str] = []
WD_FAILED_IOCS: list[str] = []
AI_FAILED_IOCS: list[str] = []
THREAD_LOCAL = local()


@dataclass
class HashInfo:
    query_hash: str = ""
    risk: str = ""
    file_size: str = ""
    file_type: str = ""
    first_seen_time: str = ""
    operating_system: str = ""
    malware_family: str = ""
    virus_name: str = ""
    threat_type_name: str = ""

    @property
    def other_file_feature(self) -> str:
        values = [
            normalize_cell(self.malware_family),
            normalize_cell(self.virus_name),
            normalize_cell(self.threat_type_name),
        ]
        return " ".join(dict.fromkeys(value for value in values if value))


@dataclass
class XmonInfo:
    ioc_search: str = ""
    disable: str = ""
    status: str = ""
    ref_sample: Any = ""
    report_links: Any = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_disabled(self) -> bool:
        text = str(self.disable).strip().lower()
        return text in {"1", "true", "yes", "disabled"}


@dataclass
class WdInfo:
    ioc: str = ""
    level: int | None = None
    sub_level: int | None = None
    malicious: bool = False
    has_snapshot: bool = False
    snapshot_topic: str = ""
    query_error: str = ""


@dataclass
class AiInfo:
    ioc: str = ""
    key_evidence: list[str] = field(default_factory=list)
    summary: str = ""
    query_error: str = ""


@dataclass
class RowDecision:
    ioc: str
    result_ioc: str
    port: str
    vendor: str = VENDOR
    out_date: str = ""
    k01_result: str = ""
    alive_status: str = ""
    file_hash: str = ""
    file_size: str = ""
    file_type: str = ""
    operating_system: str = ""
    create_time: str = ""
    other_file_feature: str = ""
    info_add: str = ""
    false_positive_reason: str = ""
    owner: str = "unknown"
    solvable: str = "否"
    solution: str = "无更多依据关联"
    rule_hit: str = "no_more_evidence"
    hit_rule: str = ""


def first_not_empty(*values: Any) -> str:
    for value in values:
        text = stringify(value).strip()
        if text:
            return text
    return ""


def stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    if isinstance(value, list):
        return " ".join(stringify(v) for v in value if stringify(v))
    if isinstance(value, dict):
        if "in" in value and "out" in value:
            return f"{stringify(value.get('in'))} {stringify(value.get('out'))}".strip()
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def normalize_cell(value: Any) -> str:
    text = stringify(value).strip()
    if text in {"--", "nan", "NaN", "None"}:
        return ""
    if re.fullmatch(r"\d+\.0", text):
        return text[:-2]
    return text


def make_session() -> Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=HTTP_POOL_CONNECTIONS,
        pool_maxsize=HTTP_POOL_MAXSIZE,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_thread_session() -> Session:
    session = getattr(THREAD_LOCAL, "session", None)
    if session is None:
        session = make_session()
        THREAD_LOCAL.session = session
    return session


def chunk_list(data: list[str], size: int) -> list[list[str]]:
    if size <= 0:
        size = 1
    return [data[i : i + size] for i in range(0, len(data), size)]


def timestamp_to_date(ts: Any) -> str:
    try:
        value = int(float(str(ts).strip()))
        if value <= 0:
            return ""
        if value > 10_000_000_000:
            value = value // 1000
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))
    except Exception:
        return normalize_cell(ts)


def format_file_size(byte_value: Any) -> str:
    text = normalize_cell(byte_value)
    if not text:
        return ""
    try:
        size = int(float(text))
    except Exception:
        return text

    units = ["bytes", "KB", "MB", "GB", "TB"]
    value = float(size)
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{size} bytes ({size} bytes)"
    return f"{value:.2f} {units[unit_index]} ({size} bytes)"


def build_ioc(row: pd.Series) -> str:
    target = normalize_cell(row.get("外联目标", ""))
    port = normalize_cell(row.get("端口", ""))
    target_type = normalize_cell(row.get("目标类型", "")).upper()
    if not target:
        return ""
    if target_type == "IP" and port:
        return f"{target}:{port}"
    return target


def result_ioc(row: pd.Series) -> str:
    # 样例 result.xlsx 中 IOC 不带端口，保留这个口径。
    return normalize_cell(row.get("外联目标", "")) or normalize_cell(row.get("ioc", ""))


def make_ti_headers() -> dict[str, str]:
    timestamp = int(time.time())
    sign = hashlib.md5((str(timestamp) + SALT).encode()).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Api-Key": API_KEY,
        "timestamp": str(timestamp),
        "sign": sign,
    }


def safe_json_response(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return {}


def parse_literal_or_json(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return value
    text = stringify(value).strip()
    if not text:
        return []
    for parser in (json.loads, ast.literal_eval):
        try:
            return parser(text)
        except Exception:
            pass
    return text


def extract_xmon_rows(resp_json: Any) -> list[dict[str, Any]]:
    if isinstance(resp_json, list):
        return [x for x in resp_json if isinstance(x, dict)]
    if not isinstance(resp_json, dict):
        return []

    for key in ("data", "result", "results", "list"):
        data = resp_json.get(key)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            return [x for x in data.values() if isinstance(x, dict)]
    return [resp_json]


def has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return bool(normalize_cell(value))


def first_raw_not_empty(*values: Any) -> Any:
    for value in values:
        if has_meaningful_value(value):
            return value
    return ""


def extract_xmon_disable(row: dict[str, Any], raw: dict[str, Any]) -> str:
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    direct = first_not_empty(
        row.get("disable"),
        row.get("Disabled"),
        row.get("disabled"),
        row.get("ioc_disabled"),
        exts.get("disable"),
        exts.get("Disabled"),
        exts.get("disabled"),
        raw.get("disable"),
        raw.get("Disabled"),
    )
    if direct:
        return direct

    tags_info = row.get("tags_info")
    if isinstance(tags_info, list):
        for item in tags_info:
            if isinstance(item, dict):
                disabled = first_not_empty(item.get("disabled"), item.get("disable"), item.get("Disabled"))
                if disabled:
                    return disabled
    return ""


def normalize_xmon_row(ioc: str, row: dict[str, Any]) -> XmonInfo:
    raw = row.get("Raw") if isinstance(row.get("Raw"), dict) else {}
    return XmonInfo(
        ioc_search=first_not_empty(row.get("ioc_search"), row.get("ioc"), row.get("IOC"), row.get("uid"), ioc),
        disable=extract_xmon_disable(row, raw),
        status=first_not_empty(row.get("status"), row.get("Status"), raw.get("status"), raw.get("Status")),
        ref_sample=row.get("ref_sample", ""),
        report_links=first_raw_not_empty(row.get("report_links"), raw.get("report_links")),
        raw=row,
    )


def empty_xmon_info(ioc: str) -> XmonInfo:
    return XmonInfo(ioc_search=ioc)


def build_xmon_batch_url(batch: list[str]) -> str:
    ioc_part = ",".join(quote(x, safe=".:_-") for x in batch)
    return f"{XMON_BASE_URL}{ioc_part}/{XMON_QUERY}"


def build_xmon_tagmon_url(ioc: str) -> str:
    return f"{XMON_TAGMON_BASE_URL}{quote(ioc, safe='.:_-')}{XMON_TAGMON_SUFFIX}"


def can_resolve_host(url: str) -> tuple[bool, str]:
    host = urlparse(url).hostname or ""
    if not host:
        return False, "empty host"
    try:
        socket.getaddrinfo(host, None)
        return True, ""
    except socket.gaierror as exc:
        return False, str(exc)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def xmon_row_ioc(row: dict[str, Any]) -> str:
    return first_not_empty(row.get("ioc"), row.get("ioc_search"), row.get("IOC"), row.get("uid"))


def xmon_row_severity(row: dict[str, Any]) -> int:
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    raw = exts.get("_raw") if isinstance(exts.get("_raw"), dict) else {}
    ioctag = exts.get("ioctag") if isinstance(exts.get("ioctag"), dict) else {}
    tag_main = row.get("tag_main") if isinstance(row.get("tag_main"), dict) else {}
    return safe_int(first_not_empty(row.get("severity"), raw.get("severity"), raw.get("opinion"), ioctag.get("severity"), tag_main.get("severity")))


def is_xmon_clue_enabled(disable_text: str) -> bool:
    return not bool(normalize_cell(disable_text))


def extract_main_ioc_disabled(row: dict[str, Any]) -> str:
    return stringify(row.get("ioc_disabled", "")).strip()


def extract_child_exts_disabled(row: dict[str, Any]) -> str:
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    return stringify(exts.get("disabled", "")).strip()


def build_xmon_valid_clues(main_row: dict[str, Any], child_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    main_disable = extract_main_ioc_disabled(main_row)
    main_ioc = normalize_cell(main_row.get("ioc", ""))
    valid_clues: list[dict[str, Any]] = []

    if is_xmon_clue_enabled(main_disable) and xmon_row_severity(main_row) > XMON_MIN_SEVERITY:
        clue = dict(main_row)
        clue["__clue_type"] = "main"
        valid_clues.append(clue)

    if not is_xmon_clue_enabled(main_disable):
        return valid_clues

    for child in child_rows:
        child_ioc = normalize_cell(child.get("ioc", ""))
        if not main_ioc or child_ioc != main_ioc:
            continue
        child_disable = extract_child_exts_disabled(child)
        if not is_xmon_clue_enabled(child_disable):
            continue
        if xmon_row_severity(child) <= XMON_MIN_SEVERITY:
            continue
        clue = dict(child)
        clue["__clue_type"] = "sub"
        valid_clues.append(clue)

    return valid_clues


def query_xmon_tagmon_children(session: Session, ioc: str) -> list[dict[str, Any]]:
    if not XMON_TAGMON_ENABLED or not ioc:
        return []
    url = build_xmon_tagmon_url(ioc)
    last_error = ""
    max_attempts = XMON_TAGMON_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(XMON_TAGMON_RETRY_SLEEP)
        try:
            resp = session.get(url, headers=XMON_HEADERS, verify=False, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return extract_xmon_rows(safe_json_response(resp))
        except Exception as exc:
            last_error = str(exc)
    with TAGMON_FAILED_LOCK:
        TAGMON_FAILED_IOCS.append(f"{ioc} | {last_error}")
    return []


def query_xmon_tagmon_children_worker(ioc: str) -> list[dict[str, Any]]:
    return query_xmon_tagmon_children(get_thread_session(), ioc)


def query_xmon_tagmon_children_many(iocs: list[str]) -> dict[str, list[dict[str, Any]]]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in iocs if ioc))
    if not XMON_TAGMON_ENABLED or not unique_iocs:
        return {ioc: [] for ioc in unique_iocs}
    if XMON_WORKERS <= 1 or len(unique_iocs) == 1:
        with make_session() as session:
            return {ioc: query_xmon_tagmon_children(session, ioc) for ioc in unique_iocs}

    result_map: dict[str, list[dict[str, Any]]] = {}
    worker_count = min(XMON_WORKERS, len(unique_iocs))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_xmon_tagmon_children_worker, ioc): ioc
            for ioc in unique_iocs
        }
        for future in as_completed(future_map):
            ioc = future_map[future]
            try:
                result_map[ioc] = future.result()
            except Exception as exc:
                with TAGMON_FAILED_LOCK:
                    TAGMON_FAILED_IOCS.append(f"{ioc} | {exc}")
                result_map[ioc] = []
    return result_map


def query_xmon_one(ioc: str) -> tuple[str, XmonInfo, bool, str]:
    session = get_thread_session()
    url = build_xmon_batch_url([ioc])
    try:
        resp = session.get(url, headers=XMON_HEADERS, verify=False, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        rows = extract_xmon_rows(safe_json_response(resp))
        if not rows:
            return ioc, empty_xmon_info(ioc), True, ""

        for row in rows:
            main_ioc = normalize_cell(row.get("ioc", ""))
            child_rows = query_xmon_tagmon_children(session, main_ioc)
            enriched_row = dict(row)
            enriched_row["__tagmon_children"] = child_rows
            enriched_row["__valid_clues"] = build_xmon_valid_clues(row, child_rows)
            return ioc, normalize_xmon_row(ioc, enriched_row), True, ""

        return ioc, empty_xmon_info(ioc), True, ""
    except Exception as exc:
        return ioc, empty_xmon_info(ioc), False, str(exc)


def query_xmon_iocs(session: Session, ioc_list: list[str]) -> dict[str, XmonInfo]:
    result_map: dict[str, XmonInfo] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return {}

    resolvable, resolve_error = can_resolve_host(XMON_BASE_URL)
    if not resolvable:
        print(f"[!] xmon 域名无法解析，跳过 xmon 查询：{urlparse(XMON_BASE_URL).hostname}，错误：{resolve_error}")
        print("[!] 请确认当前环境能访问内网 DNS/VPN，或在 WSL/Linux 中配置可解析 xmon.netlab.qihoo.net 的 DNS/hosts。")
        return {ioc: result_map.get(ioc, empty_xmon_info(ioc)) for ioc in ioc_list}

    print(f"[+] xmon 待查询：{len(query_iocs)} 条")
    worker_count = min(XMON_WORKERS, len(query_iocs))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_xmon_one, ioc): ioc for ioc in query_iocs}
        for future in as_completed(future_map):
            requested_ioc = future_map[future]
            completed += 1
            try:
                ioc, xmon_info, cacheable, error = future.result()
            except Exception as exc:
                ioc, xmon_info, cacheable, error = requested_ioc, empty_xmon_info(requested_ioc), False, str(exc)
            result_map[ioc] = xmon_info
            if not cacheable and error:
                XMON_FAILED_IOCS.append(f"{ioc} | {error}")
            if completed % XMON_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] xmon 查询进度：{completed}/{len(query_iocs)}")
    return {ioc: result_map.get(ioc, empty_xmon_info(ioc)) for ioc in ioc_list}


def first_hash_from_main_ref_sample(ref_sample: Any) -> str:
    data = parse_literal_or_json(ref_sample)
    if isinstance(data, list) and data:
        first_item = data[0]
        if isinstance(first_item, dict):
            return normalize_cell(first_item.get("md5", ""))
    return ""


def child_raw_md5(child_row: dict[str, Any]) -> str:
    exts = child_row.get("exts") if isinstance(child_row.get("exts"), dict) else {}
    raw = exts.get("_raw") if isinstance(exts.get("_raw"), dict) else {}
    return normalize_cell(raw.get("md5", ""))


def extract_hashes_from_xmon_info(xmon_info: XmonInfo) -> list[str]:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    clues = raw.get("__valid_clues")
    hashes: list[str] = []
    if isinstance(clues, list):
        for clue in clues:
            if not isinstance(clue, dict):
                continue
            clue_type = normalize_cell(clue.get("__clue_type", ""))
            if clue_type == "main":
                value = first_hash_from_main_ref_sample(clue.get("ref_sample", ""))
            elif clue_type == "sub":
                value = child_raw_md5(clue)
            else:
                value = ""
            if value:
                hashes.append(value)
    elif raw:
        # 兼容旧运行结果或异常返回结构：有效线索列表缺失时，仍按主线索规则兜底提取一次。
        main_disable = extract_main_ioc_disabled(raw)
        if is_xmon_clue_enabled(main_disable) and xmon_row_severity(raw) > XMON_MIN_SEVERITY:
            value = first_hash_from_main_ref_sample(raw.get("ref_sample", ""))
            if value:
                hashes.append(value)
    return list(dict.fromkeys(hashes))


def query_hash_batch(session: Session, hash_list: list[str]) -> Any:
    payload = {"param": ",".join(hash_list), "field": 0}
    try:
        resp = session.post(
            HASH_API_URL,
            headers=make_ti_headers(),
            data=json.dumps(payload, ensure_ascii=False),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return safe_json_response(resp)
    except Exception as exc:
        with HASH_FAILED_LOCK:
            HASH_FAILED_QUERIES.append(f"{','.join(hash_list)} | {exc}")
        return {"errno": -1, "msg": str(exc), "result": {}}


def query_hash_one(hash_value: str) -> tuple[str, HashInfo]:
    response_json = query_hash_batch(get_thread_session(), [hash_value])
    parsed = parse_hash_result([hash_value], response_json)
    return hash_value, parsed.get(hash_value, HashInfo(query_hash=hash_value))


def parse_hash_result(hash_list: list[str], response_json: Any) -> dict[str, HashInfo]:
    if not isinstance(response_json, dict):
        response_json = {}
    result = response_json.get("result", {}) or response_json.get("data", {}) or {}
    hash_map: dict[str, HashInfo] = {}
    result_by_lower_key: dict[str, dict[str, Any]] = {}
    result_by_embedded_hash: dict[str, dict[str, Any]] = {}
    if isinstance(result, dict):
        for key, value in result.items():
            if not isinstance(value, dict):
                continue
            key_text = normalize_cell(key).lower()
            if key_text:
                result_by_lower_key[key_text] = value
            for hash_key in ("md5", "sha1", "sha256"):
                embedded = normalize_cell(value.get(hash_key, "")).lower()
                if embedded:
                    result_by_embedded_hash[embedded] = value

    for h in hash_list:
        hash_key = normalize_cell(h).lower()
        item = {}
        if isinstance(result, dict):
            direct_item = result.get(h, {})
            if isinstance(direct_item, dict):
                item = direct_item
        if not item:
            item = result_by_lower_key.get(hash_key, {})
        if not item:
            item = result_by_embedded_hash.get(hash_key, {})
        if not isinstance(item, dict):
            item = {}
        threat_type = item.get("threat_type", {}) if isinstance(item.get("threat_type"), dict) else {}
        hash_map[h] = HashInfo(
            query_hash=h,
            risk=normalize_cell(item.get("risk", "")),
            file_size=normalize_cell(item.get("file_size", "")),
            file_type=normalize_cell(item.get("file_type", "")),
            first_seen_time=timestamp_to_date(first_not_empty(item.get("first_seen"), item.get("create_time"), item.get("createtime"))),
            operating_system=normalize_cell(item.get("operating_system", "")),
            malware_family=normalize_cell(item.get("malware_family", "")),
            virus_name=normalize_cell(item.get("virus_name", "")),
            threat_type_name=normalize_cell(threat_type.get("name", "")),
        )
    return hash_map


def query_hashes(session: Session, hash_list: list[str]) -> dict[str, HashInfo]:
    unique_hashes = list(dict.fromkeys(h for h in hash_list if h))
    all_hash_map: dict[str, HashInfo] = {}
    if not unique_hashes:
        return all_hash_map
    print(f"[+] 查询 hash：{len(unique_hashes)} 条，单 hash 并发查询，并发数 {min(HASH_WORKERS, len(unique_hashes))}")
    if HASH_WORKERS <= 1 or len(unique_hashes) == 1:
        for hash_value in unique_hashes:
            response_json = query_hash_batch(session, [hash_value])
            parsed = parse_hash_result([hash_value], response_json)
            all_hash_map.update(parsed)
            time.sleep(SLEEP_SECONDS)
        return all_hash_map

    worker_count = min(HASH_WORKERS, len(unique_hashes))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_hash_one, hash_value): hash_value for hash_value in unique_hashes}
        for future in as_completed(future_map):
            hash_value = future_map[future]
            completed += 1
            try:
                _, hash_info = future.result()
            except Exception as exc:
                with HASH_FAILED_LOCK:
                    HASH_FAILED_QUERIES.append(f"{hash_value} | {exc}")
                hash_info = HashInfo(query_hash=hash_value)
            all_hash_map[hash_value] = hash_info
            if completed % HASH_PROGRESS_INTERVAL == 0 or completed == len(unique_hashes):
                print(f"[+] hash 查询进度：{completed}/{len(unique_hashes)}")
    return all_hash_map


def query_wfy_one(ioc: str) -> tuple[str, dict[str, Any]]:
    try:
        session = get_thread_session()
        resp = session.post(
            WFY_API_URL,
            headers=WFY_HEADERS,
            data=json.dumps([ioc], ensure_ascii=False),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        parsed = parse_wfy_response([ioc], data)
        return ioc, parsed.get(ioc, {})
    except Exception as exc:
        return ioc, {"query_error": str(exc), "judge": ""}


def query_wfy(session: Session, ioc_list: list[str]) -> dict[str, dict[str, Any]]:
    result_map: dict[str, dict[str, Any]] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return result_map
    print(f"[+] wfy 待查询：{len(query_iocs)} 条，单 IOC 并发查询，并发数 {min(WFY_WORKERS, len(query_iocs))}")

    if WFY_WORKERS <= 1 or len(query_iocs) == 1:
        for index, ioc in enumerate(query_iocs, 1):
            ioc, info = query_wfy_one(ioc)
            result_map[ioc] = info
            if info.get("query_error"):
                WFY_FAILED_QUERIES.append(f"{ioc} | {info.get('query_error')}")
            if index % WFY_PROGRESS_INTERVAL == 0 or index == len(query_iocs):
                print(f"[+] wfy 查询进度：{index}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(WFY_WORKERS, len(query_iocs))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_wfy_one, ioc): ioc for ioc in query_iocs}
        for future in as_completed(future_map):
            fallback_ioc = future_map[future]
            completed += 1
            try:
                ioc, info = future.result()
            except Exception as exc:
                ioc = fallback_ioc
                info = {"query_error": str(exc), "judge": ""}
            result_map[ioc] = info
            if info.get("query_error"):
                WFY_FAILED_QUERIES.append(f"{ioc} | {info.get('query_error')}")
            if completed % WFY_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] wfy 查询进度：{completed}/{len(query_iocs)}")
    return result_map


def parse_wfy_response(batch: list[str], data: Any) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    if isinstance(data, dict):
        candidate = data.get("data", data.get("result", data))
        if isinstance(candidate, dict):
            for ioc in batch:
                value = candidate.get(ioc, {})
                parsed[ioc] = value if isinstance(value, dict) else {"value": value}
            return parsed
        if isinstance(candidate, list):
            data = candidate

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            ioc = first_not_empty(item.get("ioc"), item.get("query"), item.get("domain"), item.get("ip"))
            if ioc:
                parsed[ioc] = item

    for ioc in batch:
        parsed.setdefault(ioc, {})
    return parsed


def sc_category_for_ioc(ioc: str) -> str:
    text = normalize_cell(ioc).lower()
    if text.startswith(("http://", "https://")):
        return "url"
    return SC_DEFAULT_CATEGORY


def query_custom_tags(session: Session, ioc: str, category: str | None = None) -> dict[str, Any]:
    query_category = category or sc_category_for_ioc(ioc)
    payload = {
        "query": {
            "keywords": [
                {"field": "category", "value": query_category},
                {"field": "query", "value": ioc},
                {"field": "flag", "value": "2"},
            ]
        }
    }
    try:
        resp = session.post(
            TAGS_API_URL,
            headers=make_ti_headers(),
            data=json.dumps(payload, ensure_ascii=False),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        return {"query_error": str(exc)}


def query_custom_tags_worker(ioc: str) -> dict[str, Any]:
    return query_custom_tags(get_thread_session(), ioc)


def extract_sc_level(response_json: dict[str, Any]) -> int | None:
    def find_level(value: Any) -> int | None:
        if isinstance(value, dict):
            if "level" in value:
                try:
                    return int(float(str(value.get("level")).strip()))
                except Exception:
                    return None
            for nested_key in ("data", "result", "results", "list"):
                nested_level = find_level(value.get(nested_key))
                if nested_level is not None:
                    return nested_level
        if isinstance(value, list):
            for item in value:
                nested_level = find_level(item)
                if nested_level is not None:
                    return nested_level
        return None

    return find_level(response_json)


def sc_is_malicious(response_json: dict[str, Any]) -> bool:
    level = extract_sc_level(response_json)
    return level is not None and level >= 50


def query_sc(session: Session, ioc_list: list[str]) -> dict[str, bool]:
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    sc_map: dict[str, bool] = {}
    if not query_iocs:
        return sc_map
    print(f"[+] sc 待查询：{len(query_iocs)} 条，并发数 {min(SC_WORKERS, len(query_iocs))}")

    if SC_WORKERS <= 1 or len(query_iocs) == 1:
        for index, ioc in enumerate(query_iocs, 1):
            response_json = query_custom_tags(session, ioc)
            sc_map[ioc] = sc_is_malicious(response_json)
            if index % SC_PROGRESS_INTERVAL == 0 or index == len(query_iocs):
                print(f"[+] sc 查询进度：{index}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
    else:
        worker_count = min(SC_WORKERS, len(query_iocs))
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(query_custom_tags_worker, ioc): ioc for ioc in query_iocs}
            for future in as_completed(future_map):
                ioc = future_map[future]
                completed += 1
                try:
                    response_json = future.result()
                    sc_map[ioc] = sc_is_malicious(response_json)
                except Exception as exc:
                    SC_FAILED_IOCS.append(f"{ioc} | {exc}")
                    sc_map[ioc] = False
                if completed % SC_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                    print(f"[+] sc 查询进度：{completed}/{len(query_iocs)}")
    return sc_map


def make_wd_safe_headers(body: str) -> dict[str, str]:
    nonce = str(random.randint(0, 99999999)).zfill(8)
    timestamp = str(int(time.time()))
    sign_text = hashlib.md5(body.encode("utf8")).hexdigest() + WD_SAFE_APPID + nonce + timestamp + WD_SAFE_SECRET
    signature = hashlib.md5(sign_text.encode("utf8")).hexdigest()[16:]
    return {
        "X-360-Key": WD_SAFE_APPID,
        "X-360-Nonce": nonce,
        "X-360-Timestamp": timestamp,
        "X-360-Signature": signature,
        "Content-Type": "application/json",
    }


def query_wd_safe_level(session: Session, ioc: str) -> tuple[int | None, int | None, str]:
    body = json.dumps({"data": [{"url": ioc}]}, ensure_ascii=False, separators=(",", ":"))
    try:
        resp = session.post(
            WD_SAFE_API_URL,
            data=body,
            headers=make_wd_safe_headers(body),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        results = (((data.get("data") or {}).get("results") or []) if isinstance(data, dict) else [])
        if not results or not isinstance(results[0], dict):
            return None, None, "wd safe empty result"
        info = results[0].get("info") if isinstance(results[0].get("info"), dict) else {}
        return safe_int(info.get("level"), 0), safe_int(info.get("sub_level"), 0), ""
    except Exception as exc:
        return None, None, str(exc)


def query_wd_history_snapshot(session: Session, ioc: str) -> tuple[bool, str, str]:
    headers = {"X-Authtoken": WD_HISTORY_TOKEN}
    params = {"query": ioc, "time_start": WD_HISTORY_START}
    try:
        resp = session.get(
            WD_HISTORY_API_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        rows = data.get("data") if isinstance(data, dict) else []
        if not isinstance(rows, list):
            return False, "", "wd history data is not list"
        for row in rows:
            if not isinstance(row, dict):
                continue
            html = normalize_cell(row.get("html", ""))
            snapshot = normalize_cell(row.get("snapshot", ""))
            if not html and not snapshot:
                continue
            topic = first_not_empty(row.get("title"), row.get("url"), row.get("domain"), ioc)
            return True, topic, ""
        return False, "", ""
    except Exception as exc:
        return False, "", str(exc)


def query_wd_one(ioc: str) -> WdInfo:
    session = get_thread_session()
    level, sub_level, level_error = query_wd_safe_level(session, ioc)
    malicious = level is not None and level >= 50
    has_snapshot = False
    topic = ""
    snapshot_error = ""
    if malicious:
        has_snapshot, topic, snapshot_error = query_wd_history_snapshot(session, ioc)
    query_error = "; ".join(x for x in (level_error, snapshot_error) if x)
    return WdInfo(
        ioc=ioc,
        level=level,
        sub_level=sub_level,
        malicious=malicious,
        has_snapshot=has_snapshot,
        snapshot_topic=topic,
        query_error=query_error,
    )


def query_wd(session: Session, ioc_list: list[str]) -> dict[str, WdInfo]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    result_map: dict[str, WdInfo] = {}
    if unique_iocs:
        print(f"[+] wd 待查询：{len(unique_iocs)} 条，并发数 {min(WD_WORKERS, len(unique_iocs))}")
    if WD_WORKERS <= 1 or len(unique_iocs) == 1:
        for index, ioc in enumerate(unique_iocs, 1):
            wd_info = query_wd_one(ioc)
            if wd_info.query_error:
                WD_FAILED_IOCS.append(f"{ioc} | {wd_info.query_error}")
            result_map[ioc] = wd_info
            if index % WD_PROGRESS_INTERVAL == 0 or index == len(unique_iocs):
                print(f"[+] wd 查询进度：{index}/{len(unique_iocs)}")
            time.sleep(SLEEP_SECONDS)
    else:
        worker_count = min(WD_WORKERS, len(unique_iocs))
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(query_wd_one, ioc): ioc for ioc in unique_iocs}
            for future in as_completed(future_map):
                ioc = future_map[future]
                completed += 1
                try:
                    wd_info = future.result()
                except Exception as exc:
                    wd_info = WdInfo(ioc=ioc, query_error=str(exc))
                if wd_info.query_error:
                    WD_FAILED_IOCS.append(f"{ioc} | {wd_info.query_error}")
                result_map[ioc] = wd_info
                if completed % WD_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
                    print(f"[+] wd 查询进度：{completed}/{len(unique_iocs)}")
    return result_map


def wfy_is_black(wfy_info: dict[str, Any]) -> bool:
    judge = normalize_cell(first_not_empty(wfy_info.get("judge"), wfy_info.get("verdict"), wfy_info.get("label"))).lower()
    return judge == "black"


def wfy_is_white(wfy_info: dict[str, Any]) -> bool:
    judge = normalize_cell(first_not_empty(wfy_info.get("judge"), wfy_info.get("verdict"), wfy_info.get("label"))).lower()
    return judge == "white"


def wfy_is_unknown(wfy_info: dict[str, Any]) -> bool:
    if wfy_info.get("query_error"):
        return False
    if not wfy_info:
        return True
    judge = normalize_cell(first_not_empty(wfy_info.get("judge"), wfy_info.get("verdict"), wfy_info.get("label"))).lower()
    return judge in {"", "unknown", "none", "null"}


def wfy_has_no_result(wfy_info: dict[str, Any]) -> bool:
    return not bool(wfy_info)


def risk_is_black(risk: str) -> bool:
    return normalize_cell(risk).lower() in BLACK_RISKS


def risk_is_white(risk: str) -> bool:
    return normalize_cell(risk).lower() in WHITE_RISKS


def map_k01_status(xmon_status: Any) -> str:
    status = normalize_cell(xmon_status).upper()
    status_map = {
        "ACTIVE": "存活",
        "UNKNOWN": "失活",
        "SINKHOLE": "被安全机构接管",
    }
    return status_map.get(status, status)


def split_report_links(report_links: Any) -> list[str]:
    data = parse_literal_or_json(report_links)
    if isinstance(data, dict):
        values = list(data.values())
    elif isinstance(data, list):
        values = data
    else:
        values = re.split(r"[\s,;，；]+", stringify(data))

    links: list[str] = []
    for value in values:
        text = stringify(value).strip().strip("\"'")
        if not text or text.startswith("@Version:"):
            continue
        for part in re.split(r"[\s,;，；]+", text):
            part = part.strip().strip("\"'")
            if part:
                links.append(part)
    return list(dict.fromkeys(links))


def normalize_report_url(url: str) -> str:
    text = normalize_cell(url)
    if not text:
        return ""
    if text.startswith(("http://", "https://")) and "#" in text:
        text = text.split("#", 1)[0]
    return text


def pick_first_report(report_links: Any) -> str:
    for link in split_report_links(report_links):
        normalized = normalize_report_url(link)
        if normalized:
            return normalized
    return ""


def all_xmon_text(xmon_info: XmonInfo) -> str:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    if "__valid_clues" in raw:
        return stringify(raw.get("__valid_clues") or []).lower()

    fields = [
        xmon_info.ioc_search,
        xmon_info.disable,
        xmon_info.status,
        xmon_info.report_links,
        raw.get("src"),
        raw.get("source"),
        raw.get("src_end"),
        raw.get("main_clue"),
        raw.get("sub_clue"),
        raw.get("clue"),
        raw.get("Raw"),
        raw.get("tag_main"),
        raw.get("tags"),
        raw.get("tags_info"),
        raw.get("ti_info"),
        raw,
    ]
    return stringify(fields).lower()


def xmon_owner_src_values(xmon_info: XmonInfo) -> list[str]:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    clues = raw.get("__valid_clues")
    values: list[str] = []
    if isinstance(clues, list):
        for clue in clues:
            if not isinstance(clue, dict):
                continue
            clue_type = normalize_cell(clue.get("__clue_type", ""))
            if clue_type == "main":
                values.append(normalize_cell(clue.get("src", "")))
                continue
            if clue_type == "sub":
                values.append(normalize_cell(clue.get("src", "")))
    return [value.lower() for value in values if value]


def is_url_src(value: str) -> bool:
    text = normalize_cell(value).lower()
    if not text:
        return False
    if text.startswith(("http://", "https://")):
        return True
    parsed = urlparse(text)
    return bool(parsed.scheme and parsed.netloc)


def xmon_owner_candidates(xmon_info: XmonInfo) -> list[str]:
    candidates: list[str] = []
    for value in xmon_owner_src_values(xmon_info):
        if "atateam" in value:
            candidates.append("atateam")
        if "siyubo" in value:
            candidates.append("siyubo")
        if "btmon" in value or is_url_src(value):
            candidates.append("netlab")
    return list(dict.fromkeys(candidates))


def pick_owner_candidate(candidates: list[str]) -> str:
    candidate_set = set(candidates)
    for owner in OWNER_PRIORITY:
        if owner in candidate_set:
            return owner
    return "unknown"


def collect_owner_candidates(
    xmon_info: XmonInfo,
    wfy_info: dict[str, Any],
    wd_info: WdInfo,
    sc_malicious: bool = False,
) -> list[str]:
    if wfy_has_no_result(wfy_info):
        return ["unknown"]
    candidates = xmon_owner_candidates(xmon_info)
    if wd_info.malicious and wd_info.has_snapshot:
        candidates.append("wd")
    if sc_malicious:
        candidates.append("netlab")
    text = all_xmon_text(xmon_info)
    if "netlab" in text:
        candidates.append("netlab")
    if not candidates:
        candidates.append("unknown")
    return list(dict.fromkeys(candidates))


def classify_owner(xmon_info: XmonInfo, wfy_info: dict[str, Any], wd_info: WdInfo, sc_malicious: bool = False) -> str:
    candidates = collect_owner_candidates(xmon_info, wfy_info, wd_info, sc_malicious)
    return pick_owner_candidate(candidates)


def has_wd_malicious_snapshot(wd_info: WdInfo) -> tuple[bool, str]:
    return wd_info.malicious and wd_info.has_snapshot, wd_info.snapshot_topic


def summarize_evidence_details(details: list[str], limit: int = 50) -> str:
    cleaned: list[str] = []
    for detail in details:
        text = normalize_cell(detail)
        if not text:
            continue
        text = re.sub(r"\s+", "", text)
        text = text.replace("→", "，")
        cleaned.append(text)
    if not cleaned:
        return ""
    summary = "；".join(dict.fromkeys(cleaned))
    return summary[:limit]


def extract_siyubo_evidence_summary(xmon_info: XmonInfo) -> str:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    clues = raw.get("__valid_clues")
    details: list[str] = []
    if not isinstance(clues, list):
        return ""
    for clue in clues:
        if not isinstance(clue, dict):
            continue
        if normalize_cell(clue.get("__clue_type", "")) != "sub":
            continue
        exts = clue.get("exts") if isinstance(clue.get("exts"), dict) else {}
        raw_data = exts.get("_raw") if isinstance(exts.get("_raw"), dict) else {}
        ext = raw_data.get("ext") if isinstance(raw_data.get("ext"), dict) else {}
        evidence_chain = ext.get("evidence_chain")
        if not isinstance(evidence_chain, list):
            continue
        for item in evidence_chain:
            if isinstance(item, dict):
                detail = normalize_cell(item.get("detail", ""))
                if detail:
                    details.append(detail)
    return summarize_evidence_details(details)


def infer_ioc_type(ioc: str) -> str:
    text = normalize_cell(ioc)
    host = text.rsplit(":", 1)[0] if ":" in text and text.count(":") == 1 else text
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return "ip"
    if text.startswith(("http://", "https://")):
        return "url"
    return "domain"


def query_ai_quick_analysis_one(ioc: str) -> AiInfo:
    payload = {
        "ioc": ioc,
        "ioc_type": infer_ioc_type(ioc),
    }
    data: Any = {}
    last_error = ""
    max_attempts = AI_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(AI_RETRY_SLEEP_SECONDS * (attempt - 1))
        try:
            session = get_thread_session()
            resp = session.post(
                AI_QUICK_ANALYSIS_URL,
                headers=AI_QUICK_ANALYSIS_HEADERS,
                data=json.dumps(payload, ensure_ascii=False),
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = safe_json_response(resp)
            break
        except Exception as exc:
            last_error = str(exc)
    else:
        return AiInfo(ioc=ioc, query_error=last_error)

    body = data.get("data") if isinstance(data, dict) else {}
    key_evidence = body.get("key_evidence", []) if isinstance(body, dict) else []
    if not isinstance(key_evidence, list):
        key_evidence = []
    filtered = [
        normalize_cell(item)
        for item in key_evidence
        if normalize_cell(item) and "外部威胁情报显示" not in normalize_cell(item)
    ]
    return AiInfo(ioc=ioc, key_evidence=filtered, summary=summarize_evidence_details(filtered))


def query_ai_quick_analysis(ioc_list: list[str]) -> dict[str, AiInfo]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    result_map: dict[str, AiInfo] = {}
    if not unique_iocs:
        return result_map
    print(f"[+] 智能体证据链待查询：{len(unique_iocs)} 条，并发数 {min(AI_WORKERS, len(unique_iocs))}")
    if AI_WORKERS <= 1 or len(unique_iocs) == 1:
        for index, ioc in enumerate(unique_iocs, 1):
            info = query_ai_quick_analysis_one(ioc)
            if info.query_error:
                AI_FAILED_IOCS.append(f"{ioc} | {info.query_error}")
            result_map[ioc] = info
            if index % AI_PROGRESS_INTERVAL == 0 or index == len(unique_iocs):
                print(f"[+] 智能体证据链查询进度：{index}/{len(unique_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(AI_WORKERS, len(unique_iocs))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_ai_quick_analysis_one, ioc): ioc for ioc in unique_iocs}
        for future in as_completed(future_map):
            ioc = future_map[future]
            completed += 1
            try:
                info = future.result()
            except Exception as exc:
                info = AiInfo(ioc=ioc, query_error=str(exc))
            if info.query_error:
                AI_FAILED_IOCS.append(f"{ioc} | {info.query_error}")
            result_map[ioc] = info
            if completed % AI_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
                print(f"[+] 智能体证据链查询进度：{completed}/{len(unique_iocs)}")
    return result_map


def has_black_hash_evidence(xmon_info: XmonInfo, hash_map: dict[str, HashInfo]) -> bool:
    return any(risk_is_black(hash_map.get(ref_hash, HashInfo(query_hash=ref_hash)).risk) for ref_hash in extract_hashes_from_xmon_info(xmon_info))


def decide_row(
    row: pd.Series,
    xmon_info: XmonInfo,
    hash_map: dict[str, HashInfo],
    wfy_info: dict[str, Any],
    wd_info: WdInfo,
    ai_info: AiInfo | None = None,
    sc_malicious: bool = False,
) -> RowDecision:
    ioc = normalize_cell(row.get("ioc", ""))
    decision = RowDecision(
        ioc=ioc,
        result_ioc=result_ioc(row),
        port=normalize_cell(row.get("端口", "")),
        out_date=normalize_cell(row.get("外联日期", "")),
        alive_status=map_k01_status(xmon_info.status),
    )

    ref_hashes = extract_hashes_from_xmon_info(xmon_info)
    first_hash_info = HashInfo(query_hash=ref_hashes[0]) if ref_hashes else HashInfo()
    black_hash = ""
    black_hash_info = HashInfo()
    white_hash_seen = False

    for ref_hash in ref_hashes:
        hash_info = hash_map.get(ref_hash, HashInfo(query_hash=ref_hash))
        if risk_is_black(hash_info.risk):
            black_hash = ref_hash
            black_hash_info = hash_info
            break
        elif risk_is_white(hash_info.risk):
            white_hash_seen = True
        if not first_hash_info.risk:
            first_hash_info = hash_info

    first_report = pick_first_report(xmon_info.report_links)
    wd_snapshot, wd_topic = has_wd_malicious_snapshot(wd_info)
    decision.owner = classify_owner(xmon_info, wfy_info, wd_info, sc_malicious)

    if wfy_is_white(wfy_info):
        decision.k01_result = ""
        decision.info_add = "wfy未报告恶意"
        decision.false_positive_reason = "wfy未报告恶意"
        decision.solvable = "否"
        decision.solution = "wfy未报告恶意"
        decision.rule_hit = "wfy_white"
        decision.hit_rule = "wfy未报告恶意"
        return decision

    if black_hash:
        decision.k01_result = "有效"
        decision.file_hash = black_hash
        decision.file_size = format_file_size(black_hash_info.file_size)
        decision.file_type = black_hash_info.file_type
        decision.operating_system = black_hash_info.operating_system
        decision.create_time = black_hash_info.first_seen_time
        decision.other_file_feature = black_hash_info.other_file_feature
        decision.info_add = f"{decision.result_ioc}，依据ioc({decision.result_ioc}),关联样本（{black_hash}）"
        decision.solvable = "能"
        decision.solution = "存在黑样本关联"
        decision.rule_hit = "black_hash"
        decision.hit_rule = "存在黑样本关联"
        return decision

    if first_report:
        decision.k01_result = "有效"
        decision.file_hash = first_hash_info.query_hash
        decision.file_size = format_file_size(first_hash_info.file_size)
        decision.file_type = first_hash_info.file_type
        decision.operating_system = first_hash_info.operating_system
        decision.create_time = first_hash_info.first_seen_time
        decision.other_file_feature = first_hash_info.other_file_feature
        decision.info_add = f"{decision.result_ioc}，依据ioc({decision.result_ioc}),关联报告（{first_report}）"
        decision.solvable = "能"
        decision.solution = "存在关联报告关联"
        decision.rule_hit = "report"
        decision.hit_rule = "存在关联报告关联"
        return decision

    if decision.owner == "wd" and wd_snapshot:
        topic = wd_topic or decision.result_ioc
        decision.k01_result = "有效"
        decision.info_add = f"内容类，存在恶意快照的ioc({topic})"
        decision.solvable = "能"
        decision.solution = "src是wd且有快照"
        decision.rule_hit = "wd_snapshot"
        decision.hit_rule = "src是wd且有快照"
        return decision

    if decision.owner == "siyubo":
        evidence_summary = extract_siyubo_evidence_summary(xmon_info)
        if evidence_summary:
            decision.k01_result = "有效"
            decision.info_add = evidence_summary
            decision.solvable = "能"
            decision.solution = "siyubo证据链"
            decision.rule_hit = "siyubo_evidence_chain"
            decision.hit_rule = "siyubo证据链"
            return decision
        if ai_info and ai_info.summary:
            decision.k01_result = "有效"
            decision.info_add = ai_info.summary
            decision.solvable = "能"
            decision.solution = "智能体证据链"
            decision.rule_hit = "ai_evidence_chain"
            decision.hit_rule = "智能体证据链"
        return decision

    if wfy_is_unknown(wfy_info):
        decision.k01_result = "无效"
        decision.info_add = "wfy接口查询显示未知"
        decision.false_positive_reason = "wfy查不到"
        decision.solvable = "否"
        decision.solution = "wfy查不到"
        decision.rule_hit = "wfy_unknown"
        return decision

    if white_hash_seen:
        decision.k01_result = ""
        decision.false_positive_reason = "文件情报为白"
        decision.solvable = "否"
        decision.solution = "文件情报为白，暂无有效证据"
        decision.rule_hit = "hash_white"
        return decision

    decision.k01_result = ""
    decision.solvable = "否"
    decision.solution = "无更多依据关联"
    decision.rule_hit = "no_more_evidence"
    return decision


def print_debug_ioc(
    ioc: str,
    xmon_info: XmonInfo,
    hash_map: dict[str, HashInfo],
    wfy_info: dict[str, Any],
    wd_info: WdInfo,
    sc_malicious: bool,
    decision: RowDecision,
) -> None:
    if ioc not in DEBUG_IOCS and decision.result_ioc not in DEBUG_IOCS:
        return
    ref_hashes = extract_hashes_from_xmon_info(xmon_info)
    hash_risks = {h: normalize_cell(hash_map.get(h, HashInfo(query_hash=h)).risk) for h in ref_hashes}
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    valid_clues = raw.get("__valid_clues")
    valid_clue_count = len(valid_clues) if isinstance(valid_clues, list) else 0
    print("\n[DEBUG] IOC 研判链路")
    print(f"    ioc: {ioc}")
    print(f"    xmon_ioc_search: {xmon_info.ioc_search}")
    print(f"    valid_clues: {valid_clue_count}")
    print(f"    ref_hashes: {ref_hashes}")
    print(f"    hash_risks: {hash_risks}")
    print(f"    wfy_judge: {normalize_cell(wfy_info.get('judge', ''))}")
    print(f"    wd: malicious={wd_info.malicious}, snapshot={wd_info.has_snapshot}")
    print(f"    sc_malicious: {sc_malicious}")
    print(f"    rule_hit: {decision.rule_hit}")
    print(f"    hit_rule: {decision.hit_rule}")
    print(f"    result: {decision.k01_result}")
    print(f"    info_add: {decision.info_add}")


def decision_to_result_row(decision: RowDecision) -> dict[str, str]:
    return {
        "IOC": decision.result_ioc,
        "端口": decision.port,
        "厂商": decision.vendor,
        "外联日期": decision.out_date,
        "研判结果": decision.k01_result,
        "存活状态": decision.alive_status,
        "文件特征值": decision.file_hash,
        "文件大小": decision.file_size,
        "文件类型": decision.file_type,
        "影响操作系统": decision.operating_system,
        "创建时间": decision.create_time,
        "相关进程ID及文件名称": "",
        "ICP连接记录": "",
        "HTTP访问记录": "",
        "流量特征": "",
        "其他文件特征": decision.other_file_feature,
        "补充信息": decision.info_add,
        "误报原因": decision.false_positive_reason,
        "命中规则": decision.hit_rule,
    }


def decision_to_analysis_row(decision: RowDecision) -> dict[str, str]:
    return {
        "ioc外联目标": decision.result_ioc,
        "端口": decision.port,
        "厂商": decision.vendor,
        "ioc": decision.ioc,
        "生产方归属": decision.owner,
        "能否解决": decision.solvable,
        "相关解决方案": decision.solution,
    }


def owner_stats_templates(decisions: list[RowDecision]) -> dict[str, str]:
    stats: dict[str, dict[str, int]] = {
        owner: {"total": 0, "solved": 0, "unsolved": 0}
        for owner in OWNER_PRIORITY
    }
    for decision in decisions:
        owner = decision.owner if decision.owner in stats else "unknown"
        stats[owner]["total"] += 1
        if decision.solvable == "能":
            stats[owner]["solved"] += 1
        else:
            stats[owner]["unsolved"] += 1
    return {
        owner: f"{owner}量有{item['total']}，解决了{item['solved']}，{item['unsolved']}没解决"
        for owner, item in stats.items()
    }


def apply_owner_stats_fallback(decisions: list[RowDecision], wfy_map: dict[str, dict[str, Any]]) -> None:
    templates = owner_stats_templates(decisions)
    updated = 0
    for decision in decisions:
        if decision.rule_hit != "no_more_evidence":
            continue
        if not wfy_is_black(wfy_map.get(decision.ioc, {})):
            continue
        template = templates.get(decision.owner, templates["unknown"])
        decision.info_add = template
        decision.solution = template
        updated += 1
    if updated:
        print(f"[+] 生产方统计话术回填：{updated} 条")


def build_analysis_summary_rows(decisions: list[RowDecision], wfy_map: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    today_alert_count = len(decisions)
    unique_ioc_count = len({decision.ioc for decision in decisions if decision.ioc})
    unique_iocs = list(dict.fromkeys(decision.ioc for decision in decisions if decision.ioc))
    wfy_black_count = sum(1 for ioc in unique_iocs if wfy_is_black(wfy_map.get(ioc, {})))
    wfy_non_black_count = len(unique_iocs) - wfy_black_count

    black_hash_count = sum(1 for decision in decisions if decision.hit_rule == "存在黑样本关联")
    report_count = sum(1 for decision in decisions if decision.hit_rule == "存在关联报告关联")
    wd_snapshot_count = sum(1 for decision in decisions if decision.hit_rule == "src是wd且有快照")
    ai_evidence_count = sum(1 for decision in decisions if decision.hit_rule == "智能体证据链")

    remaining_decisions = [
        decision
        for decision in decisions
        if decision.rule_hit == "no_more_evidence" and wfy_is_black(wfy_map.get(decision.ioc, {}))
    ]
    remaining_count = len(remaining_decisions)
    owner_counter = Counter(decision.owner if decision.owner in OWNER_PRIORITY else "unknown" for decision in decisions)
    owner_text = "，".join(
        f"{owner}（{owner_counter.get(owner, 0)}条）"
        for owner in ("atateam", "siyubo", "wd", "netlab", "unknown")
    )

    lines = [
        f"今日告警数量：{today_alert_count}",
        f"拼接后ioc去重数量：{unique_ioc_count}",
        f"wfy黑{wfy_black_count}条，非黑{wfy_non_black_count}条",
        f"hash黑样本命中{black_hash_count}",
        f"report_links命中{report_count}",
        f"wd存在快照{wd_snapshot_count}",
        f"智能体证据链{ai_evidence_count}",
        f"还剩余{remaining_count}条ioc",
        f"生产方归属总计{today_alert_count}条，{owner_text}",
    ]
    return [{"序号": str(index), "统计信息": line} for index, line in enumerate(lines, 1)]


def list_input_files() -> list[str]:
    if not os.path.isdir(INPUT_DIR):
        raise FileNotFoundError(f"输入目录不存在：{INPUT_DIR}")
    files: list[str] = []
    for name in sorted(os.listdir(INPUT_DIR)):
        lower = name.lower()
        if name.startswith("~$"):
            continue
        if not lower.endswith((".xlsx", ".xls")):
            continue
        files.append(os.path.join(INPUT_DIR, name))
    if not files:
        raise FileNotFoundError(f"输入目录没有 Excel 文件：{INPUT_DIR}")
    return files


def read_input_file(path: str) -> pd.DataFrame:
    try:
        df = pd.read_excel(path, sheet_name="受控外联情报研判_1", dtype=str).fillna("")
    except ValueError as exc:
        raise ValueError(f"读取输入文件失败：{path}，请确认存在 sheet：受控外联情报研判_1") from exc
    required = ["外联目标", "端口", "目标类型", "外联日期"]
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"输入文件缺少字段：{path}，缺少：{missing}")
    for col in df.columns:
        df[col] = df[col].map(normalize_cell)
    df["来源文件"] = os.path.basename(path)
    return df


def read_input() -> pd.DataFrame:
    input_files = list_input_files()
    print("[+] 输入文件：")
    for path in input_files:
        print(f"    {path}")
    df = pd.concat([read_input_file(path) for path in input_files], ignore_index=True)
    if LIMIT > 0:
        df = df.head(LIMIT).copy()
    df["ioc"] = df.apply(build_ioc, axis=1)
    return df


def print_stats(decisions: list[RowDecision]) -> None:
    result_counter = Counter(d.k01_result for d in decisions)
    owner_counter = Counter(d.owner for d in decisions)
    solvable_counter = Counter(d.solvable for d in decisions)
    rule_counter = Counter(d.rule_hit for d in decisions)

    print("\n[+] 统计")
    print(f"    总数：{len(decisions)}")
    print(f"    研判结果：{dict(result_counter)}")
    print(f"    生产方归属：{dict(owner_counter)}")
    print(f"    能否解决：{dict(solvable_counter)}")
    print(f"    规则命中：{dict(rule_counter)}")


def print_failure_summary(title: str, failures: list[str], max_items: int = 20) -> None:
    if not failures:
        return
    unique_failures = list(dict.fromkeys(failures))
    print(f"\n[!] {title}")
    print(f"    总数：{len(unique_failures)}")
    for item in unique_failures[:max_items]:
        print(f"    {item}")
    if len(unique_failures) > max_items:
        print(f"    ... 其余 {len(unique_failures) - max_items} 条已省略")


def print_query_failures() -> None:
    print_failure_summary("xmon 主线索查询失败 IOC", XMON_FAILED_IOCS)
    print_failure_summary("xmon 子线索最终查询失败 IOC", TAGMON_FAILED_IOCS)
    print_failure_summary("hash 查询失败", HASH_FAILED_QUERIES)
    print_failure_summary("wfy 查询失败 IOC", WFY_FAILED_QUERIES)
    print_failure_summary("sc 查询失败 IOC", SC_FAILED_IOCS)
    print_failure_summary("wd 查询异常 IOC", WD_FAILED_IOCS)
    print_failure_summary("智能体证据链查询异常 IOC", AI_FAILED_IOCS)


def remove_old_outputs() -> None:
    for path in (RESULT_FILE, ANALYSIS_FILE):
        if not os.path.exists(path):
            continue
        try:
            os.remove(path)
            print(f"[+] 已删除旧输出：{path}")
        except PermissionError as exc:
            raise PermissionError(f"无法删除旧输出文件：{path}。请先关闭 Excel/WPS 中打开的该文件后重试。") from exc


def write_excel_file(df: pd.DataFrame, path: str) -> None:
    try:
        df.to_excel(path, index=False)
    except PermissionError as exc:
        raise PermissionError(f"无法写入输出文件：{path}。请先关闭 Excel/WPS 中打开的该文件后重试。") from exc


def write_analysis_excel(detail_df: pd.DataFrame, summary_df: pd.DataFrame, path: str) -> None:
    try:
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            detail_df.to_excel(writer, sheet_name="明细", index=False)
            summary_df.to_excel(writer, sheet_name="统计", index=False)
    except PermissionError as exc:
        raise PermissionError(f"无法写入输出文件：{path}。请先关闭 Excel/WPS 中打开的该文件后重试。") from exc


def start_stage(name: str) -> float:
    print(f"\n[+] 开始：{name}")
    return time.time()


def finish_stage(name: str, start_time: float) -> None:
    elapsed = time.time() - start_time
    print(f"[+] 完成：{name}，耗时 {elapsed:.2f} 秒（{elapsed / 60:.2f} 分钟）")


def main() -> None:
    start_time = time.time()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    remove_old_outputs()
    stage_time = start_stage("读取输入")
    df = read_input()
    ioc_list = list(dict.fromkeys(x for x in df["ioc"].tolist() if x))
    print(f"[+] 读取输入：{len(df)} 行，唯一 IOC：{len(ioc_list)}")
    finish_stage("读取输入", stage_time)

    session = make_session()
    stage_time = start_stage("查询 xmon 主线索和子线索")
    xmon_map = query_xmon_iocs(session, ioc_list)
    finish_stage("查询 xmon 主线索和子线索", stage_time)

    stage_time = start_stage("提取并查询 hash 文件情报")
    all_hashes: list[str] = []
    for xmon_info in xmon_map.values():
        all_hashes.extend(extract_hashes_from_xmon_info(xmon_info))
    unique_hashes = list(dict.fromkeys(h for h in all_hashes if h))
    print(f"[+] xmon 提取关联 hash：{len(unique_hashes)} 条")
    hash_map = query_hashes(session, unique_hashes)
    risk_counter = Counter(normalize_cell(info.risk).lower() or "empty" for info in hash_map.values())
    print(f"[+] hash risk 统计：{dict(risk_counter)}")
    hash_hit_count = sum(1 for info in hash_map.values() if normalize_cell(info.risk))
    black_hash_count = sum(1 for info in hash_map.values() if risk_is_black(info.risk))
    print(f"[+] hash 文件情报命中：{hash_hit_count}/{len(unique_hashes)}，黑样本 hash：{black_hash_count}")
    finish_stage("提取并查询 hash 文件情报", stage_time)

    stage_time = start_stage("查询 wfy")
    wfy_map = query_wfy(session, ioc_list)
    black_iocs = [ioc for ioc in ioc_list if wfy_is_black(wfy_map.get(ioc, {}))]
    owner_candidate_iocs = [ioc for ioc in ioc_list if not wfy_has_no_result(wfy_map.get(ioc, {}))]
    print(f"[+] wfy black IOC：{len(black_iocs)} 条")
    print(f"[+] 生产方归属候选 IOC：{len(owner_candidate_iocs)} 条")
    finish_stage("查询 wfy", stage_time)

    stage_time = start_stage("查询 sc")
    sc_map = query_sc(session, owner_candidate_iocs) if owner_candidate_iocs else {}
    finish_stage("查询 sc", stage_time)

    stage_time = start_stage("查询 wd")
    wd_candidate_iocs = [
        ioc
        for ioc in owner_candidate_iocs
        if not {"atateam", "siyubo"}.intersection(xmon_owner_candidates(xmon_map.get(ioc, empty_xmon_info(ioc))))
    ]
    print(f"[+] wd 候选 IOC：{len(wd_candidate_iocs)} 条")
    wd_map = query_wd(session, wd_candidate_iocs) if wd_candidate_iocs else {}
    finish_stage("查询 wd", stage_time)

    stage_time = start_stage("查询智能体证据链")
    ai_candidate_iocs: list[str] = []
    for ioc in ioc_list:
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
        if owner != "siyubo":
            continue
        if has_black_hash_evidence(xmon_info, hash_map):
            continue
        if pick_first_report(xmon_info.report_links):
            continue
        wd_snapshot, _ = has_wd_malicious_snapshot(wd_info)
        if wd_snapshot:
            continue
        if extract_siyubo_evidence_summary(xmon_info):
            continue
        ai_candidate_iocs.append(ioc)
    ai_map = query_ai_quick_analysis(ai_candidate_iocs) if ai_candidate_iocs else {}
    finish_stage("查询智能体证据链", stage_time)

    stage_time = start_stage("生成研判结果")
    decisions: list[RowDecision] = []
    for _, row in df.iterrows():
        ioc = normalize_cell(row.get("ioc", ""))
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        ai_info = ai_map.get(ioc, AiInfo(ioc=ioc))
        sc_malicious = sc_map.get(ioc, False)
        decision = decide_row(row, xmon_info, hash_map, wfy_info, wd_info, ai_info, sc_malicious)
        print_debug_ioc(ioc, xmon_info, hash_map, wfy_info, wd_info, sc_malicious, decision)
        decisions.append(decision)
    apply_owner_stats_fallback(decisions, wfy_map)
    finish_stage("生成研判结果", stage_time)

    stage_time = start_stage("写出 Excel")
    result_df = pd.DataFrame([decision_to_result_row(d) for d in decisions], columns=RESULT_COLUMNS)
    analysis_df = pd.DataFrame([decision_to_analysis_row(d) for d in decisions], columns=ANALYSIS_COLUMNS)
    analysis_summary_df = pd.DataFrame(build_analysis_summary_rows(decisions, wfy_map), columns=ANALYSIS_SUMMARY_COLUMNS)

    write_excel_file(result_df, RESULT_FILE)
    write_analysis_excel(analysis_df, analysis_summary_df, ANALYSIS_FILE)

    print(f"[+] 输出完成：{RESULT_FILE}")
    print(f"[+] 输出完成：{ANALYSIS_FILE}")
    finish_stage("写出 Excel", stage_time)
    print_stats(decisions)
    print_query_failures()
    elapsed = time.time() - start_time
    print(f"\n[+] 程序总耗时：{elapsed:.2f} 秒（{elapsed / 60:.2f} 分钟）")


if __name__ == "__main__":
    main()
