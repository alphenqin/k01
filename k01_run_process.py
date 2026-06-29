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
import ipaddress
import json
import os
import random
import re
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
OUTPUT_TIME_SUFFIX = time.strftime("%Y%m%d_%H%M%S")
RESULT_FILE = os.getenv("K01_RESULT_FILE", os.path.join(OUTPUT_DIR, f"k01_result_{OUTPUT_TIME_SUFFIX}.xlsx"))
ANALYSIS_FILE = os.getenv("K01_ANALYSIS_FILE", os.path.join(OUTPUT_DIR, f"k01_analysis_{OUTPUT_TIME_SUFFIX}.xlsx"))

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
AI_KEY_EVIDENCE_DROP_TERMS = ("外部威胁情报", "威胁情报状态", "外部")
AI_EVIDENCE_PROMPT = (
    "将以下内容汇总为一句完整的情报研判依据，长度50字左右，必须以句号结尾，不要输出半句话或泛化短语。"
    "若信息不足以形成依据，请返回空字符串。不要输出安全声明、伦理声明、拒答说明或无关建议。"
)

# ===== 大模型公共配置 =====
LLM_API_URL = os.getenv("K01_LLM_API_URL", "https://api.360.cn/v1/chat/completions")
LLM_MODEL = os.getenv("K01_LLM_MODEL", "deepseek/deepseek-v4-flash-internal")
LLM_TOKEN = os.getenv("K01_LLM_TOKEN", "fk3631605771.SW4G9234O44_fCdZNjrfq4KjcJFrmini5f2f056c")  # 如需使用大模型能力，在这里或环境变量填写 token。
LLM_SUMMARY_MAX_TOKENS = 1500  # 该接口会按 max_tokens 裁剪 messages，摘要场景不要设得过低。
LLM_EVIDENCE_MAX_INPUT_CHARS = 1000  # 主动限制证据输入长度，避免服务端不可控截断。

# ===== siyubo evidence_chain 总结配置 =====
SIYUBO_NO_RESULT = "信息有限，无对应研判结果"
SIYUBO_NO_RESULT_TERMS = ("无法研判", "无法判断", "不能研判", "信息有限", "无对应研判结果")
SIYUBO_HIT_TERMS = ("恶意", "可疑", "怀疑", "风险")
SIYUBO_EVIDENCE_PROMPT = (
    "请先判断evidence_chain中的detail是否能支持该IOC为恶意、风险或可疑IOC。"
    "只要出现可疑、潜在风险等可疑依据，"
    "即使证据不足以确认恶意，也输出一条50字左右的情报研判依据。"
    "如果完全没有恶意/风险/可疑依据，或只是备案正常、证书正常、DNS稳定、样本clean/safe、"
    f"未发现恶意、信息不足、无法研判，或显示IOC已sinkhole/被sinkhole等内容，只输出：{SIYUBO_NO_RESULT}。"
    "不要输出判断过程、编号、前缀或解释。"
)
AI_NO_RESULT_TERMS = ("无法研判", "无法判断", "不能研判", "信息有限", "无对应研判结果", "信息不足", "空字符串")
AI_REFUSAL_TERMS = ("无法回答", "不能回答", "有益知识", "法律与道德", "有建设性的话题", "遵守所有相关")
AI_SUMMARY_MIN_CHARS = 15
AI_GENERIC_SUMMARIES = {"360标记", "360威胁情报", "高危域名", "恶意域名", "威胁情报"}
AI_COMPLETE_SUMMARY_ENDINGS = ("。", "！", "？", ".", "!", "?")

# ===== 性能控制配置 =====
# 这些配置直接改脚本即可，不依赖环境变量。
REQUEST_TIMEOUT = 60  # 单次 HTTP 请求超时时间，单位秒；外部接口慢时可适当调大。
HTTP_POOL_CONNECTIONS = 100  # requests 连接池保留的连接池数量；通常无需调整。
HTTP_POOL_MAXSIZE = 100  # 每个连接池最大连接数；应不小于主要接口的并发数。
XMON_WORKERS = 4  # xmon 主线索和子线索批次查询并发数；过高可能压垮内网接口。
XMON_BATCH_SIZE = 3000  # xmon 主线索每批最多 IOC 数；还会受 URL 64KB 限制。
XMON_TAGMON_BATCH_SIZE = 100  # xmon 子线索每批最多 IOC 数；子线索返回总数受 limit=1000 影响。
XMON_MAX_URL_BYTES = 64 * 1024  # xmon GET URL 最大字节数；超过会自动拆批。
XMON_PROGRESS_INTERVAL = 100  # xmon 每处理多少条 IOC 打印一次进度。
XMON_TAGMON_ENABLED = True  # 是否查询 xmon 子线索；关闭会更快，但会丢失子线索 hash/src/evidence_chain。
XMON_TAGMON_RETRIES = 3  # xmon 子线索查询失败后的重试次数。
XMON_TAGMON_RETRY_SLEEP = 3.0  # xmon 子线索每次重试前等待秒数。
HASH_WORKERS = 8  # 文件情报 hash 查询批次并发数。
HASH_BATCH_SIZE = 10  # 文件情报每批 hash 数。
HASH_MAX_BATCH_SIZE = 10  # 文件情报接口允许的最大批量；用于防止误改超限。
HASH_PROGRESS_INTERVAL = 200  # hash 查询每处理多少条打印一次进度。
WFY_WORKERS = 4  # wfy 批次查询并发数；过高容易触发 429 限流。
WFY_BATCH_SIZE = 100  # wfy 每批 IOC 数。
WFY_MAX_BATCH_SIZE = 100  # wfy 接口允许的最大批量；用于防止误改超限。
WFY_PROGRESS_INTERVAL = 100  # wfy 每处理多少条 IOC 打印一次进度。
WFY_RETRIES = 4  # wfy 遇到 429 或临时异常时的最大重试次数。
WFY_RETRY_SLEEP_SECONDS = 2.0  # wfy 重试退避基准秒数；实际等待按 2、4、8... 递增。
SC_WORKERS = 12  # sc 批次查询并发数。
SC_BATCH_SIZE = 80  # sc 每批 IOC 数；payload 中 query.value 用英文逗号拼接。
SC_PROGRESS_INTERVAL = 100  # sc 每处理多少条 IOC 打印一次进度。
WD_WORKERS = 12  # wd 查询并发数；safe 评分按批次并发，恶意 IOC 再单条查 urldb 快照。
WD_SAFE_BATCH_SIZE = 20  # wd safe 评分接口每批 IOC 数。
WD_SAFE_MAX_BATCH_SIZE = 20  # wd safe 评分接口允许的最大批量；第 21 条起会被接口静默截断。
WD_PROGRESS_INTERVAL = 100  # wd 每处理多少条 IOC 打印一次进度。
AI_WORKERS = 24  # 智能体证据链接口并发数；接口不支持批量，过高容易 500/502/超时。
AI_PROGRESS_INTERVAL = 100  # 智能体证据链每处理多少条 IOC 打印一次进度。
AI_RETRIES = 3  # 智能体证据链接口失败后的重试次数。
AI_RETRY_SLEEP_SECONDS = 5.0  # 智能体证据链重试退避基准秒数；实际等待按 5、10、15... 递增。
LLM_WORKERS = 24  # 大模型接口并发数；外部模型接口不宜过高。
LLM_RETRIES = 3  # 大模型接口失败后的重试次数。
LLM_RETRY_SLEEP_SECONDS = 2.0  # 大模型接口重试等待秒数。
FAILED_IOC_RERUNS = 2  # 异常 IOC 全流程额外重跑轮数；1 表示首次失败后再从头补跑 1 轮。
SLEEP_SECONDS = 0.05  # 串行分支中每次请求后的短暂停顿，降低接口压力。
LIMIT = 0  # 调试用输入行数限制；0 表示不限制，处理全部输入。
XMON_MIN_SEVERITY = 30  # xmon 有效线索最低 severity 阈值；当前规则为 severity > 30。
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
    "拼接后的ioc",
]

ANALYSIS_COLUMNS = ["ioc外联目标", "端口", "厂商", "ioc", "生产方归属", "能否解决", "相关解决方案"]
ANALYSIS_SUMMARY_COLUMNS = ["序号", "统计信息"]
ANALYSIS_OWNER_SHEETS = ["atateam", "siyubo", "wd", "netlab", "unknown"]
AI_EVIDENCE_PROBLEM_TEXT = "无对应上下文支持；如关联样本，关联报告，生产方式，排查指引，站点主题等"

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
SIYUBO_LLM_REJECTED_SUMMARIES: list[str] = []
AI_LLM_REJECTED_SUMMARIES: list[str] = []
LLM_FAILED_IOCS: list[str] = []
WD_SNAPSHOT_TOPIC_SUMMARY_CACHE: dict[str, str] = {}
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
    snapshot_title: str = ""
    snapshot_content: str = ""
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


def json_utf8_body(value: Any, **kwargs: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, **kwargs).encode("utf-8")


def normalize_cell(value: Any) -> str:
    text = stringify(value).strip()
    if text in {"--", "nan", "NaN", "None"}:
        return ""
    if re.fullmatch(r"\d+\.0", text):
        return text[:-2]
    return text


def normalize_epoch_seconds(value: int) -> int:
    if value > 10_000_000_000:
        return value // 1000
    return value


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
        value = normalize_epoch_seconds(value)
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


def extract_main_report_link_values(row: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    value = row.get("report_links")
    if has_meaningful_value(value):
        values.append(value)
    return values


def extract_child_report_link_values(row: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    value = exts.get("report_link")
    if has_meaningful_value(value):
        values.append(value)
    return values


def collect_xmon_report_links(row: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for value in extract_main_report_link_values(row):
        candidates.extend(build_report_candidates(value, source="main"))

    child_rows = row.get("__tagmon_children")
    if isinstance(child_rows, list):
        for child in child_rows:
            if isinstance(child, dict):
                utime = child.get("utime")
                for value in extract_child_report_link_values(child):
                    candidates.extend(build_report_candidates(value, source="sub", timestamp=report_timestamp_from_value(utime)))
    return candidates


def normalize_xmon_row(ioc: str, row: dict[str, Any]) -> XmonInfo:
    raw = row.get("Raw") if isinstance(row.get("Raw"), dict) else {}
    return XmonInfo(
        ioc_search=first_not_empty(row.get("ioc_search"), row.get("ioc"), row.get("IOC"), row.get("uid"), ioc),
        disable=extract_xmon_disable(row, raw),
        status=first_not_empty(row.get("status"), row.get("Status"), raw.get("status"), raw.get("Status")),
        ref_sample=row.get("ref_sample", ""),
        report_links=collect_xmon_report_links(row),
        raw=row,
    )


def empty_xmon_info(ioc: str) -> XmonInfo:
    return XmonInfo(ioc_search=ioc)


def build_xmon_batch_url(batch: list[str]) -> str:
    ioc_part = ",".join(quote(x, safe=".:_-") for x in batch)
    return f"{XMON_BASE_URL}{ioc_part}/{XMON_QUERY}"


def build_xmon_tagmon_url(iocs: list[str] | str) -> str:
    if isinstance(iocs, str):
        ioc_part = quote(iocs, safe=".:_-")
    else:
        ioc_part = ",".join(quote(x, safe=".:_-") for x in iocs)
    return f"{XMON_TAGMON_BASE_URL}{ioc_part}{XMON_TAGMON_SUFFIX}"


def chunk_xmon_iocs_by_url(iocs: list[str], url_builder, max_count: int = XMON_BATCH_SIZE) -> list[list[str]]:
    batches: list[list[str]] = []
    current: list[str] = []
    for ioc in iocs:
        candidate = current + [ioc]
        if current and (len(candidate) > max_count or len(url_builder(candidate).encode("utf-8")) > XMON_MAX_URL_BYTES):
            batches.append(current)
            current = [ioc]
            if len(url_builder(current).encode("utf-8")) > XMON_MAX_URL_BYTES:
                batches.append(current)
                current = []
        else:
            current = candidate
    if current:
        batches.append(current)
    return batches


def group_xmon_rows_by_ioc(rows: list[dict[str, Any]], prefer_search: bool = False) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if prefer_search:
            ioc = normalize_cell(first_not_empty(row.get("ioc_search"), row.get("ioc"), row.get("IOC"), row.get("uid")))
        else:
            ioc = normalize_cell(xmon_row_ioc(row))
        if not ioc:
            continue
        grouped.setdefault(ioc, []).append(row)
    return grouped


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


def build_xmon_valid_clues(main_row: dict[str, Any], child_rows: list[dict[str, Any]], requested_ioc: str = "") -> list[dict[str, Any]]:
    main_disable = extract_main_ioc_disabled(main_row)
    main_ioc = normalize_cell(requested_ioc) or normalize_cell(main_row.get("ioc", ""))
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


def query_xmon_tagmon_batch(batch: list[str]) -> tuple[list[str], dict[str, list[dict[str, Any]]], str]:
    if not XMON_TAGMON_ENABLED or not batch:
        return batch, {ioc: [] for ioc in batch}, ""
    session = get_thread_session()
    url = build_xmon_tagmon_url(batch)
    last_error = ""
    max_attempts = XMON_TAGMON_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(XMON_TAGMON_RETRY_SLEEP)
        try:
            resp = session.get(url, headers=XMON_HEADERS, verify=False, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            grouped = group_xmon_rows_by_ioc(extract_xmon_rows(safe_json_response(resp)))
            for ioc in batch:
                grouped.setdefault(ioc, [])
            return batch, grouped, ""
        except Exception as exc:
            last_error = str(exc)
    return batch, {ioc: [] for ioc in batch}, last_error


def query_xmon_tagmon_children_many(iocs: list[str]) -> dict[str, list[dict[str, Any]]]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in iocs if ioc))
    if not XMON_TAGMON_ENABLED or not unique_iocs:
        return {ioc: [] for ioc in unique_iocs}
    batches = chunk_xmon_iocs_by_url(unique_iocs, build_xmon_tagmon_url, XMON_TAGMON_BATCH_SIZE)
    if XMON_WORKERS <= 1 or len(batches) == 1:
        result_map: dict[str, list[dict[str, Any]]] = {}
        for batch in batches:
            _, grouped, error = query_xmon_tagmon_batch(batch)
            if error:
                with TAGMON_FAILED_LOCK:
                    TAGMON_FAILED_IOCS.extend(f"{ioc} | {error}" for ioc in batch)
            result_map.update(grouped)
        return result_map

    result_map: dict[str, list[dict[str, Any]]] = {}
    worker_count = min(XMON_WORKERS, len(batches))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_xmon_tagmon_batch, batch): batch
            for batch in batches
        }
        for future in as_completed(future_map):
            batch = future_map[future]
            try:
                batch, grouped, error = future.result()
                result_map.update(grouped)
                if error:
                    with TAGMON_FAILED_LOCK:
                        TAGMON_FAILED_IOCS.extend(f"{ioc} | {error}" for ioc in batch)
            except Exception as exc:
                with TAGMON_FAILED_LOCK:
                    TAGMON_FAILED_IOCS.extend(f"{ioc} | {exc}" for ioc in batch)
                for ioc in batch:
                    result_map[ioc] = []
    return result_map


def query_xmon_main_batch(batch: list[str]) -> tuple[list[str], dict[str, list[dict[str, Any]]], str]:
    session = get_thread_session()
    url = build_xmon_batch_url(batch)
    try:
        resp = session.get(url, headers=XMON_HEADERS, verify=False, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        grouped = group_xmon_rows_by_ioc(extract_xmon_rows(safe_json_response(resp)), prefer_search=True)
        for ioc in batch:
            grouped.setdefault(ioc, [])
        return batch, grouped, ""
    except Exception as exc:
        return batch, {ioc: [] for ioc in batch}, str(exc)


def build_xmon_info_from_rows(requested_ioc: str, rows: list[dict[str, Any]], child_map: dict[str, list[dict[str, Any]]]) -> XmonInfo:
    if not rows:
        return empty_xmon_info(requested_ioc)
    row = rows[0]
    main_ioc = normalize_cell(row.get("ioc", "")) or requested_ioc
    child_rows = child_map.get(requested_ioc, child_map.get(main_ioc, []))
    enriched_row = dict(row)
    enriched_row["__tagmon_children"] = child_rows
    enriched_row["__valid_clues"] = build_xmon_valid_clues(row, child_rows, requested_ioc)
    return normalize_xmon_row(requested_ioc, enriched_row)


def query_xmon_iocs(session: Session, ioc_list: list[str]) -> dict[str, XmonInfo]:
    result_map: dict[str, XmonInfo] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return {}

    resolvable, resolve_error = can_resolve_host(XMON_BASE_URL)
    if not resolvable:
        host = urlparse(XMON_BASE_URL).hostname
        error = f"xmon 域名无法解析，跳过 xmon 查询：{host}，错误：{resolve_error}"
        print(f"[!] {error}")
        print("[!] 请确认当前环境能访问内网 DNS/VPN，或在 WSL/Linux 中配置可解析 xmon.netlab.qihoo.net 的 DNS/hosts。")
        XMON_FAILED_IOCS.extend(f"{ioc} | {error}" for ioc in query_iocs)
        return {ioc: result_map.get(ioc, empty_xmon_info(ioc)) for ioc in ioc_list}

    main_batches = chunk_xmon_iocs_by_url(query_iocs, build_xmon_batch_url)
    max_url_bytes = max((len(build_xmon_batch_url(batch).encode("utf-8")) for batch in main_batches), default=0)
    print(
        f"[+] xmon 主线索待查询：{len(query_iocs)} 条，批量最多 {XMON_BATCH_SIZE} 条/批，"
        f"实际 {len(main_batches)} 批，最大 URL {max_url_bytes} bytes"
    )

    main_rows_map: dict[str, list[dict[str, Any]]] = {}
    worker_count = min(XMON_WORKERS, len(main_batches))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_xmon_main_batch, batch): batch for batch in main_batches}
        for future in as_completed(future_map):
            batch = future_map[future]
            try:
                batch, grouped, error = future.result()
            except Exception as exc:
                grouped = {ioc: [] for ioc in batch}
                error = str(exc)
            main_rows_map.update(grouped)
            if error:
                XMON_FAILED_IOCS.extend(f"{ioc} | {error}" for ioc in batch)
            completed += len(batch)
            if completed % XMON_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] xmon 主线索查询进度：{completed}/{len(query_iocs)}")

    main_iocs = [requested_ioc for requested_ioc, rows in main_rows_map.items() if rows]
    child_batches = chunk_xmon_iocs_by_url(list(dict.fromkeys(main_iocs)), build_xmon_tagmon_url, XMON_TAGMON_BATCH_SIZE)
    child_max_url_bytes = max((len(build_xmon_tagmon_url(batch).encode("utf-8")) for batch in child_batches), default=0)
    print(
        f"[+] xmon 子线索待查询：{len(set(main_iocs))} 条，批量最多 {XMON_TAGMON_BATCH_SIZE} 条/批，"
        f"实际 {len(child_batches)} 批，最大 URL {child_max_url_bytes} bytes"
    )
    child_map = query_xmon_tagmon_children_many(main_iocs)

    for requested_ioc in query_iocs:
        result_map[requested_ioc] = build_xmon_info_from_rows(
            requested_ioc,
            main_rows_map.get(requested_ioc, []),
            child_map,
        )
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
            data=json_utf8_body(payload),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return safe_json_response(resp)
    except Exception as exc:
        with HASH_FAILED_LOCK:
            HASH_FAILED_QUERIES.append(f"{','.join(hash_list)} | {exc}")
        return {"errno": -1, "msg": str(exc), "result": {}}


def query_hash_batch_worker(hash_batch: list[str]) -> tuple[list[str], dict[str, HashInfo]]:
    response_json = query_hash_batch(get_thread_session(), hash_batch)
    parsed = parse_hash_result(hash_batch, response_json)
    return hash_batch, parsed


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
    batch_size = min(HASH_BATCH_SIZE, HASH_MAX_BATCH_SIZE)
    batches = chunk_list(unique_hashes, batch_size)
    print(
        f"[+] 查询 hash：{len(unique_hashes)} 条，批量 {batch_size} 条/批，"
        f"并发数 {min(HASH_WORKERS, len(batches))}"
    )
    if HASH_WORKERS <= 1 or len(batches) == 1:
        completed = 0
        for hash_batch in batches:
            response_json = query_hash_batch(session, hash_batch)
            parsed = parse_hash_result(hash_batch, response_json)
            all_hash_map.update(parsed)
            completed += len(hash_batch)
            if completed % HASH_PROGRESS_INTERVAL == 0 or completed == len(unique_hashes):
                print(f"[+] hash 查询进度：{completed}/{len(unique_hashes)}")
            time.sleep(SLEEP_SECONDS)
        return all_hash_map

    worker_count = min(HASH_WORKERS, len(batches))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_hash_batch_worker, hash_batch): hash_batch for hash_batch in batches}
        for future in as_completed(future_map):
            hash_batch = future_map[future]
            try:
                hash_batch, parsed = future.result()
                all_hash_map.update(parsed)
            except Exception as exc:
                with HASH_FAILED_LOCK:
                    HASH_FAILED_QUERIES.append(f"{','.join(hash_batch)} | {exc}")
                for hash_value in hash_batch:
                    all_hash_map[hash_value] = HashInfo(query_hash=hash_value)
            completed += len(hash_batch)
            if completed % HASH_PROGRESS_INTERVAL == 0 or completed == len(unique_hashes):
                print(f"[+] hash 查询进度：{completed}/{len(unique_hashes)}")
    return all_hash_map


def query_wfy_batch(batch: list[str]) -> tuple[list[str], dict[str, dict[str, Any]], str]:
    last_error = ""
    max_attempts = WFY_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        try:
            session = get_thread_session()
            resp = session.post(
                WFY_API_URL,
                headers=WFY_HEADERS,
                data=json_utf8_body(batch),
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 429 and attempt < max_attempts:
                retry_after = safe_int(resp.headers.get("Retry-After"), 0)
                sleep_seconds = retry_after if retry_after > 0 else WFY_RETRY_SLEEP_SECONDS * (2 ** (attempt - 1))
                time.sleep(sleep_seconds)
                continue
            resp.raise_for_status()
            data = safe_json_response(resp)
            return batch, parse_wfy_response(batch, data), ""
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_attempts:
                time.sleep(WFY_RETRY_SLEEP_SECONDS * (2 ** (attempt - 1)))
                continue
            return batch, {ioc: {"query_error": last_error, "judge": ""} for ioc in batch}, last_error
    last_error = last_error or "wfy query failed"
    return batch, {ioc: {"query_error": last_error, "judge": ""} for ioc in batch}, last_error


def query_wfy(session: Session, ioc_list: list[str]) -> dict[str, dict[str, Any]]:
    result_map: dict[str, dict[str, Any]] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return result_map
    batch_size = min(WFY_BATCH_SIZE, WFY_MAX_BATCH_SIZE)
    batches = chunk_list(query_iocs, batch_size)
    print(
        f"[+] wfy 待查询：{len(query_iocs)} 条，批量 {batch_size} 条/批，"
        f"并发数 {min(WFY_WORKERS, len(batches))}，429/异常最多重试 {WFY_RETRIES} 次"
    )

    if WFY_WORKERS <= 1 or len(batches) == 1:
        completed = 0
        for batch in batches:
            _, parsed, error = query_wfy_batch(batch)
            result_map.update(parsed)
            if error:
                for ioc in batch:
                    WFY_FAILED_QUERIES.append(f"{ioc} | {error}")
            completed += len(batch)
            if completed % WFY_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] wfy 查询进度：{completed}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(WFY_WORKERS, len(batches))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_wfy_batch, batch): batch for batch in batches}
        for future in as_completed(future_map):
            fallback_batch = future_map[future]
            try:
                batch, parsed, error = future.result()
            except Exception as exc:
                batch = fallback_batch
                error = str(exc)
                parsed = {ioc: {"query_error": error, "judge": ""} for ioc in batch}
            result_map.update(parsed)
            if error:
                for ioc in batch:
                    WFY_FAILED_QUERIES.append(f"{ioc} | {error}")
            completed += len(batch)
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


def query_custom_tags_batch(
    session: Session,
    batch: list[str],
    category: str | None = None,
) -> tuple[list[str], dict[str, dict[str, Any]], str]:
    query_category = category or SC_DEFAULT_CATEGORY
    query_value = ",".join(batch)
    payload = {
        "query": {
            "keywords": [
                {"field": "category", "value": query_category},
                {"field": "query", "value": query_value},
                {"field": "flag", "value": "2"},
            ]
        }
    }
    try:
        resp = session.post(
            TAGS_API_URL,
            headers=make_ti_headers(),
            data=json_utf8_body(payload),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        return batch, parse_sc_response(batch, data), ""
    except Exception as exc:
        return batch, {ioc: {"query_error": str(exc)} for ioc in batch}, str(exc)


def query_custom_tags_batch_worker(batch: list[str]) -> tuple[list[str], dict[str, dict[str, Any]], str]:
    return query_custom_tags_batch(get_thread_session(), batch)


def parse_sc_response(batch: list[str], data: Any) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    body = data.get("data") if isinstance(data, dict) else data
    if isinstance(body, dict):
        for ioc in batch:
            value = body.get(ioc, {})
            parsed[ioc] = value if isinstance(value, dict) else {"value": value}
    elif isinstance(body, list):
        for item in body:
            if not isinstance(item, dict):
                continue
            ioc = first_not_empty(item.get("ioc"), item.get("query"), item.get("domain"), item.get("ip"))
            if ioc:
                parsed[ioc] = item
    for ioc in batch:
        parsed.setdefault(ioc, {})
    return parsed


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
    return level is not None and level > 30


def query_sc(session: Session, ioc_list: list[str]) -> dict[str, bool]:
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    sc_map: dict[str, bool] = {}
    if not query_iocs:
        return sc_map
    batches = chunk_list(query_iocs, SC_BATCH_SIZE)
    print(
        f"[+] sc 待查询：{len(query_iocs)} 条，批量 {SC_BATCH_SIZE} 条/批，"
        f"并发数 {min(SC_WORKERS, len(batches))}"
    )

    if SC_WORKERS <= 1 or len(batches) == 1:
        completed = 0
        for batch in batches:
            _, parsed, error = query_custom_tags_batch(session, batch)
            if error:
                for ioc in batch:
                    SC_FAILED_IOCS.append(f"{ioc} | {error}")
            for ioc in batch:
                sc_map[ioc] = sc_is_malicious(parsed.get(ioc, {}))
            completed += len(batch)
            if completed % SC_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] sc 查询进度：{completed}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
    else:
        worker_count = min(SC_WORKERS, len(batches))
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(query_custom_tags_batch_worker, batch): batch for batch in batches}
            for future in as_completed(future_map):
                fallback_batch = future_map[future]
                try:
                    batch, parsed, error = future.result()
                except Exception as exc:
                    batch = fallback_batch
                    parsed = {}
                    error = str(exc)
                if error:
                    for ioc in batch:
                        SC_FAILED_IOCS.append(f"{ioc} | {error}")
                for ioc in batch:
                    sc_map[ioc] = sc_is_malicious(parsed.get(ioc, {}))
                completed += len(batch)
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


def query_wd_safe_batch(batch: list[str]) -> tuple[list[str], dict[str, WdInfo], str]:
    body = json.dumps({"data": [{"url": ioc} for ioc in batch]}, ensure_ascii=False, separators=(",", ":"))
    try:
        session = get_thread_session()
        resp = session.post(
            WD_SAFE_API_URL,
            data=body.encode("utf-8"),
            headers=make_wd_safe_headers(body),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        results = (((data.get("data") or {}).get("results") or []) if isinstance(data, dict) else [])
        result_map: dict[str, WdInfo] = {}
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                ioc = normalize_cell(item.get("url", ""))
                if not ioc:
                    continue
                info = item.get("info") if isinstance(item.get("info"), dict) else {}
                level = safe_int(info.get("level"), 0)
                sub_level = safe_int(info.get("sub_level"), 0)
                result_map[ioc] = WdInfo(
                    ioc=ioc,
                    level=level,
                    sub_level=sub_level,
                    malicious=level >= 50,
                )
        for ioc in batch:
            result_map.setdefault(ioc, WdInfo(ioc=ioc, query_error="wd safe empty result"))
        return batch, result_map, ""
    except Exception as exc:
        error = str(exc)
        return batch, {ioc: WdInfo(ioc=ioc, query_error=error) for ioc in batch}, error


def wd_snapshot_row_has_content(row: dict[str, Any]) -> bool:
    title = wd_snapshot_row_title(row)
    content = wd_snapshot_row_content(row)
    return bool(content) and not wd_snapshot_is_error_page(title, content)


def wd_snapshot_is_error_page(title: str, content: str) -> bool:
    text = normalize_cell(f"{title} {content}").lower()
    if not text:
        return False
    error_terms = (
        "403 forbidden",
        "404 not found",
        "400 bad request",
        "401 unauthorized",
        "502 bad gateway",
        "503 service temporarily unavailable",
        "504 gateway timeout",
        "access denied",
        "forbidden",
        "not found",
    )
    if any(term in text for term in error_terms):
        server_terms = ("nginx", "apache", "iis", "openresty", "cloudflare")
        return any(term in text for term in server_terms) or len(text) < 300
    return False


def wd_snapshot_row_title(row: dict[str, Any]) -> str:
    return first_not_empty(
        row.get("title"),
        row.get("page_title"),
        row.get("html_title"),
        row.get("site_title"),
    )


def wd_snapshot_row_content(row: dict[str, Any]) -> str:
    content = first_not_empty(
        row.get("content"),
        row.get("text"),
        row.get("summary"),
        row.get("html"),
        row.get("snapshot"),
    )
    text = normalize_cell(content)
    if not text:
        return ""
    text = re.sub(r"(?is)<script.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:4000]


def query_wd_history_snapshot(session: Session, ioc: str) -> tuple[bool, str, str, str, str]:
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
            return False, "", "", "", "wd history data is not list"
        snapshot_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if wd_snapshot_row_has_content(row):
                snapshot_rows.append(row)
        if not snapshot_rows:
            return False, "", "", "", ""
        title = first_not_empty(*(wd_snapshot_row_title(row) for row in snapshot_rows))
        content = first_not_empty(*(wd_snapshot_row_content(row) for row in snapshot_rows))
        topic = title
        return True, topic, title, content, ""
    except Exception as exc:
        return False, "", "", "", str(exc)


def query_wd_history_one(ioc: str) -> tuple[str, bool, str, str, str, str]:
    session = get_thread_session()
    has_snapshot, topic, title, content, error = query_wd_history_snapshot(session, ioc)
    return ioc, has_snapshot, topic, title, content, error


def query_wd(session: Session, ioc_list: list[str]) -> dict[str, WdInfo]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    result_map: dict[str, WdInfo] = {}
    if not unique_iocs:
        return result_map

    safe_batch_size = min(WD_SAFE_BATCH_SIZE, WD_SAFE_MAX_BATCH_SIZE)
    safe_batches = chunk_list(unique_iocs, safe_batch_size)
    print(
        f"[+] wd safe 评分待查询：{len(unique_iocs)} 条，批量 {safe_batch_size} 条/批，"
        f"并发数 {min(WD_WORKERS, len(safe_batches))}"
    )
    if WD_WORKERS <= 1 or len(safe_batches) == 1:
        completed = 0
        for batch in safe_batches:
            _, parsed, error = query_wd_safe_batch(batch)
            result_map.update(parsed)
            if error:
                for ioc in batch:
                    WD_FAILED_IOCS.append(f"{ioc} | {error}")
            completed += len(batch)
            if completed % WD_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
                print(f"[+] wd safe 评分查询进度：{completed}/{len(unique_iocs)}")
            time.sleep(SLEEP_SECONDS)
    else:
        worker_count = min(WD_WORKERS, len(safe_batches))
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(query_wd_safe_batch, batch): batch for batch in safe_batches}
            for future in as_completed(future_map):
                batch = future_map[future]
                try:
                    batch, parsed, error = future.result()
                except Exception as exc:
                    error = str(exc)
                    parsed = {ioc: WdInfo(ioc=ioc, query_error=error) for ioc in batch}
                result_map.update(parsed)
                if error:
                    for ioc in batch:
                        WD_FAILED_IOCS.append(f"{ioc} | {error}")
                completed += len(batch)
                if completed % WD_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
                    print(f"[+] wd safe 评分查询进度：{completed}/{len(unique_iocs)}")

    malicious_iocs = [ioc for ioc, info in result_map.items() if info.malicious]
    if not malicious_iocs:
        return result_map

    print(f"[+] wd urldb 快照待查询：{len(malicious_iocs)} 条，并发数 {min(WD_WORKERS, len(malicious_iocs))}")
    if WD_WORKERS <= 1 or len(malicious_iocs) == 1:
        for index, ioc in enumerate(malicious_iocs, 1):
            _, has_snapshot, topic, title, content, snapshot_error = query_wd_history_one(ioc)
            info = result_map.get(ioc, WdInfo(ioc=ioc))
            info.has_snapshot = has_snapshot
            info.snapshot_topic = topic
            info.snapshot_title = title
            info.snapshot_content = content
            if snapshot_error:
                info.query_error = "; ".join(x for x in (info.query_error, snapshot_error) if x)
                WD_FAILED_IOCS.append(f"{ioc} | {snapshot_error}")
            result_map[ioc] = info
            if index % WD_PROGRESS_INTERVAL == 0 or index == len(malicious_iocs):
                print(f"[+] wd urldb 快照查询进度：{index}/{len(malicious_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    completed = 0
    with ThreadPoolExecutor(max_workers=min(WD_WORKERS, len(malicious_iocs))) as executor:
        future_map = {executor.submit(query_wd_history_one, ioc): ioc for ioc in malicious_iocs}
        for future in as_completed(future_map):
            ioc = future_map[future]
            completed += 1
            try:
                _, has_snapshot, topic, title, content, snapshot_error = future.result()
            except Exception as exc:
                has_snapshot, topic, title, content, snapshot_error = False, "", "", "", str(exc)
            info = result_map.get(ioc, WdInfo(ioc=ioc))
            info.has_snapshot = has_snapshot
            info.snapshot_topic = topic
            info.snapshot_title = title
            info.snapshot_content = content
            if snapshot_error:
                info.query_error = "; ".join(x for x in (info.query_error, snapshot_error) if x)
                WD_FAILED_IOCS.append(f"{ioc} | {snapshot_error}")
            result_map[ioc] = info
            if completed % WD_PROGRESS_INTERVAL == 0 or completed == len(malicious_iocs):
                print(f"[+] wd urldb 快照查询进度：{completed}/{len(malicious_iocs)}")
    return result_map


def wfy_is_black(wfy_info: dict[str, Any]) -> bool:
    judge = normalize_cell(first_not_empty(wfy_info.get("judge"), wfy_info.get("verdict"), wfy_info.get("label"))).lower()
    return judge == "black"


def risk_is_black(risk: str) -> bool:
    return normalize_cell(risk).lower() in BLACK_RISKS


def risk_is_white(risk: str) -> bool:
    return normalize_cell(risk).lower() in WHITE_RISKS


def map_k01_status(xmon_status: Any) -> str:
    status = normalize_cell(xmon_status).upper()
    status_map = {
        "ACTIVE": "存活",
        "UNKNOWN": "存活",
        "OVER": "失活",
        "SINKHOLE": "被安全机构接管",
    }
    return status_map.get(status, status)


REPORT_DEFAULT_TIMESTAMP = 0
REPORT_URL_RE = re.compile(r"https?://[^\s\"'<>，；、（）()\\\\]+")
REPORT_DATETIME_PATTERNS = (
    re.compile(r"(?P<date>\d{4}[-/]\d{1,2}[-/]\d{1,2})(?:[T_\s]+(?P<time>\d{1,2}[:：]\d{1,2}(?:[:：]\d{1,2})?))?"),
    re.compile(r"(?P<date>\d{8})[_-]?(?P<time>\d{6})"),
)
REPORT_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


def clean_report_url(url: str) -> str:
    text = normalize_cell(url).strip().strip("\"'").rstrip(".,;，；。")
    if not text:
        return ""
    for marker in ("@Version:", "@version:", "@VERSION:", "@"):
        if marker in text:
            text = text.split(marker, 1)[0]
            break
    if "#" in text:
        text = text.split("#", 1)[0]
    return text.rstrip(".,;，；。")


def is_valid_report_url(url: str) -> bool:
    if not url or re.search(r"\s|\\", url):
        return False
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    if parsed.username or parsed.password:
        return False
    try:
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False
    except ValueError:
        return False

    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(REPORT_HOST_RE.fullmatch(host))


def report_timestamp_from_value(value: Any) -> int:
    text = normalize_cell(value)
    if not text:
        return REPORT_DEFAULT_TIMESTAMP

    numeric = text.strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", numeric):
        try:
            timestamp = int(float(numeric))
            timestamp = normalize_epoch_seconds(timestamp)
            return timestamp if timestamp > 0 else REPORT_DEFAULT_TIMESTAMP
        except Exception:
            pass

    best_timestamp = REPORT_DEFAULT_TIMESTAMP
    for pattern in REPORT_DATETIME_PATTERNS:
        for match in pattern.finditer(text):
            date_part = match.group("date")
            time_part = match.groupdict().get("time") or "00:00:00"
            try:
                if len(date_part) == 8:
                    normalized = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]} {time_part[:2]}:{time_part[2:4]}:{time_part[4:6]}"
                else:
                    if time_part.count(":") == 1 or time_part.count("：") == 1:
                        time_part = f"{time_part}:00"
                    normalized = f"{date_part.replace('/', '-')} {time_part.replace('：', ':')}"
                dt = datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S")
                best_timestamp = max(best_timestamp, int(dt.replace(tzinfo=timezone.utc).timestamp()))
            except Exception:
                continue
    return best_timestamp


def iter_report_text_values(value: Any) -> list[Any]:
    data = parse_literal_or_json(value)
    if isinstance(data, dict):
        values: list[Any] = list(data.keys()) + list(data.values())
    elif isinstance(data, list):
        values = data
    else:
        values = [data]
    return values


def build_report_candidates(value: Any, source: str = "", timestamp: int | None = None) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in iter_report_text_values(value):
        if isinstance(item, (dict, list)):
            candidates.extend(build_report_candidates(item, source=source, timestamp=timestamp))
            continue
        text = stringify(item)
        item_timestamp = report_timestamp_from_value(text) if timestamp is None else timestamp
        for match in REPORT_URL_RE.findall(text):
            url = clean_report_url(match)
            if is_valid_report_url(url):
                candidates.append({"url": url, "timestamp": item_timestamp, "source": source})
    return candidates


def normalize_report_url(url: str) -> str:
    return clean_report_url(url)


def pick_first_report(report_links: Any) -> str:
    if isinstance(report_links, list) and all(isinstance(item, dict) and "url" in item for item in report_links):
        candidates = report_links
    else:
        candidates = build_report_candidates(report_links)

    best_url = ""
    best_timestamp = -1
    for candidate in candidates:
        url = normalize_report_url(candidate.get("url", ""))
        if not is_valid_report_url(url):
            continue
        timestamp = safe_int(candidate.get("timestamp"), REPORT_DEFAULT_TIMESTAMP)
        if timestamp > best_timestamp:
            best_url = url
            best_timestamp = timestamp
    return best_url


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
        if "siyubo" in value or value == "netlab.dga":
            candidates.append("siyubo")
        if "wd" in value:
            candidates.append("wd")
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
    if not wfy_is_black(wfy_info):
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


def has_wd_malicious_snapshot(wd_info: WdInfo) -> bool:
    return wd_info.malicious and wd_info.has_snapshot


def extract_xmon_description(xmon_info: XmonInfo) -> str:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    tag_main = raw.get("tag_main") if isinstance(raw.get("tag_main"), dict) else {}
    description = first_not_empty(tag_main.get("description"))
    if description:
        return description

    child_rows = raw.get("__tagmon_children")
    if isinstance(child_rows, list):
        for child in child_rows:
            if not isinstance(child, dict):
                continue
            exts = child.get("exts") if isinstance(child.get("exts"), dict) else {}
            ioctag = exts.get("ioctag") if isinstance(exts.get("ioctag"), dict) else {}
            description = first_not_empty(ioctag.get("description"))
            if description:
                return description
    return ""


def wd_snapshot_rule_description(description: str) -> str:
    text = normalize_cell(description)
    if text.startswith("钓鱼欺诈"):
        return "钓鱼欺诈"
    return ""


def is_wd_snapshot_rule_hit(xmon_info: XmonInfo, wd_info: WdInfo) -> bool:
    return has_wd_malicious_snapshot(wd_info) and bool(wd_snapshot_rule_description(extract_xmon_description(xmon_info)))


def resolve_wd_snapshot_topic(ioc: str, wd_info: WdInfo) -> str:
    title = normalize_cell(wd_info.snapshot_title)
    if title:
        return title
    topic, error = query_wd_snapshot_llm_topic(ioc, wd_info.snapshot_content)
    if error:
        LLM_FAILED_IOCS.append(f"{ioc} | wd 快照主题大模型总结失败：{error}")
    return topic


def format_wd_snapshot_info_add(description: str, topic: str) -> str:
    return f"内容类存在恶意快照的ioc,描述信息：{description}，主题内容：{topic}"


def finalize_decision(decision: RowDecision) -> RowDecision:
    if decision.solution == "无更多依据关联":
        decision.solvable = "否"
    elif decision.solution == "存在黑样本关联":
        decision.solvable = "能"
    else:
        decision.solvable = "预解决"
    return decision


def fill_file_features(decision: RowDecision, file_hash: str, hash_info: HashInfo) -> None:
    decision.file_hash = file_hash
    decision.file_size = format_file_size(hash_info.file_size)
    decision.file_type = hash_info.file_type
    decision.operating_system = hash_info.operating_system
    decision.create_time = hash_info.first_seen_time
    decision.other_file_feature = hash_info.other_file_feature


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


def format_llm_evidence_bullets(details: list[str], max_chars: int = LLM_EVIDENCE_MAX_INPUT_CHARS) -> str:
    lines: list[str] = []
    used = 0
    for detail in dict.fromkeys(normalize_cell(item) for item in details):
        if not detail:
            continue
        line = f"- {detail}"
        next_used = used + len(line) + (1 if lines else 0)
        if lines and next_used > max_chars:
            break
        if not lines and len(line) > max_chars:
            line = line[:max_chars]
        lines.append(line)
        used += len(line) + (1 if lines else 0)
    return "\n".join(lines)


def extract_siyubo_evidence_details(xmon_info: XmonInfo) -> list[str]:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    clues = raw.get("__valid_clues")
    details: list[str] = []
    if not isinstance(clues, list):
        return []
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
    return list(dict.fromkeys(details))


def strip_llm_summary_text(value: Any) -> str:
    text = normalize_cell(value)
    if not text:
        return ""
    text = re.sub(r"^```(?:text)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    return text.strip("\"'“”‘’")


def normalize_siyubo_llm_summary_with_reason(summary: str) -> tuple[str, str]:
    text = strip_llm_summary_text(summary)
    if not text:
        return "", "大模型返回空"
    if any(term in text for term in SIYUBO_NO_RESULT_TERMS) and not any(term in text for term in SIYUBO_HIT_TERMS):
        return "", "大模型判定无法形成恶意或可疑依据"
    return text, ""


def normalize_ai_llm_summary_with_reason(summary: str) -> tuple[str, str]:
    text = strip_llm_summary_text(summary)
    if not text:
        return "", "大模型返回空"
    if any(term in text for term in AI_NO_RESULT_TERMS):
        return "", "包含无法形成依据相关词"
    if any(term in text for term in AI_REFUSAL_TERMS):
        return "", "大模型返回拒答套话"
    if text in AI_GENERIC_SUMMARIES or len(text) < AI_SUMMARY_MIN_CHARS:
        return "", "泛化短语或长度过短"
    if not text.endswith(AI_COMPLETE_SUMMARY_ENDINGS):
        return "", "未以完整句结束"
    return text, ""


def parse_llm_summary_response(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
            text = first.get("text")
            if isinstance(text, str):
                return text
    output_text = data.get("output_text")
    if isinstance(output_text, str):
        return output_text
    body = data.get("data")
    if isinstance(body, dict):
        summary = first_not_empty(body.get("summary"), body.get("content"), body.get("text"))
        if summary:
            return summary
    return ""


def query_llm_chat_summary(payload: dict[str, Any]) -> tuple[str, str]:
    if not LLM_TOKEN:
        return "", "missing LLM_TOKEN"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_TOKEN}",
    }
    last_error = ""
    max_attempts = LLM_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(LLM_RETRY_SLEEP_SECONDS * (attempt - 1))
        try:
            session = get_thread_session()
            resp = session.post(
                LLM_API_URL,
                headers=headers,
                data=json_utf8_body(payload),
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return parse_llm_summary_response(safe_json_response(resp)), ""
        except Exception as exc:
            last_error = str(exc)
    return "", last_error


def build_llm_chat_payload(system_content: str, user_content: str) -> dict[str, Any]:
    return {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0,
        "max_tokens": LLM_SUMMARY_MAX_TOKENS,
    }


def normalize_wd_snapshot_llm_topic(topic: str) -> str:
    return strip_llm_summary_text(topic)


def query_wd_snapshot_llm_topic(ioc: str, content: str) -> tuple[str, str]:
    text = normalize_cell(content)
    if not text:
        return "", ""
    if ioc in WD_SNAPSHOT_TOPIC_SUMMARY_CACHE:
        return WD_SNAPSHOT_TOPIC_SUMMARY_CACHE[ioc], ""
    payload = build_llm_chat_payload(
        "你是安全情报分析助手，只输出最终主题内容，不要解释。",
        (
            "以下是恶意快照页面内容。请总结快照主题内容，50字以内。"
            "不要输出前缀、编号或解释。\n\n"
            f"快照内容如下：\n{text[:4000]}"
        ),
    )
    topic, error = query_llm_chat_summary(payload)
    normalized_topic = normalize_wd_snapshot_llm_topic(topic)
    if normalized_topic:
        WD_SNAPSHOT_TOPIC_SUMMARY_CACHE[ioc] = normalized_topic
    return normalized_topic, error


def query_siyubo_llm_summary_one(ioc: str, details: list[str]) -> tuple[str, str, str]:
    if not LLM_TOKEN:
        return ioc, "", "missing LLM_TOKEN"
    cleaned_details = [normalize_cell(detail) for detail in details if normalize_cell(detail)]
    if not cleaned_details:
        return ioc, "", ""

    payload = build_llm_chat_payload(
        "你是安全情报分析助手，只输出最终研判依据，不要解释。",
        (
            f"{SIYUBO_EVIDENCE_PROMPT}\n\n"
            "evidence_chain detail如下：\n"
            + format_llm_evidence_bullets(cleaned_details)
        ),
    )
    summary, error = query_llm_chat_summary(payload)
    normalized_summary, reject_reason = normalize_siyubo_llm_summary_with_reason(summary)
    if reject_reason and not error:
        raw_summary = normalize_cell(summary)
        evidence_text = "；".join(cleaned_details)
        return ioc, "", f"SUMMARY_REJECTED:{reject_reason}：{raw_summary} | siyubo证据链：{evidence_text}"
    return ioc, normalized_summary, error


def query_siyubo_llm_summaries(evidence_map: dict[str, list[str]]) -> dict[str, str]:
    candidates = {ioc: details for ioc, details in evidence_map.items() if details}
    if not candidates:
        return {}
    if not LLM_TOKEN:
        print("[!] 未配置 LLM_TOKEN，跳过 siyubo evidence_chain 大模型总结，继续后续智能体证据链规则。")
        return {}

    print(f"[+] siyubo evidence_chain 大模型总结待处理：{len(candidates)} 条，并发数 {min(LLM_WORKERS, len(candidates))}")
    result_map: dict[str, str] = {}
    if LLM_WORKERS <= 1 or len(candidates) == 1:
        for index, (ioc, details) in enumerate(candidates.items(), 1):
            _, summary, error = query_siyubo_llm_summary_one(ioc, details)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    SIYUBO_LLM_REJECTED_SUMMARIES.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    LLM_FAILED_IOCS.append(f"{ioc} | {error}")
            if summary:
                result_map[ioc] = summary
            if index % AI_PROGRESS_INTERVAL == 0 or index == len(candidates):
                print(f"[+] siyubo evidence_chain 大模型总结进度：{index}/{len(candidates)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(LLM_WORKERS, len(candidates))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_siyubo_llm_summary_one, ioc, details): ioc
            for ioc, details in candidates.items()
        }
        for future in as_completed(future_map):
            ioc = future_map[future]
            completed += 1
            try:
                _, summary, error = future.result()
            except Exception as exc:
                summary = ""
                error = str(exc)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    SIYUBO_LLM_REJECTED_SUMMARIES.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    LLM_FAILED_IOCS.append(f"{ioc} | {error}")
            if summary:
                result_map[ioc] = summary
            if completed % AI_PROGRESS_INTERVAL == 0 or completed == len(candidates):
                print(f"[+] siyubo evidence_chain 大模型总结进度：{completed}/{len(candidates)}")
    return result_map


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
                data=json_utf8_body(payload),
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
        if normalize_cell(item) and not any(term in normalize_cell(item) for term in AI_KEY_EVIDENCE_DROP_TERMS)
    ]
    return AiInfo(ioc=ioc, key_evidence=filtered)


def query_ai_evidence_llm_summary_one(ioc: str, details: list[str]) -> tuple[str, str, str]:
    cleaned_details = [normalize_cell(detail) for detail in details if normalize_cell(detail)]
    if not cleaned_details:
        return ioc, "", ""
    payload = build_llm_chat_payload(
        "你是安全情报分析助手，只输出最终研判依据，不要解释。",
        f"{AI_EVIDENCE_PROMPT}\n\n" + format_llm_evidence_bullets(cleaned_details),
    )
    summary, error = query_llm_chat_summary(payload)
    normalized_summary, reject_reason = normalize_ai_llm_summary_with_reason(summary)
    if reject_reason and not error:
        raw_summary = normalize_cell(summary)
        evidence_text = "；".join(cleaned_details)
        return ioc, "", f"SUMMARY_REJECTED:{reject_reason}：{raw_summary} | 智能体证据链：{evidence_text}"
    return ioc, normalized_summary, error


def enrich_ai_infos_with_llm_summaries(result_map: dict[str, AiInfo]) -> dict[str, AiInfo]:
    candidates = {ioc: info.key_evidence for ioc, info in result_map.items() if info.key_evidence}
    if not candidates:
        return result_map
    if not LLM_TOKEN:
        print("[!] 未配置 LLM_TOKEN，跳过智能体证据链大模型总结。")
        return result_map

    print(f"[+] 智能体证据链大模型总结待处理：{len(candidates)} 条，并发数 {min(LLM_WORKERS, len(candidates))}")
    if LLM_WORKERS <= 1 or len(candidates) == 1:
        for index, (ioc, details) in enumerate(candidates.items(), 1):
            _, summary, error = query_ai_evidence_llm_summary_one(ioc, details)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    AI_LLM_REJECTED_SUMMARIES.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    AI_FAILED_IOCS.append(f"{ioc} | 智能体证据链大模型总结失败：{error}")
            if summary:
                result_map[ioc].summary = summary
            if index % AI_PROGRESS_INTERVAL == 0 or index == len(candidates):
                print(f"[+] 智能体证据链大模型总结进度：{index}/{len(candidates)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(LLM_WORKERS, len(candidates))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_ai_evidence_llm_summary_one, ioc, details): ioc
            for ioc, details in candidates.items()
        }
        for future in as_completed(future_map):
            ioc = future_map[future]
            completed += 1
            try:
                _, summary, error = future.result()
            except Exception as exc:
                summary = ""
                error = str(exc)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    AI_LLM_REJECTED_SUMMARIES.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    AI_FAILED_IOCS.append(f"{ioc} | 智能体证据链大模型总结失败：{error}")
            if summary:
                result_map[ioc].summary = summary
            if completed % AI_PROGRESS_INTERVAL == 0 or completed == len(candidates):
                print(f"[+] 智能体证据链大模型总结进度：{completed}/{len(candidates)}")
    return result_map


def query_ai_quick_analysis(ioc_list: list[str]) -> dict[str, AiInfo]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    result_map: dict[str, AiInfo] = {}
    if not unique_iocs:
        return result_map
    ai_worker_count = min(max(AI_WORKERS, 1), len(unique_iocs))
    llm_worker_count = min(max(LLM_WORKERS, 1), len(unique_iocs))
    print(f"[+] 智能体证据链待查询：{len(unique_iocs)} 条，并发数 {ai_worker_count}")
    if not LLM_TOKEN:
        print("[!] 未配置 LLM_TOKEN，跳过智能体证据链大模型总结。")

    completed = 0
    llm_completed = 0
    llm_future_map: dict[Any, str] = {}

    def print_ai_pipeline_progress(force: bool = False) -> None:
        llm_submitted = llm_completed + len(llm_future_map)
        if force or completed % AI_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
            print(
                f"[+] 智能体证据链完成 {completed}/{len(unique_iocs)}，"
                f"大语言模型总结已提交 {llm_submitted}，"
                f"大语言模型总结已完成 {llm_completed}"
            )

    def collect_llm_future(future: Any, ioc: str) -> None:
        nonlocal llm_completed
        llm_completed += 1
        try:
            _, summary, error = future.result()
        except Exception as exc:
            summary = ""
            error = str(exc)
        if error:
            if error.startswith("SUMMARY_REJECTED:"):
                AI_LLM_REJECTED_SUMMARIES.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
            else:
                AI_FAILED_IOCS.append(f"{ioc} | 智能体证据链大模型总结失败：{error}")
        if summary:
            result_map[ioc].summary = summary

    def collect_completed_llm_results() -> None:
        for llm_future, ioc in list(llm_future_map.items()):
            if not llm_future.done():
                continue
            collect_llm_future(llm_future, ioc)
            del llm_future_map[llm_future]

    def collect_ai_results(llm_executor: ThreadPoolExecutor | None = None) -> None:
        nonlocal completed
        with ThreadPoolExecutor(max_workers=ai_worker_count) as ai_executor:
            future_map = {ai_executor.submit(query_ai_quick_analysis_one, ioc): ioc for ioc in unique_iocs}
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
                if llm_executor and info.key_evidence:
                    llm_future = llm_executor.submit(query_ai_evidence_llm_summary_one, ioc, info.key_evidence)
                    llm_future_map[llm_future] = ioc
                collect_completed_llm_results()
                print_ai_pipeline_progress()

    if LLM_TOKEN:
        print(f"[+] 智能体证据链大模型总结采用流水线，并发数 {llm_worker_count}")
        with ThreadPoolExecutor(max_workers=llm_worker_count) as llm_executor:
            collect_ai_results(llm_executor)
            print_ai_pipeline_progress(force=True)
            for future in as_completed(list(llm_future_map)):
                ioc = llm_future_map.pop(future)
                collect_llm_future(future, ioc)
                if llm_completed % AI_PROGRESS_INTERVAL == 0 or not llm_future_map:
                    print_ai_pipeline_progress(force=True)
    else:
        collect_ai_results()
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
    siyubo_evidence_summary: str = "",
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
    for ref_hash in ref_hashes:
        hash_info = hash_map.get(ref_hash, HashInfo(query_hash=ref_hash))
        if risk_is_black(hash_info.risk):
            black_hash = ref_hash
            black_hash_info = hash_info
            break
        if not first_hash_info.risk:
            first_hash_info = hash_info

    first_report = pick_first_report(xmon_info.report_links)
    wd_snapshot = has_wd_malicious_snapshot(wd_info)
    decision.owner = classify_owner(xmon_info, wfy_info, wd_info, sc_malicious)

    if not wfy_is_black(wfy_info):
        decision.k01_result = ""
        decision.info_add = "wfy接口查询未显示恶意"
        decision.solvable = "否"
        decision.solution = "wfy接口查询未显示恶意"
        decision.rule_hit = "wfy_not_black"
        decision.hit_rule = "wfy未报告恶意"
        return finalize_decision(decision)

    if black_hash:
        decision.k01_result = "有效"
        fill_file_features(decision, black_hash, black_hash_info)
        decision.info_add = f"{decision.ioc}，依据ioc({decision.ioc}),关联样本（{black_hash}）"
        decision.solvable = "能"
        decision.solution = "存在黑样本关联"
        decision.rule_hit = "black_hash"
        decision.hit_rule = "存在黑样本关联"
        return finalize_decision(decision)

    if first_report:
        decision.k01_result = "有效"
        fill_file_features(decision, first_hash_info.query_hash, first_hash_info)
        decision.info_add = f"{decision.ioc}，依据ioc({decision.ioc}),关联报告（{first_report}）"
        decision.solvable = "能"
        decision.solution = "存在关联报告关联"
        decision.rule_hit = "report"
        decision.hit_rule = "存在关联报告关联"
        return finalize_decision(decision)

    if decision.owner == "wd" and wd_snapshot:
        rule_description = wd_snapshot_rule_description(extract_xmon_description(xmon_info))
        if rule_description:
            topic = resolve_wd_snapshot_topic(decision.ioc, wd_info)
            decision.k01_result = "有效"
            decision.info_add = format_wd_snapshot_info_add(rule_description, topic)
            decision.solvable = "能"
            decision.solution = "src是wd且有快照"
            decision.rule_hit = "wd_snapshot"
            decision.hit_rule = "src是wd且有快照"
            return finalize_decision(decision)

    if decision.owner == "siyubo":
        evidence_summary = normalize_cell(siyubo_evidence_summary)
        if evidence_summary:
            decision.k01_result = "有效"
            decision.info_add = evidence_summary
            decision.solvable = "能"
            decision.solution = "siyubo证据链"
            decision.rule_hit = "siyubo_evidence_chain"
            decision.hit_rule = "siyubo证据链"
            return finalize_decision(decision)

    if ai_info and ai_info.summary:
        decision.k01_result = "有效"
        decision.info_add = ai_info.summary
        decision.solvable = "能"
        decision.solution = "智能体证据链"
        decision.rule_hit = "ai_evidence_chain"
        decision.hit_rule = "智能体证据链"
        return finalize_decision(decision)

    decision.k01_result = ""
    decision.solvable = "否"
    decision.solution = "无更多依据关联"
    decision.rule_hit = "no_more_evidence"
    return finalize_decision(decision)


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
        "误报原因": "",
        "命中规则": decision.hit_rule,
        "拼接后的ioc": decision.ioc,
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


def dedupe_decisions_by_ioc(decisions: list[RowDecision]) -> list[RowDecision]:
    deduped: list[RowDecision] = []
    seen: set[str] = set()
    for decision in decisions:
        key = decision.ioc
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        deduped.append(decision)
    return deduped


def build_analysis_summary_rows(decisions: list[RowDecision], wfy_map: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    deduped_decisions = dedupe_decisions_by_ioc(decisions)
    today_alert_count = len(decisions)
    unique_ioc_count = len({decision.ioc for decision in deduped_decisions if decision.ioc})
    unique_iocs = list(dict.fromkeys(decision.ioc for decision in deduped_decisions if decision.ioc))
    wfy_black_count = sum(1 for ioc in unique_iocs if wfy_is_black(wfy_map.get(ioc, {})))
    wfy_non_black_count = len(unique_iocs) - wfy_black_count

    black_hash_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "存在黑样本关联")
    report_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "存在关联报告关联")
    wd_snapshot_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "src是wd且有快照")
    ai_evidence_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "智能体证据链")

    remaining_decisions = [
        decision
        for decision in deduped_decisions
        if decision.rule_hit == "no_more_evidence" and wfy_is_black(wfy_map.get(decision.ioc, {}))
    ]
    remaining_count = len(remaining_decisions)
    owner_counter = Counter(decision.owner if decision.owner in OWNER_PRIORITY else "unknown" for decision in deduped_decisions)
    owner_total = sum(owner_counter.get(owner, 0) for owner in OWNER_PRIORITY)
    owner_text = "，".join(
        f"{owner}（{owner_counter.get(owner, 0)}条）"
        for owner in ("atateam", "siyubo", "wd", "netlab", "unknown")
    )
    non_ai_decisions = [decision for decision in deduped_decisions if decision.solution != "智能体证据链"]
    non_ai_owner_counter = Counter(decision.owner if decision.owner in OWNER_PRIORITY else "unknown" for decision in non_ai_decisions)
    non_ai_owner_total = sum(non_ai_owner_counter.get(owner, 0) for owner in OWNER_PRIORITY)
    non_ai_owner_text = "，".join(
        f"{owner}（{non_ai_owner_counter.get(owner, 0)}/{owner_counter.get(owner, 0)}条）"
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
        f"拼接ioc去重后生产方归属总计{owner_total}条，{owner_text}",
        f"拼接ioc去重后，排除智能体证据链后，生产方归属总计{non_ai_owner_total}/{owner_total}条；\n"
        f"生产方对应已解决情况：{non_ai_owner_text}；",
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
    workbook = pd.ExcelFile(path)
    sheet_name = "受控外联情报研判_1" if "受控外联情报研判_1" in workbook.sheet_names else workbook.sheet_names[0]
    df = pd.read_excel(workbook, sheet_name=sheet_name, dtype=str).fillna("")
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


def print_failure_summary(
    title: str,
    failures: list[str],
    max_items: int | None = 20,
    count_only: bool = False,
) -> None:
    if not failures:
        return
    unique_failures = list(dict.fromkeys(failures))
    print(f"\n[!] {title}")
    print(f"    总数：{len(unique_failures)}")
    if count_only:
        return
    items = unique_failures if max_items is None else unique_failures[:max_items]
    for item in items:
        print(f"    {item}")
    if max_items is not None and len(unique_failures) > max_items:
        print(f"    ... 其余 {len(unique_failures) - max_items} 条已省略")


def print_query_failures() -> None:
    print_failure_summary("xmon 主线索查询失败 IOC", XMON_FAILED_IOCS)
    print_failure_summary("xmon 子线索最终查询失败 IOC", TAGMON_FAILED_IOCS)
    print_failure_summary("hash 查询失败", HASH_FAILED_QUERIES)
    print_failure_summary("wfy 查询失败 IOC", WFY_FAILED_QUERIES)
    print_failure_summary("sc 查询失败 IOC", SC_FAILED_IOCS)
    print_failure_summary("wd 查询异常 IOC", WD_FAILED_IOCS)
    print_failure_summary("siyubo evidence_chain 大模型总结异常 IOC", LLM_FAILED_IOCS)
    print_failure_summary("siyubo evidence_chain 大模型总结无效 IOC", SIYUBO_LLM_REJECTED_SUMMARIES, max_items=50)
    print_failure_summary("智能体证据链查询异常 IOC", AI_FAILED_IOCS, max_items=None)
    print_failure_summary("智能体证据链大模型总结不合规 IOC", AI_LLM_REJECTED_SUMMARIES, max_items=50)


def failure_item_ioc(item: str) -> str:
    return normalize_cell(item.split("|", 1)[0])


def failure_iocs(failures: list[str]) -> set[str]:
    return {ioc for ioc in (failure_item_ioc(item) for item in failures) if ioc}


def remove_failure_items(failures: list[str], iocs: set[str]) -> None:
    if not iocs:
        return
    failures[:] = [item for item in failures if failure_item_ioc(item) not in iocs]


def failure_hashes() -> set[str]:
    hashes: set[str] = set()
    for item in HASH_FAILED_QUERIES:
        query_text = failure_item_ioc(item)
        for value in query_text.split(","):
            hash_value = normalize_cell(value)
            if hash_value:
                hashes.add(hash_value)
    return hashes


def remove_hash_failure_items(hashes: set[str]) -> None:
    if not hashes:
        return
    HASH_FAILED_QUERIES[:] = [
        item
        for item in HASH_FAILED_QUERIES
        if not any(normalize_cell(value) in hashes for value in failure_item_ioc(item).split(","))
    ]


def collect_failed_iocs_for_rerun(xmon_map: dict[str, XmonInfo]) -> list[str]:
    failed_iocs: set[str] = set()
    for failures in (
        XMON_FAILED_IOCS,
        TAGMON_FAILED_IOCS,
        WFY_FAILED_QUERIES,
        SC_FAILED_IOCS,
        WD_FAILED_IOCS,
        LLM_FAILED_IOCS,
        SIYUBO_LLM_REJECTED_SUMMARIES,
        AI_FAILED_IOCS,
        AI_LLM_REJECTED_SUMMARIES,
    ):
        failed_iocs.update(failure_iocs(failures))

    hash_values = failure_hashes()
    if hash_values:
        for ioc, xmon_info in xmon_map.items():
            if set(extract_hashes_from_xmon_info(xmon_info)).intersection(hash_values):
                failed_iocs.add(ioc)
    return list(dict.fromkeys(ioc for ioc in failed_iocs if ioc))


def clear_failed_records_for_iocs(iocs: set[str], xmon_map: dict[str, XmonInfo]) -> None:
    if not iocs:
        return
    for failures in (
        XMON_FAILED_IOCS,
        TAGMON_FAILED_IOCS,
        WFY_FAILED_QUERIES,
        SC_FAILED_IOCS,
        WD_FAILED_IOCS,
        LLM_FAILED_IOCS,
        SIYUBO_LLM_REJECTED_SUMMARIES,
        AI_FAILED_IOCS,
        AI_LLM_REJECTED_SUMMARIES,
    ):
        remove_failure_items(failures, iocs)

    hashes = {
        hash_value
        for ioc in iocs
        for hash_value in extract_hashes_from_xmon_info(xmon_map.get(ioc, empty_xmon_info(ioc)))
    }
    remove_hash_failure_items(hashes)


def retry_failed_iocs_from_start(
    session: Session,
    all_iocs: list[str],
    xmon_map: dict[str, XmonInfo],
    hash_map: dict[str, HashInfo],
    wfy_map: dict[str, dict[str, Any]],
    sc_map: dict[str, bool],
    wd_map: dict[str, WdInfo],
    siyubo_summary_map: dict[str, str],
    ai_map: dict[str, AiInfo],
) -> None:
    if FAILED_IOC_RERUNS <= 0:
        return

    allowed_iocs = set(all_iocs)
    retry_iocs = [ioc for ioc in collect_failed_iocs_for_rerun(xmon_map) if ioc in allowed_iocs]
    for round_index in range(1, FAILED_IOC_RERUNS + 1):
        if not retry_iocs:
            break
        retry_ioc_set = set(retry_iocs)
        clear_failed_records_for_iocs(retry_ioc_set, xmon_map)
        print(f"\n[+] 异常 IOC 全流程重跑第 {round_index}/{FAILED_IOC_RERUNS} 轮：{len(retry_iocs)} 条")

        retry_xmon_map = query_xmon_iocs(session, retry_iocs)
        xmon_map.update(retry_xmon_map)

        retry_hashes: list[str] = []
        for ioc in retry_iocs:
            retry_hashes.extend(extract_hashes_from_xmon_info(xmon_map.get(ioc, empty_xmon_info(ioc))))
        retry_unique_hashes = list(dict.fromkeys(hash_value for hash_value in retry_hashes if hash_value))
        if retry_unique_hashes:
            hash_map.update(query_hashes(session, retry_unique_hashes))

        wfy_map.update(query_wfy(session, retry_iocs))
        retry_black_iocs = [ioc for ioc in retry_iocs if wfy_is_black(wfy_map.get(ioc, {}))]

        if retry_black_iocs:
            sc_map.update(query_sc(session, retry_black_iocs))

        wd_candidate_iocs = [
            ioc
            for ioc in retry_black_iocs
            if not {"atateam", "siyubo"}.intersection(xmon_owner_candidates(xmon_map.get(ioc, empty_xmon_info(ioc))))
        ]
        if wd_candidate_iocs:
            wd_map.update(query_wd(session, wd_candidate_iocs))

        retry_siyubo_evidence_details_map: dict[str, list[str]] = {}
        for ioc in retry_iocs:
            xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
            wfy_info = wfy_map.get(ioc, {})
            wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
            owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
            if owner != "siyubo":
                continue
            if is_wd_snapshot_rule_hit(xmon_info, wd_info):
                continue
            if has_black_hash_evidence(xmon_info, hash_map):
                continue
            if pick_first_report(xmon_info.report_links):
                continue
            details = extract_siyubo_evidence_details(xmon_info)
            if details:
                retry_siyubo_evidence_details_map[ioc] = details
        siyubo_summary_map.update(query_siyubo_llm_summaries(retry_siyubo_evidence_details_map))

        retry_ai_candidate_iocs: list[str] = []
        for ioc in retry_iocs:
            xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
            wfy_info = wfy_map.get(ioc, {})
            wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
            if not wfy_is_black(wfy_info):
                continue
            if has_black_hash_evidence(xmon_info, hash_map):
                continue
            if pick_first_report(xmon_info.report_links):
                continue
            owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
            if owner == "wd" and is_wd_snapshot_rule_hit(xmon_info, wd_info):
                continue
            if siyubo_summary_map.get(ioc):
                continue
            retry_ai_candidate_iocs.append(ioc)
        if retry_ai_candidate_iocs:
            ai_map.update(query_ai_quick_analysis(retry_ai_candidate_iocs))

        remaining_iocs = set(collect_failed_iocs_for_rerun(xmon_map)).intersection(retry_ioc_set)
        recovered_count = len(retry_ioc_set) - len(remaining_iocs)
        print(f"[+] 异常 IOC 全流程重跑恢复：{recovered_count} 条，仍异常：{len(remaining_iocs)} 条")
        retry_iocs = [ioc for ioc in retry_iocs if ioc in remaining_iocs]


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


def build_analysis_owner_ai_sheet(detail_df: pd.DataFrame, owner: str) -> pd.DataFrame:
    filtered = detail_df[
        (detail_df["生产方归属"] == owner)
        & (detail_df["相关解决方案"] == "智能体证据链")
    ].copy()
    filtered["能否解决"] = AI_EVIDENCE_PROBLEM_TEXT
    filtered = filtered.rename(columns={"能否解决": "问题情况"})
    return filtered.drop(columns=["相关解决方案"])


def write_analysis_excel(detail_df: pd.DataFrame, summary_df: pd.DataFrame, path: str) -> None:
    try:
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            detail_df.to_excel(writer, sheet_name="明细", index=False)
            summary_df.to_excel(writer, sheet_name="统计", index=False)
            for owner in ANALYSIS_OWNER_SHEETS:
                owner_df = build_analysis_owner_ai_sheet(detail_df, owner)
                owner_df.to_excel(writer, sheet_name=owner, index=False)
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
    print(f"[+] wfy black IOC：{len(black_iocs)} 条")
    finish_stage("查询 wfy", stage_time)

    stage_time = start_stage("查询 sc")
    sc_map = query_sc(session, black_iocs) if black_iocs else {}
    finish_stage("查询 sc", stage_time)

    stage_time = start_stage("查询 wd")
    wd_candidate_iocs = [
        ioc
        for ioc in black_iocs
        if not {"atateam", "siyubo"}.intersection(xmon_owner_candidates(xmon_map.get(ioc, empty_xmon_info(ioc))))
    ]
    print(f"[+] wd 候选 IOC：{len(wd_candidate_iocs)} 条")
    wd_map = query_wd(session, wd_candidate_iocs) if wd_candidate_iocs else {}
    finish_stage("查询 wd", stage_time)

    stage_time = start_stage("总结 siyubo evidence_chain")
    siyubo_evidence_details_map: dict[str, list[str]] = {}
    for ioc in ioc_list:
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
        if owner != "siyubo":
            continue
        if is_wd_snapshot_rule_hit(xmon_info, wd_info):
            continue
        if has_black_hash_evidence(xmon_info, hash_map):
            continue
        if pick_first_report(xmon_info.report_links):
            continue
        details = extract_siyubo_evidence_details(xmon_info)
        if details:
            siyubo_evidence_details_map[ioc] = details
    siyubo_summary_map = query_siyubo_llm_summaries(siyubo_evidence_details_map)
    print(f"[+] siyubo evidence_chain 大模型有效总结：{len(siyubo_summary_map)} 条")
    finish_stage("总结 siyubo evidence_chain", stage_time)

    stage_time = start_stage("查询智能体证据链")
    ai_candidate_iocs: list[str] = []
    for ioc in ioc_list:
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        if not wfy_is_black(wfy_info):
            continue
        if has_black_hash_evidence(xmon_info, hash_map):
            continue
        if pick_first_report(xmon_info.report_links):
            continue
        owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
        if owner == "wd" and is_wd_snapshot_rule_hit(xmon_info, wd_info):
            continue
        if siyubo_summary_map.get(ioc):
            continue
        ai_candidate_iocs.append(ioc)
    ai_map = query_ai_quick_analysis(ai_candidate_iocs) if ai_candidate_iocs else {}
    retry_failed_iocs_from_start(
        session,
        ioc_list,
        xmon_map,
        hash_map,
        wfy_map,
        sc_map,
        wd_map,
        siyubo_summary_map,
        ai_map,
    )
    finish_stage("查询智能体证据链", stage_time)

    stage_time = start_stage("生成研判结果")
    decisions: list[RowDecision] = []
    for _, row in df.iterrows():
        ioc = normalize_cell(row.get("ioc", ""))
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        ai_info = ai_map.get(ioc, AiInfo(ioc=ioc))
        siyubo_evidence_summary = siyubo_summary_map.get(ioc, "")
        sc_malicious = sc_map.get(ioc, False)
        decision = decide_row(
            row,
            xmon_info,
            hash_map,
            wfy_info,
            wd_info,
            ai_info,
            siyubo_evidence_summary,
            sc_malicious,
        )
        print_debug_ioc(ioc, xmon_info, hash_map, wfy_info, wd_info, sc_malicious, decision)
        decisions.append(decision)
    finish_stage("生成研判结果", stage_time)

    stage_time = start_stage("写出 Excel")
    deduped_decisions = dedupe_decisions_by_ioc(decisions)
    result_df = pd.DataFrame([decision_to_result_row(d) for d in decisions], columns=RESULT_COLUMNS)
    analysis_df = pd.DataFrame([decision_to_analysis_row(d) for d in deduped_decisions], columns=ANALYSIS_COLUMNS)
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
