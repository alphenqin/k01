# -*- coding: utf-8 -*-
import os
import ast
import time
import json
import hashlib
import requests
import pandas as pd
from urllib.parse import quote


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE_DIR, "1781076134862_导出结果_20260610_1.xlsx")

# ===== xmon配置 =====
XMON_BASE_URL = "http://xmon.netlab.qihoo.net/api/iocmon-search/ioc/"
XMON_QUERY = "?ui_simple=true&pretick=false&model=false&trace=true&keep_no=false&inspect=true&other_source=false"

XMON_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-AuthToken": "6189ff22-21c8-49ab-8519-7ef85f396954",
    "Pragma": "no-cache",
    "Referer": "http://xmon.netlab.qihoo.net/ui/iocmon/",
    "User-Agent": "Mozilla/5.0",
    "X-Requested-With": "XMLHttpRequest",
}

# ===== hash查询配置 =====
HASH_API_URL = "https://api.ti.360.cn/v2/file"
API_KEY = "8d5ae25afc18d812a51cc1048b7ef57d"
SALT = "fc05b3246ed550cc0da9748e7002d676"


ENRICH_COLUMNS = [
    "ioc",
    "xmon_is_disable",
    "xmon_hash",
    "xmon_report",
    "xmon_hash_is_black",
    "k01_res",
    "k01_status",
    "hash_filesize",
    "hash_filetype",
    "hash_operating_system",
    "hash_creattime",
    "hash_risk",
    "other_file_malware_family",
    "info_add",
]


def random_end_txt():
    return str(int(time.time()))


def format_file_size(byte_value):
    """
    将字节数转换为：453.50 KB (464384 bytes)
    """
    try:
        size = int(str(byte_value).strip())
    except Exception:
        return ""

    units = ["bytes", "KB", "MB", "GB", "TB"]
    value = float(size)
    unit_index = 0

    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{size} bytes ({size} bytes)"
    else:
        return f"{value:.2f} {units[unit_index]} ({size} bytes)"


def join_val(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return " ".join(map(str, v))
    if isinstance(v, dict):
        if "in" in v and "out" in v:
            return f"{v.get('in', '')} {v.get('out', '')}"
        return str(v)
    return str(v)


def chunk_list(data, size=10):
    size = min(size, 10)
    for i in range(0, len(data), size):
        yield data[i:i + size]


def timestamp_to_date(ts):
    try:
        ts = int(ts)
        if ts <= 0:
            return ""
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return ""


def build_ioc(row):
    target = str(row.get("外联目标", "")).strip()
    port = str(row.get("端口", "")).strip()
    target_type = str(row.get("目标类型", "")).strip().upper()

    if not target:
        return ""

    if target_type == "IP":
        return f"{target}:{port}" if port else target

    return target


def empty_xmon_row(ioc):
    return {
        "ioc_search": ioc,
        "disable": "",
        "status": "",
        "ref_sample": "",
        "report_links": "",
    }


def normalize_xmon_row(ioc, row):
    return {
        "ioc_search": row.get("ioc_search", ioc),
        "disable": join_val(row.get("disable", row.get("Disabled", row.get("ioc_disabled", "")))),
        "status": join_val(row.get("status", row.get("Status", ""))),
        "ref_sample": row.get("ref_sample", ""),
        "report_links": row.get("report_links", ""),
    }


def extract_xmon_rows(resp_json):
    if isinstance(resp_json, list):
        return resp_json

    if isinstance(resp_json, dict):
        data = resp_json.get("data", [])
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return list(data.values())

    return []


def query_xmon_iocs(ioc_list, batch_size=10):
    result_map = {}

    for batch in chunk_list(ioc_list, batch_size):
        ioc_part = ",".join(quote(x, safe=".:_-") for x in batch)
        url = f"{XMON_BASE_URL}{ioc_part}/{XMON_QUERY}"

        print(f"[+] 查询 xmon：{len(batch)} 条")
        try:
            resp = requests.get(url, headers=XMON_HEADERS, verify=False, timeout=60)
            resp.raise_for_status()
            for row in extract_xmon_rows(resp.json()):
                ioc = (
                    row.get("ioc_search")
                    or row.get("ioc")
                    or row.get("IOC")
                    or row.get("uid")
                )
                if not ioc:
                    continue
                result_map[ioc] = normalize_xmon_row(ioc, row)
        except Exception as e:
            print(f"[!] 查询 xmon 失败 (批量: {batch})，错误信息: {e}")

        time.sleep(0.3)

    return {ioc: result_map.get(ioc, empty_xmon_row(ioc)) for ioc in ioc_list}


def parse_ref_sample(ref_sample):
    if not ref_sample:
        return []

    if isinstance(ref_sample, list):
        return ref_sample

    try:
        data = ast.literal_eval(str(ref_sample))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def get_ref_hash(data):
    if not data or not isinstance(data, list):
        return ""

    first = data[0]
    if not isinstance(first, dict):
        return ""

    for key in ("md5", "sha1", "sha256"):
        value = str(first.get(key, "")).strip()
        if value:
            return value

    return ""


def make_hash_headers():
    timestamp = int(time.time())
    sign = hashlib.md5((str(timestamp) + SALT).encode()).hexdigest()

    return {
        "Content-Type": "application/json",
        "X-Api-Key": API_KEY,
        "timestamp": str(timestamp),
        "sign": sign,
    }


def query_hash_batch(hash_list):
    payload = {
        "param": ",".join(hash_list),
        "field": 0,
    }

    try:
        resp = requests.post(
            HASH_API_URL,
            headers=make_hash_headers(),
            data=json.dumps(payload),
            timeout=30,
        )
        return resp.json()
    except Exception as e:
        return {
            "errno": -1,
            "msg": str(e),
            "result": {},
        }


def parse_hash_result(hash_list, response_json):
    result = response_json.get("result", {}) or {}
    hash_map = {}

    for h in hash_list:
        item = result.get(h, {}) or {}

        threat_type = item.get("threat_type", {}) or {}

        if item:
            hash_map[h] = {
                "query_hash": h,
                "risk": item.get("risk", ""),
                "file_size": item.get("file_size", ""),
                "file_type": item.get("file_type", ""),
                "first_seen_time": timestamp_to_date(item.get("first_seen", 0)),
                "operating_system": item.get("operating_system", ""),
                "malware_family": item.get("malware_family", ""),
                "virus_name": item.get("virus_name", ""),
                "threat_type_name": threat_type.get("name", ""),
            }
        else:
            hash_map[h] = {
                "query_hash": h,
                "risk": "",
                "file_size": "",
                "file_type": "",
                "first_seen_time": "",
                "operating_system": "",
                "malware_family": "",
                "virus_name": "",
                "threat_type_name": "",
            }

    return hash_map


def query_hashes(hash_list, batch_size=10):
    hash_list = [h for h in hash_list if h]
    hash_list = list(dict.fromkeys(hash_list))

    all_hash_map = {}

    for batch in chunk_list(hash_list, batch_size):
        print(f"[+] 查询 hash：{len(batch)} 条")
        response_json = query_hash_batch(batch)
        all_hash_map.update(parse_hash_result(batch, response_json))
        time.sleep(0.5)

    return all_hash_map


def map_k01_status(xmon_status):
    status = str(xmon_status).strip().upper()

    status_map = {
        "ACTIVE": "存活",
        "UNKNOWN": "失活",
        "SINKHOLE": "被安全机构接管",
    }

    return status_map.get(status, status)


def main():
    df = pd.read_excel(INPUT_FILE, dtype=str).fillna("")

    for col in ENRICH_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    # 1. 先生成 ioc
    df["ioc"] = df.apply(build_ioc, axis=1)

    ioc_list = [x for x in df["ioc"].astype(str).str.strip().tolist() if x]
    print(ioc_list)
    # 2. 请求 xmon
    xmon_map = query_xmon_iocs(ioc_list, batch_size=10)


    # 3. 从 xmon 结果提取 xmon_hash
    xmon_hash_list = []

    for idx, row in df.iterrows():
        ioc = str(row.get("ioc", "")).strip()
        xmon_row = xmon_map.get(ioc, empty_xmon_row(ioc))

        df.at[idx, "xmon_is_disable"] = join_val(xmon_row.get("disable", ""))
        df.at[idx, "xmon_report"] = join_val(xmon_row.get("report_links", ""))

        ref_sample = xmon_row.get("ref_sample", "")
        xmon_hash = get_ref_hash(parse_ref_sample(ref_sample))
        df.at[idx, "xmon_hash"] = xmon_hash

        df.at[idx, "k01_status"] = map_k01_status(xmon_row.get("status", ""))

        if xmon_hash:
            xmon_hash_list.append(xmon_hash)

    # 4. 请求 hash 查询接口
    hash_map = query_hashes(xmon_hash_list, batch_size=10)

    # 5. 填充 hash 相关字段
    for idx, row in df.iterrows():
        ioc = str(row.get("ioc", "")).strip()
        xmon_hash = str(row.get("xmon_hash", "")).strip()

        hash_info = hash_map.get(xmon_hash, {}) if xmon_hash else {}

        df.at[idx, "xmon_hash_is_black"] = str(hash_info.get("risk", ""))
        df.at[idx, "k01_res"] = ""

        df.at[idx, "hash_filesize"] = format_file_size(hash_info.get("file_size", ""))
        df.at[idx, "hash_filetype"] = str(hash_info.get("file_type", ""))
        df.at[idx, "hash_operating_system"] = str(hash_info.get("operating_system", ""))
        df.at[idx, "hash_creattime"] = str(hash_info.get("first_seen_time", ""))
        df.at[idx, "hash_risk"] = str(hash_info.get("risk", ""))
        df.at[idx, "other_file_malware_family"] = str(hash_info.get("malware_family", ""))

        if xmon_hash:
            df.at[idx, "info_add"] = f"{ioc}，依据ioc({ioc}),关联样本（{xmon_hash}）"
        else:
            df.at[idx, "info_add"] = ""

    output_file = os.path.join(BASE_DIR, f"output_enriched_{random_end_txt()}.xlsx")
    df.to_excel(output_file, index=False)

    print(f"[+] 富化完成：{output_file}")


if __name__ == "__main__":
    main()