from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import pandas as pd

from app.core import process as core
from app.schemas.judge import empty_agent, empty_item, empty_project_table, empty_sc
from app.services.validators import infer_supported_ioc_type, normalize_ioc, split_port


UNSUPPORTED_IOC_ERROR = "不支持的ioc类型（请输入domain，ip:port，url）"
NON_360_ERROR = "非360情报（ti平台查询：https://ti.360.cn/）"
NO_AGENT_ERROR = "无对应智能体研判结果，请重试"
URL_RE = re.compile(r"https?://[^\s\"'<>，；、（）()\\\\]+")


def judge_iocs(raw_iocs: list[Any], project: Any = None) -> dict[str, Any]:
    total = len(raw_iocs)
    include_project_table = project == "project_k01_table_daily"
    if total == 0:
        return {
            "code": 0,
            "message": "success",
            "total": 0,
            "success_count": 0,
            "failed_count": 0,
            "data": [],
        }

    prepared = [_prepare_item(value) for value in raw_iocs]
    valid_iocs = [item["ioc"] for item in prepared if not item["error"]]
    unique_valid_iocs = list(dict.fromkeys(valid_iocs))

    result_map: dict[str, dict[str, Any]] = {}
    if unique_valid_iocs:
        result_map = _judge_valid_iocs(unique_valid_iocs)

    data: list[dict[str, Any]] = []
    for item in prepared:
        if item["error"]:
            data.append(_shape_response_item(empty_item(item["ioc"], item["ioc_type"], item["port"], item["error"]), include_project_table))
            continue
        data.append(
            _shape_response_item(
                result_map.get(item["ioc"], empty_item(item["ioc"], item["ioc_type"], item["port"], "服务端异常")),
                include_project_table,
            )
        )

    failed_count = sum(1 for item in data if item.get("error"))
    success_count = total - failed_count
    message = "success" if failed_count == 0 else "partial success"
    return {
        "code": 0,
        "message": message,
        "total": total,
        "success_count": success_count,
        "failed_count": failed_count,
        "data": data,
    }


def _shape_response_item(item: dict[str, Any], include_project_table: bool) -> dict[str, Any]:
    if include_project_table:
        return item
    return {
        key: value
        for key, value in item.items()
        if key != "project_k01_table_daily"
    }


def _prepare_item(value: Any) -> dict[str, str]:
    ioc = normalize_ioc(value)
    ioc_type = infer_supported_ioc_type(ioc)
    if not ioc:
        return {"ioc": ioc, "ioc_type": "", "port": "", "error": "IOC 不能为空"}
    if ioc_type not in {"domain", "ip_port", "url"}:
        return {"ioc": ioc, "ioc_type": ioc_type, "port": "", "error": UNSUPPORTED_IOC_ERROR}
    return {"ioc": ioc, "ioc_type": ioc_type, "port": split_port(ioc), "error": ""}


def _judge_valid_iocs(ioc_list: list[str]) -> dict[str, dict[str, Any]]:
    _reset_core_failure_state()
    sc_raw_map = _query_sc_raw(ioc_list)
    sc_map = {ioc: _build_sc(ioc, sc_raw_map.get(ioc, {})) for ioc in ioc_list}
    sc_malicious_map = {ioc: core.sc_is_malicious(sc_raw_map.get(ioc, {})) for ioc in ioc_list}

    result_map: dict[str, dict[str, Any]] = {}
    candidate_iocs: list[str] = []
    for ioc in ioc_list:
        ioc_type = infer_supported_ioc_type(ioc)
        port = split_port(ioc)
        item = empty_item(ioc, ioc_type, port)
        item["sc"] = sc_map[ioc]
        sc_raw = sc_raw_map.get(ioc, {})
        if _sc_is_empty(sc_raw):
            item["error"] = NON_360_ERROR
            item["project_k01_table_daily"]["supplement_info"] = NON_360_ERROR
            result_map[ioc] = item
            continue
        if not sc_malicious_map[ioc]:
            item["error"] = NO_AGENT_ERROR
            item["project_k01_table_daily"]["supplement_info"] = NO_AGENT_ERROR
            result_map[ioc] = item
            continue
        candidate_iocs.append(ioc)

    if not candidate_iocs:
        return result_map

    decision_bundle = _run_core_decision_pipeline(candidate_iocs, sc_malicious_map)
    for ioc in candidate_iocs:
        decision = decision_bundle["decisions"].get(ioc)
        ai_info = decision_bundle["ai_map"].get(ioc, core.AiInfo(ioc=ioc))
        item = empty_item(ioc, infer_supported_ioc_type(ioc), split_port(ioc))
        item["sc"] = sc_map[ioc]
        item["agent"] = _build_agent(ioc, item["sc"], ai_info, decision)
        if decision is not None:
            item["project_k01_table_daily"] = _project_table_from_decision(decision)
        result_map[ioc] = item
    return result_map


def _reset_core_failure_state() -> None:
    for name in (
        "XMON_FAILED_IOCS",
        "TAGMON_FAILED_IOCS",
        "HASH_FAILED_QUERIES",
        "WFY_FAILED_QUERIES",
        "EXTERNAL_IOC_FAILED_QUERIES",
        "SC_FAILED_IOCS",
        "WD_FAILED_IOCS",
        "AI_FAILED_IOCS",
        "WD_LLM_FAILED_IOCS",
        "ATATEAM_LLM_FAILED_IOCS",
        "ATATEAM_LLM_REJECTED_SUMMARIES",
        "SIYUBO_LLM_FAILED_IOCS",
        "SIYUBO_LLM_REJECTED_SUMMARIES",
        "AI_LLM_REJECTED_SUMMARIES",
    ):
        value = getattr(core, name, None)
        if isinstance(value, list):
            value.clear()


def _query_sc_raw(ioc_list: list[str]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[str]] = {}
    for ioc in ioc_list:
        grouped.setdefault(core.sc_category_for_ioc(ioc), []).append(ioc)

    result_map: dict[str, dict[str, Any]] = {}
    for category, iocs in grouped.items():
        batches = core.chunk_list(iocs, core.SC_BATCH_SIZE)
        worker_count = min(max(core.SC_WORKERS, 1), len(batches))
        if worker_count <= 1:
            for batch in batches:
                _, parsed, _ = core.query_custom_tags_batch(batch, category=category)
                result_map.update(parsed)
            continue
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {
                executor.submit(core.query_custom_tags_batch, batch, category): batch
                for batch in batches
            }
            for future in as_completed(future_map):
                batch = future_map[future]
                try:
                    _, parsed, _ = future.result()
                except Exception as exc:
                    parsed = {ioc: {"query_error": str(exc)} for ioc in batch}
                result_map.update(parsed)
    for ioc in ioc_list:
        result_map.setdefault(ioc, {})
    return result_map


def _run_core_decision_pipeline(ioc_list: list[str], sc_malicious_map: dict[str, bool]) -> dict[str, Any]:
    wfy_map = core.query_wfy(ioc_list)
    black_iocs = [ioc for ioc in ioc_list if core.wfy_is_black(wfy_map.get(ioc, {}))]

    if black_iocs:
        first_parallel_results = core.run_parallel_stages(
            {
                "查询 xmon 主线索和子线索": lambda: core.query_xmon_iocs(black_iocs),
            }
        )
        xmon_map = first_parallel_results["查询 xmon 主线索和子线索"]
    else:
        xmon_map = {}

    wd_candidate_iocs = core.build_wd_candidate_iocs(black_iocs, xmon_map)
    second_stage_funcs: dict[str, Any] = {
        "提取并查询 hash 文件情报": lambda: core.build_hash_map_from_xmon(xmon_map),
    }
    if wd_candidate_iocs:
        second_stage_funcs["查询 wd"] = lambda: core.query_wd(wd_candidate_iocs)
    second_parallel_results = core.run_parallel_stages(second_stage_funcs)
    hash_map = second_parallel_results["提取并查询 hash 文件情报"]
    wd_map = second_parallel_results.get("查询 wd", {})

    atateam_evidence_ext_map = core.build_atateam_evidence_ext_map(
        black_iocs, xmon_map, hash_map, wfy_map, sc_malicious_map, wd_map
    )
    siyubo_evidence_details_map = core.build_siyubo_evidence_details_map(
        black_iocs, xmon_map, hash_map, wfy_map, sc_malicious_map, wd_map
    )
    atateam_workers, siyubo_workers = core.split_llm_stage_workers(
        len(atateam_evidence_ext_map),
        len(siyubo_evidence_details_map),
    )
    llm_stage_funcs: dict[str, Any] = {}
    if atateam_evidence_ext_map:
        llm_stage_funcs["总结 atateam evidence_chain"] = lambda: core.query_atateam_llm_summaries(
            atateam_evidence_ext_map,
            max_workers=atateam_workers,
        )
    if siyubo_evidence_details_map:
        llm_stage_funcs["总结 siyubo evidence_chain"] = lambda: core.query_siyubo_llm_summaries(
            siyubo_evidence_details_map,
            max_workers=siyubo_workers,
        )
    llm_parallel_results = core.run_parallel_stages(llm_stage_funcs) if llm_stage_funcs else {}
    atateam_summary_map = llm_parallel_results.get("总结 atateam evidence_chain", {})
    siyubo_summary_map = llm_parallel_results.get("总结 siyubo evidence_chain", {})

    ai_candidate_iocs = core.build_ai_candidate_iocs(
        ioc_list,
        xmon_map,
        hash_map,
        wfy_map,
        sc_malicious_map,
        wd_map,
        atateam_summary_map,
        siyubo_summary_map,
    )
    external_ioc_map = core.query_external_ioc_evidence(ai_candidate_iocs) if ai_candidate_iocs else {}
    ai_map = core.query_ai_quick_analysis(ai_candidate_iocs) if ai_candidate_iocs else {}

    decisions: dict[str, core.RowDecision] = {}
    for ioc in ioc_list:
        row = pd.Series({"ioc": ioc, "外联目标": ioc, "端口": split_port(ioc), "外联日期": ""})
        decision = core.decide_row(
            row,
            xmon_map.get(ioc, core.empty_xmon_info(ioc)),
            hash_map,
            wfy_map.get(ioc, {}),
            wd_map.get(ioc, core.WdInfo(ioc=ioc)),
            ai_map.get(ioc, core.AiInfo(ioc=ioc)),
            external_ioc_map.get(ioc, core.ExternalIocInfo(ioc=ioc)),
            atateam_summary_map.get(ioc, ""),
            siyubo_summary_map.get(ioc, ""),
            sc_malicious_map.get(ioc, False),
        )
        decisions[ioc] = decision

    return {"decisions": decisions, "ai_map": ai_map}


def _sc_is_empty(sc_raw: dict[str, Any]) -> bool:
    if not sc_raw:
        return True
    meaningful = {k: v for k, v in sc_raw.items() if k != "query_error" and v not in ("", None, [], {})}
    return not meaningful


def _build_sc(ioc: str, sc_raw: dict[str, Any]) -> dict[str, Any]:
    ioc_type = infer_supported_ioc_type(ioc)
    sc = empty_sc(ioc, ioc_type)
    level = core.extract_sc_level(sc_raw)
    if level is not None:
        if level > 30:
            sc["judge"] = "black"
        else:
            sc["judge"] = "white"
    sc["ext"]["status"] = _first_text(sc_raw, ("status", "state", "disable", "disabled"))
    sc["ext"]["tags_info"] = _build_sc_tags_info(sc_raw)
    return sc


def _build_sc_tags_info(sc_raw: dict[str, Any]) -> list[dict[str, str]]:
    tags = sc_raw.get("tags") if isinstance(sc_raw, dict) else []
    if not isinstance(tags, list):
        return []

    result: list[dict[str, str]] = []
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        tag_name = core.normalize_cell(tag.get("name", ""))
        tag_id = core.normalize_cell(tag.get("id", ""))
        tag_text = tag_name
        if tag_name and tag_id:
            tag_text = f"{tag_name}({tag_id})"
        elif tag_id:
            tag_text = tag_id
        result.append(
            {
                "tags": tag_text,
                "desc": core.normalize_cell(tag.get("desc", "")),
            }
        )
    return result


def _build_agent(
    ioc: str,
    sc: dict[str, Any],
    ai_info: core.AiInfo,
    decision: core.RowDecision | None = None,
) -> dict[str, Any]:
    agent = empty_agent(ioc, sc.get("judge", "unknown"), sc.get("ext", {}).get("status", ""))
    agent["handle_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if decision is not None and decision.rule_hit == "black_hash":
        agent["supplement_info"] = decision.info_add
        _fill_sample_behavior(agent, decision)
        return agent

    if decision is not None and decision.rule_hit == "report":
        agent["supplement_info"] = decision.info_add
        agent["evidence"]["source_links"] = _extract_first_url(decision.info_add)
        return agent

    if decision is not None and decision.rule_hit != "no_more_evidence" and decision.info_add:
        agent["supplement_info"] = decision.info_add
        agent["evidence"]["other_evidence"]["parent_evidence"] = decision.info_add
        return agent

    evidence_text = "；".join(ai_info.key_evidence)
    if ai_info.summary:
        evidence_text = ai_info.summary
    agent["evidence"]["other_evidence"]["parent_evidence"] = evidence_text
    return agent


def _fill_sample_behavior(agent: dict[str, Any], decision: core.RowDecision) -> None:
    sample_behavior = agent["evidence"]["sample_behavior"]
    sample_behavior["hash_md5"] = decision.file_hash
    sample_behavior["file_size"] = _parse_file_size_bytes(decision.file_size)
    sample_behavior["file_type"] = decision.file_type
    if decision.operating_system:
        sample_behavior["platform"] = [decision.operating_system]


def _parse_file_size_bytes(value: str) -> int | None:
    text = core.normalize_cell(value)
    if not text:
        return None
    match = re.search(r"\((\d+) bytes\)", text)
    if match:
        return int(match.group(1))
    if text.isdigit():
        return int(text)
    return None


def _extract_first_url(value: str) -> str:
    match = URL_RE.search(core.normalize_cell(value))
    if not match:
        return ""
    return core.clean_report_url(match.group(0))


def _project_table_from_decision(decision: core.RowDecision) -> dict[str, Any]:
    row = core.decision_to_result_row(decision)
    return {
        "ioc": row["拼接后的ioc"] or row["IOC"],
        "port": row["端口"],
        "vendor": row["厂商"],
        "outbound_date": row["外联日期"],
        "judgement_result": row["研判结果"],
        "alive_status": row["存活状态"],
        "file_hash": row["文件特征值"],
        "file_size": row["文件大小"],
        "file_type": row["文件类型"],
        "affected_operating_system": row["影响操作系统"],
        "create_time": row["创建时间"],
        "related_process": row["相关进程ID及文件名称"],
        "icp_connection_record": row["ICP连接记录"],
        "http_access_record": row["HTTP访问记录"],
        "traffic_feature": row["流量特征"],
        "other_file_feature": row["其他文件特征"],
        "supplement_info": row["补充信息"],
        "false_positive_reason": row["误报原因"],
    }


def _first_text(data: Any, keys: tuple[str, ...]) -> str:
    if not isinstance(data, dict):
        return ""
    for key in keys:
        value = data.get(key)
        text = core.normalize_cell(value)
        if text:
            return text
    for value in data.values():
        if isinstance(value, dict):
            text = _first_text(value, keys)
            if text:
                return text
        elif isinstance(value, list):
            for item in value:
                text = _first_text(item, keys)
                if text:
                    return text
    return ""


def _find_nested_dict(data: Any, key: str) -> dict[str, Any]:
    if isinstance(data, dict):
        value = data.get(key)
        if isinstance(value, dict):
            return value
        for nested in data.values():
            found = _find_nested_dict(nested, key)
            if found:
                return found
    if isinstance(data, list):
        for item in data:
            found = _find_nested_dict(item, key)
            if found:
                return found
    return {}
