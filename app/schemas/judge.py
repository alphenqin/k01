from __future__ import annotations

from typing import Any


def empty_sc(search_ioc: str = "", ioc_type: str = "") -> dict[str, Any]:
    return {
        "search_ioc": search_ioc,
        "ioc_type": ioc_type,
        "judge": "unknown",
        "ext": {
            "status": "",
            "tags_info": [],
        },
    }


def empty_agent(ioc: str = "", judge: str = "unknown", status: str = "") -> dict[str, Any]:
    return {
        "search_ioc": ioc,
        "ioc": ioc,
        "judge": judge,
        "status": status,
        "vendor": "360",
        "handle_time": "",
        "supplement_info": "",
        "evidence": {
            "sample_behavior": {
                "hash_md5": "",
                "hash_sha256": "",
                "file_name": [],
                "file_size": None,
                "file_type": "",
                "platform": [],
                "persistence_mechanism": "",
                "files_written": "",
                "processes_tree": "",
                "tcp_connections": "",
                "http_requests": "",
                "behavior_description": "",
            },
            "traffic_fragments": {
                "traffic_type": "",
                "traffic_pattern": "",
                "description": "",
            },
            "phishing_details": {
                "brand": [],
                "target_system": [],
                "website_title": [],
                "backend_url": [],
                "download_link": [],
                "download_name": [],
                "behavior_description": "",
            },
            "source_links": "",
            "other_evidence": {
                "parent_intelligence": [],
                "parent_evidence": "",
                "pivoting_feature": "",
            },
        },
    }


def empty_project_table(ioc: str = "", port: str = "") -> dict[str, Any]:
    return {
        "ioc": ioc,
        "port": port,
        "vendor": "360",
        "outbound_date": "",
        "judgement_result": "",
        "alive_status": "",
        "file_hash": "",
        "file_size": "",
        "file_type": "",
        "affected_operating_system": "",
        "create_time": "",
        "related_process": "",
        "icp_connection_record": "",
        "http_access_record": "",
        "traffic_feature": "",
        "other_file_feature": "",
        "supplement_info": "",
        "false_positive_reason": "",
    }


def empty_item(ioc: str, ioc_type: str = "", port: str = "", error: str = "") -> dict[str, Any]:
    return {
        "ioc": ioc,
        "error": error,
        "sc": empty_sc(ioc, ioc_type),
        "agent": empty_agent(ioc),
        "project_k01_table_daily": empty_project_table(ioc, port),
    }
