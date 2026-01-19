#!/usr/bin/env python3
import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests

DEFAULT_INDEX_PATTERN = r"^logstash-(.+)-\d+$"
DEFAULT_WEIGHTS = {
    "storage_gb": 1.0,
    "shard_count": 5.0,
    "segment_count": 0.1,
    "fielddata_mb": 2.0,
    "query_cache_mb": 0.5,
}
WEIGHTED_METRICS = {
    "total_storage_gb": "storage_gb",
    "total_shards": "shard_count",
    "total_segments": "segment_count",
    "fielddata_mb": "fielddata_mb",
    "query_cache_mb": "query_cache_mb",
}
HEAP_USAGE_KEYS = (
    "segment_memory_mb",
    "fielddata_mb",
    "query_cache_mb",
    "request_cache_mb",
)
CLUSTER_COST = 1000.0
REPORT_WIDTH = 80
NAME_WIDTH = 40


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze Elasticsearch index impact for billing.")
    parser.add_argument("--host", default="localhost", help="Elasticsearch host")
    parser.add_argument("--port", type=int, default=9200, help="Elasticsearch port")
    parser.add_argument("--user", help="Username for basic auth")
    parser.add_argument("--password", help="Password for basic auth")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("-o", "--output", help="Write output to a file")
    parser.add_argument("--top", type=int, help="Show only top consumers")
    parser.add_argument(
        "--index-pattern",
        default=DEFAULT_INDEX_PATTERN,
        help=(
            "Regex for grouping indices. Use a capture group for log name "
            "(named group 'log_name' preferred)."
        ),
    )
    parser.add_argument(
        "--score-mode",
        choices=["normalized", "weighted"],
        default="normalized",
        help="Scoring mode: normalized (default, cluster capacity) or weighted.",
    )

    parser.add_argument(
        "--weight-storage",
        type=float,
        default=DEFAULT_WEIGHTS["storage_gb"],
        help="Weight for storage in GB (weighted mode only)",
    )
    parser.add_argument(
        "--weight-shards",
        type=float,
        default=DEFAULT_WEIGHTS["shard_count"],
        help="Weight for shard count (weighted mode only)",
    )
    parser.add_argument(
        "--weight-segments",
        type=float,
        default=DEFAULT_WEIGHTS["segment_count"],
        help="Weight for segment count (weighted mode only)",
    )
    parser.add_argument(
        "--weight-fielddata",
        type=float,
        default=DEFAULT_WEIGHTS["fielddata_mb"],
        help="Weight for fielddata in MB (weighted mode only)",
    )
    parser.add_argument(
        "--weight-query-cache",
        type=float,
        default=DEFAULT_WEIGHTS["query_cache_mb"],
        help="Weight for query cache in MB (weighted mode only)",
    )

    return parser.parse_args()


def request_json(session: requests.Session, url: str, params: Dict[str, str]) -> Dict[str, Any]:
    response = session.get(url, params=params, timeout=30)
    response.raise_for_status()
    return response.json()


def bytes_to_gb(value: float) -> float:
    return value / (1024 ** 3)


def bytes_to_mb(value: float) -> float:
    return value / (1024 ** 2)


def to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def fetch_cluster_capacity(session: requests.Session, base_url: str) -> Dict[str, float]:
    stats = request_json(session, f"{base_url}/_cluster/stats", params={})
    nodes = stats.get("nodes", {})
    fs_total_bytes = nodes.get("fs", {}).get("total_in_bytes", 0)
    heap_max_bytes = nodes.get("jvm", {}).get("mem", {}).get("heap_max_in_bytes", 0)

    return {
        "disk_total_gb": bytes_to_gb(fs_total_bytes),
        "heap_max_mb": bytes_to_mb(heap_max_bytes),
    }


def collect_index_metrics(stats: Dict[str, Any], settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    metrics: List[Dict[str, Any]] = []
    for index_name, index_stats in stats.get("indices", {}).items():
        primaries = index_stats.get("primaries", {})
        total = index_stats.get("total", {})

        primary_store_bytes = primaries.get("store", {}).get("size_in_bytes", 0)
        total_store_bytes = total.get("store", {}).get("size_in_bytes", 0)
        doc_count = primaries.get("docs", {}).get("count", 0)
        segment_count = total.get("segments", {}).get("count", 0)
        segment_memory_bytes = total.get("segments", {}).get("memory_in_bytes", 0)
        fielddata_bytes = total.get("fielddata", {}).get("memory_size_in_bytes", 0)
        query_cache_bytes = total.get("query_cache", {}).get("memory_size_in_bytes", 0)
        request_cache_bytes = total.get("request_cache", {}).get("memory_size_in_bytes", 0)

        settings_index = settings.get(index_name, {}).get("settings", {}).get("index", {})
        num_shards = to_int(settings_index.get("number_of_shards"))
        num_replicas = to_int(settings_index.get("number_of_replicas"))
        shard_count = num_shards * (1 + num_replicas)

        metrics.append(
            {
                "name": index_name,
                "primary_storage_gb": bytes_to_gb(primary_store_bytes),
                "total_storage_gb": bytes_to_gb(total_store_bytes),
                "doc_count": doc_count,
                "total_shards": shard_count,
                "total_segments": segment_count,
                "segment_memory_mb": bytes_to_mb(segment_memory_bytes),
                "fielddata_mb": bytes_to_mb(fielddata_bytes),
                "query_cache_mb": bytes_to_mb(query_cache_bytes),
                "request_cache_mb": bytes_to_mb(request_cache_bytes),
            }
        )
    return metrics


def init_group(log_name: str) -> Dict[str, Any]:
    return {
        "log_name": log_name,
        "index_count": 0,
        "impact_score": 0.0,
        "metrics": {
            "primary_storage_gb": 0.0,
            "total_storage_gb": 0.0,
            "doc_count": 0,
            "total_shards": 0,
            "total_segments": 0,
            "segment_memory_mb": 0.0,
            "fielddata_mb": 0.0,
            "query_cache_mb": 0.0,
            "request_cache_mb": 0.0,
        },
        "indices": [],
    }


def extract_log_name(match: re.Match, index_name: str) -> str:
    if "log_name" in match.re.groupindex:
        name = match.group("log_name")
    elif match.re.groups >= 1:
        name = match.group(1)
    else:
        name = None

    return name if name else index_name


def group_by_logname(
    metrics: List[Dict[str, Any]], index_pattern: re.Pattern
) -> Tuple[List[Dict[str, Any]], List[str]]:
    groups: Dict[str, Dict[str, Any]] = {}
    unmatched: List[str] = []

    for entry in metrics:
        match = index_pattern.match(entry["name"])
        if not match:
            unmatched.append(entry["name"])
            continue

        log_name = extract_log_name(match, entry["name"])
        group = groups.setdefault(log_name, init_group(log_name))
        group["index_count"] += 1
        group["indices"].append(entry["name"])

        for key in group["metrics"]:
            group["metrics"][key] += entry[key]

    return list(groups.values()), unmatched


def calculate_weighted_impact(metrics: Dict[str, Any], weights: Dict[str, float]) -> float:
    return sum(
        metrics[key] * weights[weight_key] for key, weight_key in WEIGHTED_METRICS.items()
    )


def calculate_capacity_impact(metrics: Dict[str, Any], capacity: Dict[str, float]) -> float:
    score = 0.0
    disk_total_gb = capacity.get("disk_total_gb", 0.0)
    heap_max_mb = capacity.get("heap_max_mb", 0.0)

    if disk_total_gb:
        score += metrics["total_storage_gb"] / disk_total_gb

    if heap_max_mb:
        heap_usage_mb = sum(metrics[key] for key in HEAP_USAGE_KEYS)
        score += heap_usage_mb / heap_max_mb

    return score


def apply_scoring(
    groups: List[Dict[str, Any]],
    score_mode: str,
    weights: Dict[str, float],
    capacity: Optional[Dict[str, float]],
) -> List[Dict[str, Any]]:
    if score_mode == "normalized":
        for group in groups:
            group["impact_score"] = calculate_capacity_impact(group["metrics"], capacity or {})
    else:
        for group in groups:
            group["impact_score"] = calculate_weighted_impact(group["metrics"], weights)

    return sorted(groups, key=lambda g: g["impact_score"], reverse=True)


def render_report(
    groups: List[Dict[str, Any]],
    display_groups: List[Dict[str, Any]],
    score_mode: str,
    weights: Dict[str, float],
    total_impact: float,
    capacity: Optional[Dict[str, float]],
) -> str:
    lines: List[str] = []
    lines.append("=" * REPORT_WIDTH)
    lines.append("ELASTICSEARCH INDEX IMPACT ANALYSIS FOR BILLING")
    lines.append("=" * REPORT_WIDTH)
    lines.append("")
    if score_mode == "normalized":
        lines.append("Scoring mode: normalized (cluster capacity)")
        if capacity:
            lines.append(
                "Cluster totals: "
                f"disk {capacity.get('disk_total_gb', 0.0):.2f}G, "
                f"heap {capacity.get('heap_max_mb', 0.0):.0f}MB"
            )
    else:
        lines.append("Scoring mode: weighted")
        lines.append(f"Weights used: {json.dumps(weights, indent=2)}")
    lines.append("")
    lines.append(f"Total log groups analyzed: {len(groups)}")
    lines.append(f"Total impact score: {total_impact:.2f}")
    lines.append("Storage column uses total store size (primaries + replicas).")
    lines.append("")
    lines.append("-" * REPORT_WIDTH)
    lines.append(
        f"{'Log Name':<{NAME_WIDTH}} {'Impact':>10} {'Storage':>10} {'Shards':>8} {'Indices':>8}"
    )
    lines.append("-" * REPORT_WIDTH)

    for group in display_groups:
        storage_display = f"{group['metrics']['total_storage_gb']:.2f}G"
        lines.append(
            f"{group['log_name']:<{NAME_WIDTH}}"
            f" {group['impact_score']:>10.2f}"
            f" {storage_display:>10}"
            f" {group['metrics']['total_shards']:>8d}"
            f" {group['index_count']:>8d}"
        )

    lines.append("")
    lines.append("=" * REPORT_WIDTH)
    lines.append("BILLING PERCENTAGE BREAKDOWN")
    lines.append("=" * REPORT_WIDTH)
    lines.append("")
    lines.append(
        f"{'Log Name':<{NAME_WIDTH}} {'Impact %':>9} {'Estimated Monthly $':>20}"
    )
    lines.append("-" * REPORT_WIDTH)

    for group in display_groups:
        impact_pct = (group["impact_score"] / total_impact * 100.0) if total_impact else 0.0
        estimated_cost = CLUSTER_COST * (impact_pct / 100.0)
        lines.append(
            f"{group['log_name']:<{NAME_WIDTH}}"
            f" {impact_pct:>8.2f}%"
            f" {estimated_cost:>20.2f}"
        )

    lines.append("...")
    lines.append(f"(Based on example cluster cost of ${CLUSTER_COST:.0f}/month)")
    return "\n".join(lines)


def build_json_output(display_groups: List[Dict[str, Any]]) -> str:
    payload = []
    for group in display_groups:
        payload.append(
            {
                "log_name": group["log_name"],
                "index_count": group["index_count"],
                "impact_score": round(group["impact_score"], 2),
                "metrics": {
                    "primary_storage_gb": round(group["metrics"]["primary_storage_gb"], 3),
                    "total_storage_gb": round(group["metrics"]["total_storage_gb"], 3),
                    "doc_count": int(group["metrics"]["doc_count"]),
                    "total_shards": int(group["metrics"]["total_shards"]),
                    "total_segments": int(group["metrics"]["total_segments"]),
                    "segment_memory_mb": round(group["metrics"]["segment_memory_mb"], 2),
                    "fielddata_mb": round(group["metrics"]["fielddata_mb"], 2),
                    "query_cache_mb": round(group["metrics"]["query_cache_mb"], 2),
                    "request_cache_mb": round(group["metrics"]["request_cache_mb"], 2),
                },
                "indices": group["indices"],
            }
        )
    return json.dumps(payload, indent=2)


def write_output(content: str, output_path: Optional[str], is_json: bool) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        label = "JSON report" if is_json else "report"
        print(f"Wrote {label} to {output_path}", file=sys.stderr)
    else:
        print(content)


def main() -> int:
    args = parse_args()

    if (args.user and not args.password) or (args.password and not args.user):
        print("Both --user and --password are required for basic auth.", file=sys.stderr)
        return 2

    weights = {
        "storage_gb": args.weight_storage,
        "shard_count": args.weight_shards,
        "segment_count": args.weight_segments,
        "fielddata_mb": args.weight_fielddata,
        "query_cache_mb": args.weight_query_cache,
    }

    scheme = "https" if args.ssl else "http"
    base_url = f"{scheme}://{args.host}:{args.port}"

    session = requests.Session()
    if args.user and args.password:
        session.auth = (args.user, args.password)

    try:
        stats = request_json(
            session,
            f"{base_url}/_stats",
            params={
                "metric": "store,docs,segments,fielddata,query_cache,request_cache",
                "level": "indices",
            },
        )
        settings = request_json(
            session,
            f"{base_url}/_settings",
            params={
                "filter_path": "**.settings.index.number_of_shards,**.settings.index.number_of_replicas"
            },
        )
    except requests.RequestException as exc:
        print(f"Failed to fetch data from {base_url}: {exc}", file=sys.stderr)
        return 1

    capacity: Optional[Dict[str, float]] = None
    if args.score_mode == "normalized":
        try:
            capacity = fetch_cluster_capacity(session, base_url)
        except requests.RequestException as exc:
            print(
                f"Failed to fetch cluster capacity from {base_url}: {exc}",
                file=sys.stderr,
            )
            return 1

        disk_total = capacity.get("disk_total_gb", 0.0)
        heap_total = capacity.get("heap_max_mb", 0.0)
        if not disk_total and not heap_total:
            print(
                "Cluster capacity totals are unavailable; normalized scoring requires cluster stats.",
                file=sys.stderr,
            )
            print("Use --score-mode weighted to bypass capacity-based scoring.", file=sys.stderr)
            return 1
        if not disk_total or not heap_total:
            missing = []
            if not disk_total:
                missing.append("disk total")
            if not heap_total:
                missing.append("heap max")
            print(
                "Normalized scoring will skip missing capacity metrics: "
                + ", ".join(missing),
                file=sys.stderr,
            )

    index_metrics = collect_index_metrics(stats, settings)
    try:
        index_pattern = re.compile(args.index_pattern)
    except re.error as exc:
        print(f"Invalid --index-pattern: {exc}", file=sys.stderr)
        return 2

    if index_pattern.groups == 0:
        print(
            "Index pattern has no capture groups; grouping by full index name.",
            file=sys.stderr,
        )

    groups, unmatched = group_by_logname(index_metrics, index_pattern)

    if unmatched:
        print(
            f"Skipped {len(unmatched)} indices that do not match pattern {index_pattern.pattern}",
            file=sys.stderr,
        )

    if not groups:
        print("No indices matched the expected pattern.", file=sys.stderr)
        return 1

    groups = apply_scoring(groups, args.score_mode, weights, capacity)

    display_groups = groups[: args.top] if args.top else groups
    total_impact = sum(group["impact_score"] for group in groups)

    if args.json:
        output = build_json_output(display_groups)
    else:
        output = render_report(
            groups, display_groups, args.score_mode, weights, total_impact, capacity
        )

    write_output(output, args.output, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
