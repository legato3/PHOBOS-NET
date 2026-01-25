import uuid
from typing import Dict, List, Optional

from app.services.events.model import EventRecord
from app.services.shared.helpers import fmt_bytes


def _event(
    *,
    ts: int,
    source: str,
    severity: str,
    title: str,
    summary: str,
    rule_id: str,
    dedupe_key: str,
    window_sec: int,
    tags: Optional[List[str]] = None,
    evidence: Optional[Dict[str, object]] = None,
    count: int = 1,
) -> EventRecord:
    primary_entity = None
    if evidence and isinstance(evidence, dict):
        val = evidence.get("primary_entity")
        if val is not None:
            primary_entity = str(val)
    return EventRecord(
        id=str(uuid.uuid4()),
        ts=ts,
        source=source,
        severity=severity,
        title=title,
        summary=summary,
        tags=tags or [],
        evidence=evidence or {},
        rule_id=rule_id,
        dedupe_key=dedupe_key,
        window_sec=window_sec,
        count=count,
        kind="notable",
        primary_entity=primary_entity,
    )


def _with_context(
    evidence: Dict[str, object],
    *,
    primary_entity: str,
    window_sec: int,
    baseline_value: float,
    current_value: float,
    min_abs_threshold: float,
) -> Dict[str, object]:
    ratio = None
    if baseline_value > 0:
        ratio = round(current_value / baseline_value, 2)
    enriched = dict(evidence)
    enriched.update(
        {
            "primary_entity": primary_entity,
            "window_sec": window_sec,
            "baseline_value": round(baseline_value, 2),
            "current_value": round(current_value, 2),
            "ratio": ratio,
            "min_abs_threshold": min_abs_threshold,
        }
    )
    return enriched


def rule_new_external_destination(
    *,
    ts: int,
    dst_ip: str,
    country: str,
    dst_ports: List[int],
    top_src_ip: Optional[str],
    bytes_count: int,
    flows_count: int,
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = f"New external destination {dst_ip}"
    summary = "First time seen in the last 24 hours"
    base = {
        "dst_ip": dst_ip,
        "dst_country": country or "UNKNOWN",
        "dst_ports": dst_ports,
        "top_src_ip": top_src_ip or "UNKNOWN",
        "bytes": bytes_count,
        "flows": flows_count,
        "bytes_fmt": fmt_bytes(bytes_count),
    }
    evidence = _with_context(
        base,
        primary_entity=dst_ip,
        window_sec=300,
        baseline_value=0,
        current_value=flows_count,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="netflow",
        severity="notice",
        title=title,
        summary=summary,
        rule_id="NEW_EXTERNAL_DESTINATION",
        dedupe_key=f"NEW_EXTERNAL_DESTINATION:{dst_ip}",
        window_sec=300,
        tags=["NETFLOW", "NEW", "EXTERNAL"],
        evidence=evidence,
    )


def rule_top_talker_changed(
    *,
    ts: int,
    direction: str,
    old_top: str,
    new_top: str,
    delta_pct: float,
    bytes_count: int,
    baseline_value: float = 0,
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = f"Top {direction} talker changed"
    summary = f"{old_top} → {new_top}"
    base = {
        "old_top": old_top,
        "new_top": new_top,
        "delta_pct": round(delta_pct, 1),
        "bytes": bytes_count,
        "bytes_fmt": fmt_bytes(bytes_count),
    }
    evidence = _with_context(
        base,
        primary_entity=direction,
        window_sec=300,
        baseline_value=baseline_value,
        current_value=bytes_count,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="netflow",
        severity="info",
        title=title,
        summary=summary,
        rule_id="TOP_TALKER_CHANGED",
        dedupe_key=f"TOP_TALKER_CHANGED:{direction}",
        window_sec=300,
        tags=["NETFLOW", "TOP", direction.upper()],
        evidence=evidence,
    )


def rule_port_spike(
    *,
    ts: int,
    port: int,
    current: int,
    baseline: float,
    top_src: Optional[str],
    top_dst: Optional[str],
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = f"Port {port} spike"
    summary = f"{current} vs baseline {baseline:.1f}"
    base = {
        "port": port,
        "current": current,
        "baseline": round(baseline, 1),
        "top_src_ip": top_src or "UNKNOWN",
        "top_dst_ip": top_dst or "UNKNOWN",
    }
    evidence = _with_context(
        base,
        primary_entity=str(port),
        window_sec=300,
        baseline_value=baseline,
        current_value=current,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="netflow",
        severity="warn",
        title=title,
        summary=summary,
        rule_id="PORT_SPIKE",
        dedupe_key=f"PORT_SPIKE:{port}",
        window_sec=300,
        tags=["NETFLOW", "PORT", str(port)],
        evidence=evidence,
        count=current,
    )


def rule_block_spike(
    *,
    ts: int,
    interface: str,
    action: str,
    current: int,
    baseline: float,
    top_src: Optional[str],
    top_dst: Optional[str],
    top_port: Optional[int],
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = "Firewall block spike"
    summary = f"{current} blocks vs baseline {baseline:.1f}"
    base = {
        "interface": interface,
        "action": action,
        "current": current,
        "baseline": round(baseline, 1),
        "top_src_ip": top_src or "UNKNOWN",
        "top_dst_ip": top_dst or "UNKNOWN",
        "top_port": top_port or 0,
    }
    evidence = _with_context(
        base,
        primary_entity=f"{interface}:{action}",
        window_sec=300,
        baseline_value=baseline,
        current_value=current,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="filterlog",
        severity="warn",
        title=title,
        summary=summary,
        rule_id="BLOCK_SPIKE",
        dedupe_key=f"BLOCK_SPIKE:{interface}:{action}",
        window_sec=300,
        tags=["FIREWALL", "BLOCK", interface.upper()],
        evidence=evidence,
        count=current,
    )


def rule_new_inbound_wan_source(
    *,
    ts: int,
    src_ip: str,
    country: str,
    dst_port: int,
    rule_label: Optional[str],
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = "New inbound WAN source"
    summary = f"{src_ip} first seen on WAN"
    base = {
        "src_ip": src_ip,
        "country": country or "UNKNOWN",
        "dst_port": dst_port,
        "rule_label": rule_label or "UNKNOWN",
    }
    evidence = _with_context(
        base,
        primary_entity=src_ip,
        window_sec=300,
        baseline_value=0,
        current_value=1,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="filterlog",
        severity="notice",
        title=title,
        summary=summary,
        rule_id="NEW_INBOUND_WAN_SOURCE",
        dedupe_key=f"NEW_INBOUND_WAN_SOURCE:{src_ip}",
        window_sec=300,
        tags=["FIREWALL", "WAN", "NEW"],
        evidence=evidence,
    )


def rule_rule_hit_spike(
    *,
    ts: int,
    rule_id: str,
    rule_label: str,
    current: int,
    baseline: float,
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = "Rule hit spike"
    summary = f"{current} hits vs baseline {baseline:.1f}"
    base = {
        "rule_id": rule_id,
        "rule_label": rule_label,
        "current": current,
        "baseline": round(baseline, 1),
    }
    evidence = _with_context(
        base,
        primary_entity=rule_id or rule_label,
        window_sec=300,
        baseline_value=baseline,
        current_value=current,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="filterlog",
        severity="notice",
        title=title,
        summary=summary,
        rule_id="RULE_HIT_SPIKE",
        dedupe_key=f"RULE_HIT_SPIKE:{rule_id or rule_label}",
        window_sec=300,
        tags=["FIREWALL", "RULE"],
        evidence=evidence,
        count=current,
    )


def rule_nxdomain_burst(
    *,
    ts: int,
    current: int,
    baseline: float,
    top_domains: List[str],
    top_clients: List[str],
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = "NXDOMAIN burst"
    summary = f"{current} NXDOMAIN vs baseline {baseline:.1f}"
    base = {
        "current": current,
        "baseline": round(baseline, 1),
        "top_domains": top_domains,
        "top_clients": top_clients,
    }
    evidence = _with_context(
        base,
        primary_entity="nxdomain",
        window_sec=300,
        baseline_value=baseline,
        current_value=current,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="syslog",
        severity="notice",
        title=title,
        summary=summary,
        rule_id="NXDOMAIN_BURST",
        dedupe_key="NXDOMAIN_BURST",
        window_sec=300,
        tags=["SYSLOG", "DNS"],
        evidence=evidence,
        count=current,
    )


def rule_new_domain_to_many_hosts(
    *,
    ts: int,
    domain: str,
    host_count: int,
    top_hosts: List[str],
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = "New domain queried by many hosts"
    summary = f"{domain} queried by {host_count} hosts"
    base = {
        "domain": domain,
        "host_count": host_count,
        "top_hosts": top_hosts,
    }
    evidence = _with_context(
        base,
        primary_entity=domain,
        window_sec=300,
        baseline_value=0,
        current_value=host_count,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="syslog",
        severity="notice",
        title=title,
        summary=summary,
        rule_id="NEW_DOMAIN_TO_MANY_HOSTS",
        dedupe_key=f"NEW_DOMAIN_TO_MANY_HOSTS:{domain}",
        window_sec=300,
        tags=["SYSLOG", "DNS", "NEW"],
        evidence=evidence,
        count=host_count,
    )


def rule_source_stale(
    *,
    ts: int,
    source: str,
    last_seen_age: float,
    threshold: int,
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = "Source stale"
    summary = f"No data for {int(last_seen_age)}s (threshold {threshold}s)"
    base = {
        "source": source,
        "last_seen_age": round(last_seen_age, 1),
        "threshold": threshold,
    }
    evidence = _with_context(
        base,
        primary_entity=source,
        window_sec=threshold,
        baseline_value=threshold,
        current_value=last_seen_age,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="system",
        severity="notice",
        title=title,
        summary=summary,
        rule_id="SOURCE_STALE",
        dedupe_key=f"SOURCE_STALE:{source}",
        window_sec=threshold,
        tags=["SYSTEM", "STALE"],
        evidence=evidence,
    )


def rule_parser_error_spike(
    *,
    ts: int,
    parser: str,
    current: int,
    baseline: float,
    sample_error: Optional[str],
    min_abs_threshold: float = 1,
) -> EventRecord:
    title = "Parser error spike"
    summary = f"{current} errors vs baseline {baseline:.1f}"
    base = {
        "parser": parser,
        "current": current,
        "baseline": round(baseline, 1),
        "sample_error": sample_error or "UNKNOWN",
    }
    evidence = _with_context(
        base,
        primary_entity=parser,
        window_sec=300,
        baseline_value=baseline,
        current_value=current,
        min_abs_threshold=min_abs_threshold,
    )
    return _event(
        ts=ts,
        source="system",
        severity="warn",
        title=title,
        summary=summary,
        rule_id="PARSER_ERROR_SPIKE",
        dedupe_key=f"PARSER_ERROR_SPIKE:{parser}",
        window_sec=300,
        tags=["SYSTEM", "PARSER"],
        evidence=evidence,
        count=current,
    )
