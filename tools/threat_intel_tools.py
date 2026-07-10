from __future__ import annotations

import base64
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from state import ThreatIntelResult
from tools.audit_utils import make_audit_entry

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
MOCK_DATA_PATH = Path("data/mock_threat_intel.json")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _load_mock_data() -> dict[str, Any]:
    if MOCK_DATA_PATH.exists():
        return json.loads(MOCK_DATA_PATH.read_text(encoding="utf-8"))
    return {}


def _result_from_mock(indicator: str, indicator_type: str, reason: str) -> ThreatIntelResult:
    mock_data = _load_mock_data()
    mock_entry = mock_data.get(indicator, {})
    return ThreatIntelResult(
        indicator=indicator,
        indicator_type=indicator_type,
        reputation=mock_entry.get("reputation", "unknown"),
        confidence=float(mock_entry.get("confidence", 0.35)),
        sources=mock_entry.get("sources", ["local_mock"]),
        evidence=mock_entry.get("evidence", [reason]),
        details=mock_entry.get("details", {}),
        errors=[] if mock_entry else [reason],
        mocked=True,
    )


def _vt_headers() -> dict[str, str]:
    if not VT_API_KEY:
        raise ValueError("VirusTotal API key not configured.")
    return {"X-Apikey": VT_API_KEY}


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _format_unix_timestamp(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return None


def _get_nested(payload: dict[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _vt_reputation_and_confidence(stats: dict[str, Any]) -> tuple[str, float, dict[str, int]]:
    malicious = _safe_int(stats.get("malicious", 0))
    suspicious = _safe_int(stats.get("suspicious", 0))
    harmless = _safe_int(stats.get("harmless", 0))
    undetected = _safe_int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    if malicious > 0:
        reputation = "malicious"
    elif suspicious > 0:
        reputation = "suspicious"
    elif harmless > 0 or undetected > 0:
        reputation = "benign"
    else:
        reputation = "unknown"

    confidence = min(
        0.95,
        0.2
        + (malicious * 0.1)
        + (suspicious * 0.05)
        + (0.15 if total > 0 else 0.0),
    )
    if reputation == "benign" and total > 0:
        confidence = max(confidence, 0.45)
    if reputation == "unknown":
        confidence = min(confidence, 0.35)

    normalized_stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
    }
    return reputation, round(confidence, 2), normalized_stats


def _vt_request(path: str) -> dict[str, Any]:
    response = requests.get(
        url=f"{VT_BASE_URL}/{path}",
        headers=_vt_headers(),
        timeout=10,
    )
    response.raise_for_status()
    return response.json().get("data", {}).get("attributes", {})


def _vt_check_ip(indicator: str) -> tuple[dict[str, Any], dict[str, int]]:
    data = _vt_request(f"ip_addresses/{indicator}")
    stats = data.get("last_analysis_stats", {})
    return {
        "country": data.get("country"),
        "network": data.get("network"),
        "as_owner": data.get("as_owner"),
        "regional_internet_registry": data.get("regional_internet_registry"),
        "last_analysis_stats": stats,
    }, _vt_reputation_and_confidence(stats)[2]


def _vt_check_domain(indicator: str) -> tuple[dict[str, Any], dict[str, int]]:
    data = _vt_request(f"domains/{indicator}")
    stats = data.get("last_analysis_stats", {})
    cert_alt_names = _get_nested(
        data,
        "last_https_certificate",
        "extensions",
        "subject_alternative_name",
    )
    return {
        "alt_names": cert_alt_names if isinstance(cert_alt_names, list) else [],
        "domain_expiration": _format_unix_timestamp(data.get("expiration_date")),
        "domain_reputation_stats": stats,
        "last_analysis_stats": stats,
        "rdap": data.get("rdap", {}),
    }, _vt_reputation_and_confidence(stats)[2]


def _vt_check_url(indicator: str) -> tuple[dict[str, Any], dict[str, int]]:
    data = _vt_request(f"urls/{_vt_url_id(indicator)}")
    stats = data.get("last_analysis_stats", {})
    html_meta = data.get("html_meta", {}) if isinstance(data.get("html_meta"), dict) else {}
    og_url = html_meta.get("og:url")
    if isinstance(og_url, list):
        normalized_og_url = og_url[0] if og_url else None
    else:
        normalized_og_url = og_url

    return {
        "url_description": html_meta.get("description"),
        "url_reputation": stats,
        "og_url": normalized_og_url,
        "last_analysis_stats": stats,
    }, _vt_reputation_and_confidence(stats)[2]


def _query_virustotal(
    indicator: str,
    indicator_type: str,
    audit_log: list[dict[str, Any]] | None = None,
) -> ThreatIntelResult:
    if not VT_API_KEY:
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id="threat_intel",
                    agent_name="ThreatIntelAgent",
                    action="query_virustotal",
                    details={"indicator": indicator, "indicator_type": indicator_type, "status": "mock_fallback", "reason": "api_key_missing"},
                )
            )
        return _result_from_mock(indicator, indicator_type, "VirusTotal API key not configured.")

    handlers = {
        "ip": _vt_check_ip,
        "domain": _vt_check_domain,
        "url": _vt_check_url,
    }
    handler = handlers.get(indicator_type)
    if not handler:
        return _result_from_mock(indicator, indicator_type, "Unsupported indicator type for VirusTotal.")

    try:
        details, _ = handler(indicator)
        stats = details.get("last_analysis_stats", {})
        reputation, confidence, normalized_stats = _vt_reputation_and_confidence(stats)
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id="threat_intel",
                    agent_name="ThreatIntelAgent",
                    action="query_virustotal",
                    details={
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "status": "success",
                        "reputation": reputation,
                    },
                )
            )
        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=reputation,
            confidence=confidence,
            sources=["VirusTotal"],
            evidence=[
                (
                    "VirusTotal stats: "
                    f"malicious={normalized_stats['malicious']}, "
                    f"suspicious={normalized_stats['suspicious']}, "
                    f"harmless={normalized_stats['harmless']}, "
                    f"undetected={normalized_stats['undetected']}"
                )
            ],
            details={
                **details,
                "vt_malicious_count": normalized_stats["malicious"],
                "vt_suspicious_count": normalized_stats["suspicious"],
                "vt_harmless_count": normalized_stats["harmless"],
                "vt_undetected_count": normalized_stats["undetected"],
                "vt_total_engines": normalized_stats["total"],
            },
            mocked=False,
        )
    except Exception as exc:
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id="threat_intel",
                    agent_name="ThreatIntelAgent",
                    action="query_virustotal",
                    details={
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "status": "mock_fallback",
                        "reason": str(exc),
                    },
                )
            )
        result = _result_from_mock(indicator, indicator_type, f"VirusTotal query failed: {exc}")
        result.errors.append(str(exc))
        return result


def _query_abuseipdb(indicator: str, audit_log: list[dict[str, Any]] | None = None) -> ThreatIntelResult:
    if not ABUSEIPDB_API_KEY:
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id="threat_intel",
                    agent_name="ThreatIntelAgent",
                    action="query_abuseipdb",
                    details={"indicator": indicator, "status": "mock_fallback", "reason": "api_key_missing"},
                )
            )
        return _result_from_mock(indicator, "ip", "AbuseIPDB API key not configured.")

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": indicator, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        reputation = "malicious" if score >= 75 else "suspicious" if score >= 25 else "benign"
        confidence = round(min(0.95, 0.3 + (score / 100)), 2)
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id="threat_intel",
                    agent_name="ThreatIntelAgent",
                    action="query_abuseipdb",
                    details={"indicator": indicator, "status": "success", "reputation": reputation, "score": score},
                )
            )
        return ThreatIntelResult(
            indicator=indicator,
            indicator_type="ip",
            reputation=reputation,
            confidence=confidence,
            sources=["AbuseIPDB"],
            evidence=[f"AbuseIPDB confidence score: {score}"],
            details={
                "abuse_confidence_score": score,
                "country_code": data.get("countryCode"),
                "domain": data.get("domain"),
                "tor_status": data.get("isTor"),
                "usage_type": data.get("usageType"),
            },
            mocked=False,
        )
    except Exception as exc:
        if audit_log is not None:
            audit_log.append(
                make_audit_entry(
                    agent_id="threat_intel",
                    agent_name="ThreatIntelAgent",
                    action="query_abuseipdb",
                    details={"indicator": indicator, "status": "mock_fallback", "reason": str(exc)},
                )
            )
        result = _result_from_mock(indicator, "ip", f"AbuseIPDB query failed: {exc}")
        result.errors.append(str(exc))
        return result


def enrich_indicators(
    indicators: list[tuple[str, str]],
    audit_log: list[dict[str, Any]] | None = None,
) -> list[ThreatIntelResult]:
    results: list[ThreatIntelResult] = []
    seen: set[tuple[str, str]] = set()

    for indicator, indicator_type in indicators:
        key = (indicator, indicator_type)
        if key in seen:
            continue
        seen.add(key)

        vt_result = _query_virustotal(indicator, indicator_type, audit_log=audit_log)
        if indicator_type == "ip":
            abuse_result = _query_abuseipdb(indicator, audit_log=audit_log)
            merged = ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                reputation=vt_result.reputation if vt_result.reputation != "unknown" else abuse_result.reputation,
                confidence=round(max(vt_result.confidence, abuse_result.confidence), 2),
                sources=sorted(set(vt_result.sources + abuse_result.sources)),
                evidence=vt_result.evidence + abuse_result.evidence,
                details={"virustotal": vt_result.details, "abuseipdb": abuse_result.details},
                errors=vt_result.errors + abuse_result.errors,
                mocked=vt_result.mocked and abuse_result.mocked,
            )
            results.append(merged)
        else:
            results.append(vt_result)

    return results
