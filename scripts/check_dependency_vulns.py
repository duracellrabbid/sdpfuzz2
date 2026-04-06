"""Fail on high/critical dependency vulnerabilities.

The script uses pip-audit JSON output and blocks when:
- CVSS score >= 7.0, or
- severity label is HIGH/CRITICAL, or
- vulnerability has no severity metadata (conservative fail-closed behavior).
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

HIGH_CVSS_THRESHOLD = 7.0


@dataclass(frozen=True)
class Finding:
    package: str
    vuln_id: str
    severity: str


def _run_pip_audit() -> Any:
    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "--local",
        "--format",
        "json",
        "--progress-spinner",
        "off",
        "--vulnerability-service",
        "osv",
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)

    # pip-audit uses non-zero exit code when vulnerabilities are found.
    if result.returncode not in (0, 1):
        message = result.stderr.strip() or result.stdout.strip() or "pip-audit failed"
        raise RuntimeError(message)

    stdout = result.stdout.strip()
    if not stdout:
        return {"dependencies": []}

    return json.loads(stdout)


def _extract_dependencies(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("dependencies"), list):
        return [d for d in payload["dependencies"] if isinstance(d, dict)]
    if isinstance(payload, list):
        return [d for d in payload if isinstance(d, dict)]
    return []


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _to_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _cvss_from_severity_list(severity_list: Any) -> float | None:
    if not isinstance(severity_list, list):
        return None

    for item in severity_list:
        if not isinstance(item, dict):
            continue
        score = _to_float(item.get("score"))
        if score is not None:
            return score
    return None


def _extract_cvss(vuln: dict[str, Any]) -> float | None:
    severity_score = _cvss_from_severity_list(vuln.get("severity"))
    if severity_score is not None:
        return severity_score

    for key in ("cvss", "cvss_score", "score"):
        score = _to_float(vuln.get(key))
        if score is not None:
            return score
    return None


def _extract_label(vuln: dict[str, Any]) -> str | None:
    for key in ("severity", "severity_label", "cvss_severity"):
        value = vuln.get(key)
        if isinstance(value, str):
            return value.upper()
    return None


def _finding_for_vuln(package: str, vuln: dict[str, Any]) -> Finding | None:
    vuln_id = str(vuln.get("id", "unknown-id"))
    label = _extract_label(vuln)
    cvss = _extract_cvss(vuln)

    if label in {"CRITICAL", "HIGH"}:
        return Finding(package=package, vuln_id=vuln_id, severity=label)

    if cvss is not None:
        if cvss >= HIGH_CVSS_THRESHOLD:
            return Finding(
                package=package,
                vuln_id=vuln_id,
                severity=f"{_severity_from_score(cvss)} (CVSS {cvss:.1f})",
            )
        return None

    # Fail closed when severity metadata is unavailable.
    return Finding(package=package, vuln_id=vuln_id, severity="UNKNOWN")


def _collect_blocking_findings(payload: Any) -> list[Finding]:
    findings: list[Finding] = []

    for dep in _extract_dependencies(payload):
        package = str(dep.get("name", "unknown-package"))
        vulns = dep.get("vulns", [])
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue

            finding = _finding_for_vuln(package, vuln)
            if finding is not None:
                findings.append(finding)

    return findings


def main() -> int:
    try:
        payload = _run_pip_audit()
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        print(f"Dependency scan failed to execute: {exc}", file=sys.stderr)
        return 2

    findings = _collect_blocking_findings(payload)
    if not findings:
        print("Dependency scan passed: no high/critical findings.")
        return 0

    print("Dependency scan blocked commit/push due to high/critical findings:")
    for finding in findings:
        print(f"- {finding.package}: {finding.vuln_id} [{finding.severity}]")

    print("Fix or explicitly document/ignore vulnerabilities before committing.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
