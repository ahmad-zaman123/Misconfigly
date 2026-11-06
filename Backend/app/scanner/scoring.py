"""The 0 to 100 score and the counts shown for a scan."""

from .core import CHECKS, SEVERITIES

WEIGHTS = {"critical": 10, "high": 5, "medium": 3, "low": 1}


def check_status(statuses):
    """A check fails if any resource fails. Otherwise it is an error if it couldn't look at everything."""
    if "fail" in statuses:
        return "fail"
    if "error" in statuses:
        return "error"
    return "pass"


def summarize(findings):
    """findings: anything with check_id and status. Checks that couldn't run are left out of the score."""
    by_check = {}
    for finding in findings:
        by_check.setdefault(finding.check_id, set()).add(finding.status)

    totals = {"pass": 0, "fail": 0, "error": 0}
    failed = dict.fromkeys(SEVERITIES, 0)
    earned = possible = 0
    for check_id, statuses in by_check.items():
        status = check_status(statuses)
        totals[status] += 1
        severity = CHECKS[check_id].severity
        if status == "fail":
            failed[severity] += 1
        if status != "error":
            possible += WEIGHTS[severity]
            earned += WEIGHTS[severity] if status == "pass" else 0

    return {
        "score": round(100 * earned / possible) if possible else None,
        "checks": totals,
        "failed_by_severity": failed,
        "failing_resources": sum(1 for f in findings if f.status == "fail"),
    }
