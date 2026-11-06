"""Running scans for users and shaping stored findings for the API."""

from dataclasses import dataclass
from typing import Callable

from .scanner import CHECKS, SEVERITIES
from .scanner.fixes import FIXES, finding_values, render
from .scanner.scoring import check_status

STATUS_ORDER = {"fail": 0, "error": 1, "pass": 2}
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class ScanTarget:
    """What a scan runs against.

    connect() returns a boto3 session once the scan has started, and disconnect() runs after it, even if it failed.
    regions=None means every region enabled in the account.
    """

    source: str
    connect: Callable[[], object]
    regions: list[str] | None = None
    disconnect: Callable[[], None] | None = None


def no_target(user):
    """Used when nothing is connected for this user."""
    return None


def cis_key(cis):
    return tuple(int(part) for part in cis.split("."))


def scan_view(scan):
    return {
        "id": str(scan["id"]),
        "source": scan["source"],
        "status": scan["status"],
        "account_id": scan["account_id"],
        "regions": scan["regions"],
        "summary": scan["summary"],
        "error": scan["error"],
        "started_at": scan["started_at"],
        "finished_at": scan["finished_at"],
    }


def catalog():
    return [
        {
            "id": c.id,
            "cis": c.cis,
            "title": c.title,
            "service": c.service,
            "severity": c.severity,
            "regional": c.regional,
            "why": FIXES[c.id].why,
        }
        for c in sorted(CHECKS.values(), key=lambda c: cis_key(c.cis))
    ]


def _finding(row, fix, account_id):
    item = {"status": row["status"], "region": row["region"], "resource": row["resource"], "detail": row["detail"]}
    if row["status"] == "fail":
        values = finding_values(row["resource"], row["region"], account_id or "ACCOUNT_ID")
        item["fix"] = {
            "console": [render(step, values) for step in fix.console],
            "cli": render(fix.cli, values),
            "terraform": render(fix.terraform, values),
        }
    return item


def grouped_checks(rows, account_id, severities=None, service=None, status=None):
    """Findings grouped by check, failing checks first and the most severe first among them."""
    by_check = {}
    for row in rows:
        by_check.setdefault(row["check_id"], []).append(row)

    checks = []
    for check_id, items in by_check.items():
        check = CHECKS.get(check_id)
        if check is None:  # A check that has since been removed.
            continue
        # The severity saved with the scan, so old scans read the same after a severity changes.
        severity = items[0]["severity"]
        overall = check_status({r["status"] for r in items})
        if (severities and severity not in severities) or (service and check.service != service) or (status and overall != status):
            continue
        items.sort(key=lambda r: (STATUS_ORDER[r["status"]], r["region"] or "", r["resource"]))
        checks.append(
            {
                "id": check.id,
                "cis": check.cis,
                "title": check.title,
                "service": check.service,
                "severity": severity,
                "status": overall,
                "why": FIXES[check.id].why,
                "counts": {s: sum(1 for r in items if r["status"] == s) for s in STATUS_ORDER},
                "findings": [_finding(r, FIXES[check.id], account_id) for r in items],
            }
        )
    checks.sort(key=lambda c: (STATUS_ORDER[c["status"]], SEVERITY_ORDER[c["severity"]], cis_key(c["cis"])))
    return checks
