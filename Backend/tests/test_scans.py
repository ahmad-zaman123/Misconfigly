from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.main import NO_TARGET, RATE_LIMITS, SCAN_FAILED, SCAN_RUNNING
from app.scanner import CHECKS
from app.scanner.fixes import FIXES, PLACEHOLDER, finding_values, render
from app.scanner.scoring import summarize
from app.scanner.core import Finding
from app.scans import ScanTarget

from .conftest import bearer, sign_up
from .scanner.conftest import REGION, build_insecure_account, build_secure_account, simulated_aws


@pytest.fixture
def insecure_aws():
    with simulated_aws() as session:
        build_insecure_account(session)
        yield session


@pytest.fixture
def scanning(build, insecure_aws):
    """A client whose users all scan the misconfigured account, and one signed-in user."""
    client = build(scan_target=lambda user: ScanTarget("test", lambda: insecure_aws, [REGION]))
    return client, bearer(sign_up(client)["token"])


def run(client, headers):
    response = client.post("/api/scans", headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def test_scanning_needs_a_connected_account(client):
    headers = bearer(sign_up(client)["token"])
    response = client.post("/api/scans", headers=headers)
    assert response.status_code == 409
    assert response.json()["detail"] == NO_TARGET
    assert client.get("/api/scans", headers=headers).json() == {"scans": []}


def test_scans_need_a_signed_in_user(client):
    assert client.post("/api/scans").status_code == 401
    assert client.get("/api/scans").status_code == 401


def test_a_scan_is_saved_with_its_score_and_counts(scanning):
    client, headers = scanning
    scan = run(client, headers)
    assert scan["status"] == "done"
    assert scan["account_id"] == "123456789012"
    assert scan["regions"] == [REGION]
    summary = scan["summary"]
    assert 0 <= summary["score"] < 30
    # Bob's keys are brand new today, so only the two age checks pass.
    assert summary["checks"] == {"pass": 2, "fail": len(CHECKS) - 2, "error": 0}
    assert summary["failed_by_severity"]["critical"] == 5
    assert [s["id"] for s in client.get("/api/scans", headers=headers).json()["scans"]] == [scan["id"]]


def test_results_put_the_worst_problems_first(scanning):
    client, headers = scanning
    scan = run(client, headers)
    body = client.get(f"/api/scans/{scan['id']}", headers=headers).json()
    checks = body["checks"]
    assert len(checks) == len(CHECKS)
    assert [c["severity"] for c in checks[:5]] == ["critical"] * 5
    assert checks[0]["cis"] == "1.4"
    assert "S3" in body["services"] and "IAM" in body["services"]


def test_each_failing_resource_gets_a_fix_written_for_it(scanning):
    client, headers = scanning
    scan = run(client, headers)
    checks = {c["id"]: c for c in client.get(f"/api/scans/{scan['id']}", headers=headers).json()["checks"]}

    [bucket] = [f for f in checks["s3.public_buckets"]["findings"] if f["status"] == "fail"]
    assert "aws s3api put-bucket-acl --bucket acme-public-site --acl private" in bucket["fix"]["cli"]
    assert 'bucket                  = "acme-public-site"' in bucket["fix"]["terraform"]
    assert bucket["fix"]["console"][0] == "Open S3 > Buckets > acme-public-site > Permissions."

    [group] = [f for f in checks["ec2.sg_admin_ports_ipv4"]["findings"] if f["status"] == "fail"]
    group_id = group["resource"].split(" ")[0]
    assert f"--group-id {group_id} --protocol tcp --port 22 --cidr 0.0.0.0/0 --region {REGION}" in group["fix"]["cli"]

    [keys] = checks["iam.one_active_key"]["findings"]
    assert "aws iam list-access-keys --user-name bob" in keys["fix"]["cli"]

    https = [f for f in checks["s3.https_only"]["findings"] if f["resource"] == "acme-public-site"][0]
    assert '"Condition": {"Bool": {"aws:SecureTransport": "false"}}' in https["fix"]["cli"]

    assert checks["iam.root_mfa"]["findings"][0]["fix"]["cli"] is None

    for check in checks.values():
        for finding in check["findings"]:
            if finding["status"] != "fail":
                assert "fix" not in finding
                continue
            text = "\n".join([*finding["fix"]["console"], finding["fix"]["cli"] or "", finding["fix"]["terraform"] or ""])
            assert not PLACEHOLDER.search(text), (check["id"], text)


def test_results_can_be_filtered(scanning):
    client, headers = scanning
    scan = run(client, headers)
    url = f"/api/scans/{scan['id']}"

    critical = client.get(url, params={"severity": "critical"}, headers=headers).json()["checks"]
    assert {c["severity"] for c in critical} == {"critical"} and len(critical) == 5

    two = client.get(url, params=[("severity", "critical"), ("severity", "low")], headers=headers).json()["checks"]
    assert {c["severity"] for c in two} == {"critical", "low"}

    s3 = client.get(url, params={"service": "S3"}, headers=headers).json()["checks"]
    assert {c["service"] for c in s3} == {"S3"} and len(s3) == 4

    passing = client.get(url, params={"status": "pass"}, headers=headers).json()["checks"]
    assert {c["id"] for c in passing} == {"iam.unused_credentials", "iam.key_rotation"}
    assert client.get(url, params={"severity": "urgent"}, headers=headers).status_code == 422


def test_nobody_else_can_see_a_scan(scanning):
    client, headers = scanning
    scan = run(client, headers)
    other = bearer(sign_up(client, email="omar@example.com")["token"])
    assert client.get(f"/api/scans/{scan['id']}", headers=other).status_code == 404
    assert client.get("/api/scans", headers=other).json() == {"scans": []}
    assert client.get("/api/scans/not-a-uuid", headers=headers).status_code == 404


def test_only_one_scan_runs_at_a_time(scanning, store):
    client, headers = scanning
    user_id = client.get("/api/me", headers=headers).json()["id"]
    store.start_scan(user_id, "test")
    response = client.post("/api/scans", headers=headers)
    assert response.status_code == 409
    assert response.json()["detail"] == SCAN_RUNNING


def test_a_scan_stuck_running_stops_blocking_after_a_while(scanning, store, database_url):
    client, headers = scanning
    user_id = client.get("/api/me", headers=headers).json()["id"]
    stuck = store.start_scan(user_id, "test")
    with psycopg.connect(database_url, autocommit=True) as db:
        db.execute("UPDATE scans SET started_at = %s WHERE id = %s", (datetime.now(timezone.utc) - timedelta(hours=1), stuck["id"]))
    run(client, headers)
    statuses = {s["id"]: s["status"] for s in client.get("/api/scans", headers=headers).json()["scans"]}
    assert statuses[str(stuck["id"])] == "failed"


class BrokenSession:
    region_name = REGION

    def client(self, *args, **kwargs):
        raise RuntimeError("no network")


def test_a_scan_that_breaks_is_saved_as_failed_and_can_be_retried(build):
    client = build(scan_target=lambda user: ScanTarget("test", BrokenSession, [REGION]))
    headers = bearer(sign_up(client)["token"])
    response = client.post("/api/scans", headers=headers)
    assert response.status_code == 502
    assert response.json()["detail"] == SCAN_FAILED
    [scan] = client.get("/api/scans", headers=headers).json()["scans"]
    assert scan["status"] == "failed" and scan["error"] == SCAN_FAILED
    assert client.post("/api/scans", headers=headers).status_code == 502


def test_scans_are_rate_limited(build, monkeypatch):
    monkeypatch.setitem(RATE_LIMITS, "scan", (1, timedelta(hours=1), "Slow down"))
    client = build(scan_target=lambda user: ScanTarget("test", BrokenSession, [REGION]))
    headers = bearer(sign_up(client)["token"])
    client.post("/api/scans", headers=headers)
    response = client.post("/api/scans", headers=headers)
    assert response.status_code == 429 and response.json()["detail"] == "Slow down"


def test_deleting_a_user_deletes_their_scans(scanning, database_url):
    client, headers = scanning
    run(client, headers)
    with psycopg.connect(database_url, autocommit=True) as db:
        db.execute("DELETE FROM users")
        assert db.execute("SELECT count(*) FROM findings").fetchone()[0] == 0


def test_a_key_finding_fills_in_both_the_user_and_the_key():
    values = finding_values("bob / AKIAEXAMPLE", None, "123456789012")
    text = render(FIXES["iam.key_rotation"].cli, values)
    assert "--user-name bob --access-key-id AKIAEXAMPLE --status Inactive" in text
    assert values["region"] == "us-east-1"


def test_the_catalog_lists_every_check_in_cis_order(client):
    checks = client.get("/api/checks").json()["checks"]
    assert len(checks) == len(CHECKS)
    assert checks[0]["cis"] == "1.4" and checks[-1]["cis"] == "5.6"
    assert all(c["why"] for c in checks)


def test_a_secure_account_scores_100():
    with simulated_aws() as session:
        build_secure_account(session)
        from app.scanner import run_scan

        assert summarize(run_scan(session, regions=[REGION]).findings)["score"] == 100


def test_the_score_weights_checks_by_severity_and_ignores_checks_that_couldnt_run():
    findings = [
        Finding("iam.root_mfa", "fail", None, "root", "x"),  # critical, 10
        Finding("iam.support_role", "pass", None, "role", ""),  # low, 1
        Finding("ec2.imdsv2", "pass", REGION, "i-1", ""),  # high, 5
        Finding("ec2.imdsv2", "fail", REGION, "i-2", "x"),
        Finding("rds.public", "error", REGION, "acct", "x"),  # left out
    ]
    summary = summarize(findings)
    assert summary["score"] == round(100 * 1 / 16)
    assert summary["checks"] == {"pass": 1, "fail": 2, "error": 1}
    assert summary["failed_by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert summary["failing_resources"] == 2
