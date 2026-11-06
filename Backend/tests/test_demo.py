import uuid

import boto3
import botocore
import pytest
from moto.core.base_backend import BackendDict

from app import demo
from app.main import DEMO_ONLY
from app.scanner import CHECKS, run_scan
from app.scanner.scoring import check_status, summarize

from .conftest import bearer, sign_up


def scan_with(fixed, user_id=None):
    user_id = user_id or uuid.uuid4()
    session = demo.DemoSession(demo.demo_account_id(user_id))
    try:
        demo.build(session, user_id, fixed)
        result = run_scan(session, regions=[demo.REGION])
    finally:
        demo.forget(session.account_id)
    statuses = {}
    for finding in result.findings:
        statuses.setdefault(finding.check_id, set()).add(finding.status)
    return result, {check_id: check_status(s) for check_id, s in statuses.items()}


def start_demo(client):
    response = client.post("/api/auth/demo")
    assert response.status_code == 201
    return bearer(response.json()["token"])


def test_with_nothing_fixed_every_check_finds_its_problem():
    _, statuses = scan_with(set())
    assert statuses == dict.fromkeys(CHECKS, "fail")


def test_with_everything_fixed_every_check_passes():
    result, statuses = scan_with(set(CHECKS))
    assert statuses == dict.fromkeys(CHECKS, "pass")
    assert summarize(result.findings)["score"] == 100


@pytest.mark.parametrize("check_id", sorted(CHECKS))
def test_fixing_one_check_makes_it_pass(check_id):
    _, statuses = scan_with(demo.ALREADY_FINE | demo.with_dependencies({check_id}))
    assert statuses[check_id] == "pass"


def test_a_new_demo_starts_with_real_problems_and_some_things_done_right():
    result, statuses = scan_with(demo.ALREADY_FINE)
    failing = {c for c, s in statuses.items() if s == "fail"}
    assert failing == set(CHECKS) - demo.ALREADY_FINE
    assert {"iam.root_mfa", "s3.public_buckets", "rds.public"} <= failing
    assert 20 <= summarize(result.findings)["score"] <= 60


def test_each_visitor_has_their_own_account_and_names():
    first, second = uuid.uuid4(), uuid.uuid4()
    assert demo.demo_account_id(first) == demo.demo_account_id(first)
    assert demo.demo_account_id(first) != demo.demo_account_id(second)
    assert len(demo.demo_account_id(first)) == 12
    result, _ = scan_with(set(), user_id=first)
    assert result.account_id == demo.demo_account_id(first)
    buckets = {f.resource for f in result.findings if f.check_id == "s3.https_only"}
    assert all(b.endswith(result.account_id[-6:]) for b in buckets)


def test_demo_accounts_are_kept_apart_and_forgotten():
    a = demo.DemoSession("111111111111")
    b = demo.DemoSession("222222222222")
    a.client("s3").create_bucket(Bucket="only-in-a-111111")
    assert b.client("s3").list_buckets()["Buckets"] == []
    demo.forget("111111111111")
    assert all("111111111111" not in backend for backend in BackendDict._instances)
    assert a.client("s3").list_buckets()["Buckets"] == []
    # The same names can be used again by the next scan of this account.
    a.client("s3").create_bucket(Bucket="only-in-a-111111")
    demo.forget("111111111111")


def test_the_same_visitor_can_be_rebuilt_again_and_again():
    user_id = uuid.uuid4()
    for _ in range(3):
        _, statuses = scan_with(demo.ALREADY_FINE, user_id=user_id)
        assert statuses["iam.root_mfa"] == "fail"


def test_demo_clients_dont_catch_other_aws_calls():
    """A real scan running at the same time must go to AWS, not to the simulated account."""
    demo.DemoSession("333333333333").client("sts").get_caller_identity()
    plain = boto3.Session(aws_access_key_id="x", aws_secret_access_key="y", region_name="us-east-1").client(
        "sts",
        endpoint_url="http://127.0.0.1:9",
        config=botocore.config.Config(retries={"max_attempts": 0}, connect_timeout=1),
    )
    with pytest.raises(botocore.exceptions.EndpointConnectionError):
        plain.get_caller_identity()


def test_a_demo_visitor_can_scan_straight_away(client):
    headers = start_demo(client)
    scan = client.post("/api/scans", headers=headers).json()
    assert scan["status"] == "done" and scan["source"] == "demo"
    assert 20 <= scan["summary"]["score"] <= 60


def test_fixing_in_the_demo_raises_the_score_and_reset_undoes_it(client):
    headers = start_demo(client)
    before = client.post("/api/scans", headers=headers).json()["summary"]

    fixed = client.post("/api/demo/fixes", json={"check_ids": ["iam.root_mfa", "monitoring.console_without_mfa"]}, headers=headers)
    assert fixed.status_code == 200
    assert fixed.json()["fixed"] == ["cloudtrail.all_regions", "iam.root_mfa", "monitoring.console_without_mfa"]

    after = client.post("/api/scans", headers=headers).json()
    assert after["summary"]["score"] > before["score"]
    assert after["summary"]["failed_by_severity"]["critical"] == before["failed_by_severity"]["critical"] - 1
    checks = {c["id"]: c["status"] for c in client.get(f"/api/scans/{after['id']}", headers=headers).json()["checks"]}
    assert checks["iam.root_mfa"] == "pass" and checks["monitoring.console_without_mfa"] == "pass"

    assert client.delete("/api/demo/fixes", headers=headers).json() == {"fixed": []}
    assert client.post("/api/scans", headers=headers).json()["summary"]["score"] == before["score"]


def test_unknown_checks_cant_be_fixed(client):
    headers = start_demo(client)
    response = client.post("/api/demo/fixes", json={"check_ids": ["iam.made_up"]}, headers=headers)
    assert response.status_code == 400
    assert client.get("/api/demo/fixes", headers=headers).json() == {"fixed": []}


def test_only_demo_accounts_have_demo_fixes(client):
    headers = bearer(sign_up(client)["token"])
    response = client.post("/api/demo/fixes", json={"check_ids": ["iam.root_mfa"]}, headers=headers)
    assert response.status_code == 403 and response.json()["detail"] == DEMO_ONLY
    assert client.post("/api/scans", headers=headers).status_code == 409
