from datetime import datetime, timedelta, timezone

import pytest

from app.scanner import CHECKS, SEVERITIES, run_scan

from .conftest import REGION, build_insecure_account, build_secure_account, simulated_aws

LATER = datetime.now(timezone.utc) + timedelta(days=120)


def by_check(result):
    grouped = {}
    for finding in result.findings:
        grouped.setdefault(finding.check_id, []).append(finding)
    return grouped


# Each account is built and scanned once, then every test reads the same findings.
@pytest.fixture(scope="module")
def secure_scan():
    with simulated_aws() as session:
        build_secure_account(session)
        return by_check(run_scan(session, regions=[REGION]))


@pytest.fixture(scope="module")
def insecure_scan():
    with simulated_aws() as session:
        build_insecure_account(session)
        # Months later, so the keys are old and the password has gone unused.
        return by_check(run_scan(session, regions=[REGION], now=LATER))


def test_about_thirty_cis_checks_each_with_a_known_severity():
    assert len(CHECKS) >= 30
    for item in CHECKS.values():
        assert item.severity in SEVERITIES
        assert item.cis and item.title and item.service


@pytest.mark.parametrize("check_id", sorted(CHECKS))
def test_a_secure_account_passes(secure_scan, check_id):
    findings = secure_scan[check_id]
    assert findings
    assert [f for f in findings if f.status != "pass"] == []


@pytest.mark.parametrize("check_id", sorted(CHECKS))
def test_a_misconfigured_account_fails(insecure_scan, check_id):
    statuses = {f.status for f in insecure_scan[check_id]}
    assert "fail" in statuses, insecure_scan[check_id]
    assert "error" not in statuses


def test_findings_name_the_resource_and_the_problem(insecure_scan):
    [bucket] = [f for f in insecure_scan["s3.public_buckets"] if f.status == "fail"]
    assert bucket.resource == "acme-public-site"
    assert "bucket policy allows s3:GetObject to anyone" in bucket.detail
    assert "ACL gives everyone READ" in bucket.detail

    [group] = [f for f in insecure_scan["ec2.sg_admin_ports_ipv4"] if f.status == "fail"]
    assert "open-door" in group.resource and "SSH (22)" in group.detail

    [unused] = insecure_scan["iam.unused_credentials"]
    assert unused.resource == "bob" and "console password" in unused.detail

    assert {f.region for f in insecure_scan["ec2.imdsv2"]} == {REGION}
    assert {f.region for f in insecure_scan["iam.root_mfa"]} == {None}
