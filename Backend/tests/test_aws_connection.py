import json
import pathlib

import pytest
import yaml

from app.aws import (
    NO_TOKEN,
    NOT_SET_UP,
    ROLE_DENIED,
    WRONG_ROLE,
    AwsAccess,
    ConnectionFailed,
    parse_role_arn,
)
from app.main import DEMO_CANT_CONNECT, RATE_LIMITS, TEMPLATE_PATH
from app.scanner import CHECKS

from .conftest import bearer, sign_up
from .scanner.conftest import build_insecure_account, simulated_aws

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCANNER = "arn:aws:iam::111122223333:role/MisconfiglyScanner"
CUSTOMER = "444455556666"
CUSTOMER_ROLE = f"arn:aws:iam::{CUSTOMER}:role/MisconfiglyAudit"


class FakeAws(AwsAccess):
    """Checks the role and ExternalId the way the real trust policy would, and hands out a moto session."""

    def __init__(self, session=None, configured=True):
        super().__init__(SCANNER if configured else "")
        self.session = session
        self.trusted = {}  # role ARN -> the ExternalId its stack was created with
        self.calls = []

    def customer_session(self, oidc_token, role_arn, external_id, user_id):
        parse_role_arn(role_arn)
        self.calls.append((oidc_token, role_arn, external_id))
        if not self.configured:
            raise ConnectionFailed(NOT_SET_UP)
        if self.trusted.get(role_arn) != external_id:
            raise ConnectionFailed(ROLE_DENIED)
        return self.session


@pytest.fixture
def fake_aws():
    return FakeAws()


@pytest.fixture
def connecting(build, fake_aws):
    client = build(aws=fake_aws)
    return client, bearer(sign_up(client)["token"]), fake_aws


# The AWS side, against moto


@pytest.mark.parametrize(
    "arn, account",
    [
        (CUSTOMER_ROLE, CUSTOMER),
        (f"  {CUSTOMER_ROLE}  ", CUSTOMER),
        (f"arn:aws:iam::{CUSTOMER}:role/security/MisconfiglyAudit", CUSTOMER),
    ],
)
def test_audit_role_arns_are_accepted(arn, account):
    assert parse_role_arn(arn) == account


@pytest.mark.parametrize(
    "arn",
    [
        f"arn:aws:iam::{CUSTOMER}:role/AdminRole",
        f"arn:aws:iam::{CUSTOMER}:user/MisconfiglyAudit",
        "arn:aws:iam::12345:role/MisconfiglyAudit",
        f"arn:aws:iam::{CUSTOMER}:role/MisconfiglyAuditX",
        "MisconfiglyAudit",
    ],
)
def test_other_arns_are_refused(arn):
    with pytest.raises(ConnectionFailed) as error:
        parse_role_arn(arn)
    assert error.value.message == WRONG_ROLE


def test_nothing_connects_until_the_scanner_role_is_set():
    with pytest.raises(ConnectionFailed) as error:
        AwsAccess("").scanner_session("token")
    assert error.value.message == NOT_SET_UP


def test_on_vercel_a_missing_token_never_falls_back_to_other_credentials():
    with pytest.raises(ConnectionFailed) as error:
        AwsAccess(SCANNER, on_vercel=True).scanner_session(None)
    assert error.value.message == NO_TOKEN


def test_locally_the_aws_cli_profile_stands_in_for_the_scanner_role():
    made = []
    access = AwsAccess(SCANNER, on_vercel=False, sessions=lambda **kw: made.append(kw) or "profile-session")
    assert access.scanner_session(None) == "profile-session"
    assert made == [{"region_name": "us-east-1"}]


def test_the_token_becomes_the_scanner_role_then_the_customer_role():
    with simulated_aws() as session:
        access = AwsAccess(SCANNER, on_vercel=True, sessions=lambda **kw: session)
        customer = access.customer_session("vercel-oidc-token", CUSTOMER_ROLE, "mcfg-external", "user-1")
        assert customer.client("sts").get_caller_identity()["Account"] == CUSTOMER


# The API


def test_the_connect_page_gets_an_external_id_that_stays_the_same(connecting):
    client, headers, _ = connecting
    first = client.get("/api/connection", headers=headers).json()
    assert first["available"] is True and first["connected"] is False
    assert first["external_id"].startswith("mcfg-") and len(first["external_id"]) == 37
    assert first["scanner_role_arn"] == SCANNER
    assert first["template_path"] == TEMPLATE_PATH
    assert client.get("/api/connection", headers=headers).json()["external_id"] == first["external_id"]


def test_each_user_gets_their_own_external_id(connecting):
    client, headers, _ = connecting
    other = bearer(sign_up(client, email="omar@example.com")["token"])
    mine = client.get("/api/connection", headers=headers).json()["external_id"]
    theirs = client.get("/api/connection", headers=other).json()["external_id"]
    assert mine != theirs


def test_connecting_checks_the_role_before_saving_it(connecting):
    client, headers, aws = connecting
    external_id = client.get("/api/connection", headers=headers).json()["external_id"]
    aws.trusted[CUSTOMER_ROLE] = external_id

    response = client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers={**headers, "x-vercel-oidc-token": "tok"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["connected"] is True and body["account_id"] == CUSTOMER and body["role_arn"] == CUSTOMER_ROLE
    assert aws.calls == [("tok", CUSTOMER_ROLE, external_id)]


def test_a_stack_made_with_someone_elses_external_id_is_refused(connecting):
    client, headers, aws = connecting
    aws.trusted[CUSTOMER_ROLE] = "mcfg-somebody-else"
    response = client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=headers)
    assert response.status_code == 400 and response.json()["detail"] == ROLE_DENIED
    assert client.get("/api/connection", headers=headers).json()["connected"] is False


def test_a_role_that_isnt_the_audit_role_is_refused_without_calling_aws(connecting):
    client, headers, aws = connecting
    response = client.post("/api/connection", json={"role_arn": f"arn:aws:iam::{CUSTOMER}:role/OrganizationAccountAccessRole"}, headers=headers)
    assert response.status_code == 400 and response.json()["detail"] == WRONG_ROLE
    assert aws.calls == []


def test_disconnecting_forgets_the_role_and_changes_the_external_id(connecting):
    client, headers, aws = connecting
    old = client.get("/api/connection", headers=headers).json()["external_id"]
    aws.trusted[CUSTOMER_ROLE] = old
    client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=headers)

    body = client.delete("/api/connection", headers=headers).json()
    assert body["connected"] is False and body["role_arn"] is None and body["external_id"] != old
    # The old stack can't be reconnected, because its ExternalId is no longer this user's.
    response = client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=headers)
    assert response.status_code == 400


def test_demo_accounts_cant_connect_a_real_account(connecting):
    client, _, _ = connecting
    demo = bearer(client.post("/api/auth/demo").json()["token"])
    for response in (
        client.get("/api/connection", headers=demo),
        client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=demo),
    ):
        assert response.status_code == 403 and response.json()["detail"] == DEMO_CANT_CONNECT


def test_connecting_is_rate_limited(connecting, monkeypatch):
    client, headers, _ = connecting
    monkeypatch.setitem(RATE_LIMITS, "connect", (2, RATE_LIMITS["connect"][1], "Slow down"))
    for _ in range(2):
        client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=headers)
    assert client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=headers).status_code == 429


def test_a_connected_account_is_scanned_in_every_enabled_region(build):
    with simulated_aws() as session:
        build_insecure_account(session)
        aws = FakeAws(session)
        client = build(aws=aws)
        headers = bearer(sign_up(client)["token"])
        aws.trusted[CUSTOMER_ROLE] = client.get("/api/connection", headers=headers).json()["external_id"]
        client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=headers)

        response = client.post("/api/scans", headers={**headers, "x-vercel-oidc-token": "scan-token"})
        assert response.status_code == 201, response.text
        scan = response.json()
        assert scan["source"] == "aws" and scan["status"] == "done"
        assert len(scan["regions"]) > 10 and "eu-west-2" in scan["regions"]
        assert scan["summary"]["checks"]["error"] == 0
        assert aws.calls[-1][0] == "scan-token"


def test_a_role_deleted_after_connecting_fails_the_scan_with_a_clear_message(connecting):
    client, headers, aws = connecting
    aws.trusted[CUSTOMER_ROLE] = client.get("/api/connection", headers=headers).json()["external_id"]
    client.post("/api/connection", json={"role_arn": CUSTOMER_ROLE}, headers=headers)
    aws.trusted.clear()  # The customer deleted the stack.

    response = client.post("/api/scans", headers=headers)
    assert response.status_code == 502 and response.json()["detail"] == ROLE_DENIED
    [scan] = client.get("/api/scans", headers=headers).json()["scans"]
    assert scan["status"] == "failed" and scan["error"] == ROLE_DENIED


def test_without_a_scanner_role_the_connect_page_says_so(build):
    client = build(aws=FakeAws(configured=False))
    headers = bearer(sign_up(client)["token"])
    body = client.get("/api/connection", headers=headers).json()
    assert body["available"] is False and body["scanner_role_arn"] is None
    assert client.post("/api/scans", headers=headers).status_code == 409


# The CloudFormation templates


def load_template(path):
    return yaml.safe_load((ROOT / path).read_text())


def test_the_customer_role_is_read_only_and_locked_to_misconfigly_and_the_external_id():
    template = load_template("Frontend/public/aws/misconfigly-audit-role.yaml")
    role = template["Resources"]["AuditRole"]["Properties"]
    assert role["RoleName"] == "MisconfiglyAudit"
    assert role["ManagedPolicyArns"] == [{"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/SecurityAudit"}]
    assert "Policies" not in role
    [statement] = role["AssumeRolePolicyDocument"]["Statement"]
    assert statement["Principal"] == {"AWS": {"Ref": "MisconfiglyRoleArn"}}
    assert statement["Condition"] == {"StringEquals": {"sts:ExternalId": {"Ref": "ExternalId"}}}
    assert template["Outputs"]["RoleArn"]["Value"] == {"Fn::GetAtt": ["AuditRole", "Arn"]}
    assert TEMPLATE_PATH == "/aws/misconfigly-audit-role.yaml"


def test_the_scanner_role_trusts_only_production_on_vercel_and_can_only_assume_audit_roles():
    template = load_template("infra/misconfigly-service.yaml")
    role = template["Resources"]["ScannerRole"]["Properties"]
    trust = json.loads(role["AssumeRolePolicyDocument"]["Fn::Sub"])
    [statement] = trust["Statement"]
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    conditions = statement["Condition"]["StringEquals"]
    assert conditions["oidc.vercel.com/${VercelTeamSlug}:sub"].endswith(":environment:production")
    [policy] = role["Policies"]
    [allow] = policy["PolicyDocument"]["Statement"]
    assert allow == {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::*:role/MisconfiglyAudit"}


def test_every_check_still_has_a_permission_in_security_audit():
    """SecurityAudit is AWS's own policy. This guards against a new check needing more than it grants."""
    assert len(CHECKS) == 37
