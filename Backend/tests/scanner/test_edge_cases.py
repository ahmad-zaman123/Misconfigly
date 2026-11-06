import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from app.scanner import CHECKS, run_scan
from app.scanner.checks.monitoring import IAM_POLICY_EVENTS, _matches
from app.scanner.core import Check

from .conftest import ACCOUNT, REGION, build_insecure_account, build_secure_account, default_vpc

BLOCK_ALL = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}


def scan(session, *ids, regions=(REGION,), now=None):
    return [f for f in run_scan(session, regions=list(regions), now=now, only=set(ids)).findings]


def denied(ctx):
    raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetAccountSummary")
    yield


def test_a_missing_permission_is_reported_and_the_other_checks_still_run(aws, monkeypatch):
    monkeypatch.setitem(CHECKS, "test.denied", Check("test.denied", "0.0", "Test", "IAM", "low", False, denied))
    findings = scan(aws, "test.denied", "iam.root_mfa")
    by_id = {f.check_id: f for f in findings}
    assert by_id["test.denied"].status == "error"
    assert "isn't allowed to call GetAccountSummary" in by_id["test.denied"].detail
    assert by_id["iam.root_mfa"].status == "fail"


def test_an_empty_account_passes_checks_with_nothing_to_look_at(aws):
    [finding] = scan(aws, "rds.public")
    assert finding.status == "pass" and finding.resource == ACCOUNT and finding.detail == "Nothing of this kind to check"


def test_block_public_access_cancels_a_public_policy_and_acl(aws):
    build_insecure_account(aws)
    aws.client("s3control").put_public_access_block(AccountId=ACCOUNT, PublicAccessBlockConfiguration=BLOCK_ALL)
    public = [f for f in scan(aws, "s3.public_buckets") if f.resource == "acme-public-site"]
    assert [f.status for f in public] == ["pass"]
    bucket_level = scan(aws, "s3.bucket_public_access_block")
    assert {f.status for f in bucket_level} == {"pass"}
    assert all(f.detail == "Covered by the account setting" for f in bucket_level)


def test_only_public_acls_still_count_when_policies_alone_are_blocked(aws):
    build_insecure_account(aws)
    aws.client("s3").put_public_access_block(
        Bucket="acme-public-site",
        PublicAccessBlockConfiguration={**BLOCK_ALL, "BlockPublicAcls": False, "IgnorePublicAcls": False},
    )
    [finding] = [f for f in scan(aws, "s3.public_buckets") if f.resource == "acme-public-site"]
    assert finding.status == "fail"
    assert "ACL gives everyone READ" in finding.detail and "bucket policy" not in finding.detail


def test_a_conditional_public_policy_isnt_public(aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="partner-drop")
    s3.put_bucket_policy(
        Bucket="partner-drop",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "*"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::partner-drop/*",
                        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-acme"}},
                    }
                ],
            }
        ),
    )
    assert [f.status for f in scan(aws, "s3.public_buckets")] == ["pass"]


def nacl_of_default_vpc(ec2):
    vpc = default_vpc(ec2)
    return ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkAcls"][0]["NetworkAclId"]


def test_a_lower_numbered_deny_hides_a_later_allow_in_a_nacl(aws):
    ec2 = aws.client("ec2")
    acl = nacl_of_default_vpc(ec2)
    for number, port in ((80, 22), (90, 3389)):
        ec2.create_network_acl_entry(
            NetworkAclId=acl, RuleNumber=number, Protocol="6", RuleAction="deny", Egress=False,
            CidrBlock="0.0.0.0/0", PortRange={"From": port, "To": port},
        )  # fmt: skip
    assert {f.status for f in scan(aws, "ec2.nacl_admin_ports")} == {"pass"}


def test_a_port_range_that_spans_ssh_but_not_rdp(aws):
    ec2 = aws.client("ec2")
    acl = nacl_of_default_vpc(ec2)
    ec2.replace_network_acl_entry(
        NetworkAclId=acl, RuleNumber=100, Protocol="6", RuleAction="allow", Egress=False,
        CidrBlock="0.0.0.0/0", PortRange={"From": 0, "To": 1024},
    )  # fmt: skip
    [finding] = [f for f in scan(aws, "ec2.nacl_admin_ports") if f.resource == acl]
    assert finding.status == "fail"
    assert "SSH (22)" in finding.detail and "RDP" not in finding.detail


def test_a_security_group_open_on_every_protocol_counts_as_both_ports(aws):
    ec2 = aws.client("ec2")
    group = ec2.create_security_group(GroupName="wide-open", Description="All traffic", VpcId=default_vpc(ec2))["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    [finding] = [f for f in scan(aws, "ec2.sg_admin_ports_ipv4") if "wide-open" in f.resource]
    assert finding.detail == "Opens SSH (22) and RDP (3389) to 0.0.0.0/0"


def test_filter_patterns_match_whatever_the_spacing_and_quotes():
    assert _matches('{($.eventName="ConsoleLogin")&&($.additionalEventData.MFAUsed != "Yes")}',
                    ['$.eventName="ConsoleLogin"', '$.additionalEventData.MFAUsed!="Yes"'])  # fmt: skip
    assert _matches("{ $.eventName = ConsoleLogin && $.additionalEventData.MFAUsed != Yes }",
                    ['$.eventName="ConsoleLogin"', '$.additionalEventData.MFAUsed!="Yes"'])  # fmt: skip


def test_an_event_name_doesnt_match_a_longer_one_that_starts_with_it():
    without_create_policy = " || ".join(f"($.eventName={e})" for e in IAM_POLICY_EVENTS if e != "CreatePolicy")
    assert "CreatePolicyVersion" in without_create_policy
    assert not _matches(without_create_policy, [f"$.eventName={e}" for e in IAM_POLICY_EVENTS])


def test_an_alarm_nobody_hears_doesnt_count(aws):
    build_secure_account(aws)
    sns = aws.client("sns")
    for sub in sns.list_subscriptions()["Subscriptions"]:
        sns.unsubscribe(SubscriptionArn=sub["SubscriptionArn"])
    [finding] = scan(aws, "monitoring.root_usage")
    assert finding.status == "fail"
    assert "has no alarm that notifies anyone" in finding.detail


def test_a_trail_that_stops_logging_fails_and_alarms_lose_their_source(aws):
    build_secure_account(aws)
    aws.client("cloudtrail").stop_logging(Name="org-trail")
    by_id = {f.check_id: f for f in scan(aws, "cloudtrail.all_regions", "monitoring.trail_changes")}
    assert by_id["cloudtrail.all_regions"].status == "fail"
    assert "is switched off" in by_id["cloudtrail.all_regions"].detail
    assert by_id["monitoring.trail_changes"].status == "fail"


def test_regional_checks_run_in_each_region_and_global_ones_once(aws):
    findings = scan(aws, "ec2.ebs_default_encryption", "iam.root_mfa", regions=("us-east-1", "eu-west-2"))
    ebs = sorted(f.region for f in findings if f.check_id == "ec2.ebs_default_encryption")
    assert ebs == ["eu-west-2", "us-east-1"]
    assert [f.region for f in findings if f.check_id == "iam.root_mfa"] == [None]


def test_inactive_keys_and_password_less_users_are_left_alone(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="ci-bot")
    key = iam.create_access_key(UserName="ci-bot")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="ci-bot", AccessKeyId=key, Status="Inactive")
    later = datetime.now(timezone.utc) + timedelta(days=200)
    findings = scan(aws, "iam.user_mfa", "iam.key_rotation", "iam.unused_credentials", "iam.one_active_key", now=later)
    assert {f.status for f in findings} == {"pass"}
    assert all(f.resource == ACCOUNT for f in findings)


def test_a_month_old_key_is_within_both_limits(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="deployer")
    iam.create_access_key(UserName="deployer")
    findings = scan(aws, "iam.unused_credentials", "iam.key_rotation", now=datetime.now(timezone.utc) + timedelta(days=30))
    assert {f.status for f in findings} == {"pass"}


def test_a_multi_region_trail_is_counted_once_however_many_regions_are_scanned(aws):
    build_secure_account(aws)
    findings = scan(aws, "cloudtrail.log_validation", regions=("us-east-1", "eu-west-2", "ap-south-1"))
    assert [(f.resource, f.status) for f in findings] == [("org-trail", "pass")]
