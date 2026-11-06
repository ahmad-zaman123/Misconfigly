"""The simulated AWS account each demo visitor scans, built in moto.

Requests from a demo session never leave the process. A private moto handler is attached to that session's clients
only, so real AWS calls made at the same time by other users are never intercepted. Each visitor gets their own
account ID, and the account is rebuilt for every scan from a recipe: a well-run account, with one deliberate problem
per check unless the visitor has fixed it.
"""

import json
import random
import threading
from datetime import datetime, timedelta, timezone

import boto3
from moto.core.base_backend import BackendDict, backend_lock
from moto.core.botocore_stubber import BotocoreStubber
from moto.core.config import default_user_config
from moto.iam.models import AccessKeyLastUsed, iam_backends
from moto.s3.models import s3_backends

from .scanner import CHECKS
from .scans import ScanTarget

REGION = "us-east-1"
# The AWS managed policies, such as AWSSupportAccess, exist in every real account.
default_user_config["iam"]["load_aws_managed_policies"] = True
_stubber = BotocoreStubber()
_stubber.enabled = True

COMPANIES = ("northwind", "kestrel", "fieldstone", "tidewater", "harbourline", "copperleaf", "brightwell", "ashgrove")
BLOCK_ALL = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
ALARMS = {
    "monitoring.unauthorized_calls": ("unauthorized-api-calls", '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'),
    "monitoring.console_without_mfa": ("console-without-mfa", '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'),
    "monitoring.root_usage": ("root-usage", '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'),
    "monitoring.iam_policy_changes": ("iam-policy-changes", None),
    "monitoring.trail_changes": ("trail-changes", None),
}  # fmt: skip
# What a typical, half-looked-after account already gets right. The rest is left for the visitor to find and fix.
ALREADY_FINE = frozenset({
    "iam.root_access_keys", "iam.password_reuse", "iam.admin_policies", "iam.user_policies", "iam.expired_certificates",
    "rds.encryption", "rds.minor_upgrades", "ec2.ebs_default_encryption", "ec2.sg_admin_ports_ipv6",
    "cloudtrail.all_regions", "cloudtrail.log_validation", "cloudtrail.kms", "kms.rotation", "vpc.flow_logs",
    "monitoring.root_usage", "monitoring.trail_changes",
})  # fmt: skip
# Fixing one of these in the demo also fixes what it relies on, as it would have to in a real account.
DEPENDS_ON = {check_id: ("cloudtrail.all_regions",) for check_id in ALARMS}
TRUST_ACCOUNT = '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":"sts:AssumeRole"}}]}}'
TRUST_SERVICE = '{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"Service":"{service}"}},"Action":"sts:AssumeRole"}}]}}'


def _event_pattern(names):
    return "{ " + " || ".join(f"($.eventName = {n})" for n in names) + " }"


def demo_account_id(user_id):
    """A stable 12-digit account ID for a visitor, never moto's default 123456789012."""
    number = int(str(user_id).replace("-", ""), 16) % 899_999_999_999 + 100_000_000_000
    return str(number if number != 123456789012 else number + 1)


class DemoSession:
    """Looks like a boto3 Session to the scanner, but every client it makes talks to this account in moto."""

    def __init__(self, account_id):
        self.account_id = account_id
        self.region_name = REGION
        self._session = boto3.Session(aws_access_key_id="demo", aws_secret_access_key="demo", region_name=REGION)
        self._lock = threading.Lock()

    def _tag_account(self, request, **_):
        request.headers["x-moto-account-id"] = self.account_id

    def client(self, service, region_name=REGION, **kwargs):
        with self._lock:
            client = self._session.client(service, region_name=region_name, **kwargs)
        client.meta.events.register("before-sign", self._tag_account)
        client.meta.events.register_first("before-send", _stubber)
        return client


def forget(account_id):
    """Drops everything moto holds for this account, so memory doesn't grow with each demo scan."""
    with backend_lock:
        for backend in list(BackendDict._instances):
            backend.pop(account_id, None)
        # S3 bucket names are global, so moto also keeps one index of them across accounts.
        for name, (_, owner) in list(s3_backends.bucket_accounts.items()):
            if owner == account_id:
                s3_backends.bucket_accounts.pop(name, None)


def with_dependencies(check_ids):
    result = set(check_ids)
    for check_id in check_ids:
        result.update(DEPENDS_ON.get(check_id, ()))
    return result


def build(session, user_id, fixed=frozenset()):
    """Builds the visitor's account. Every check not in `fixed` gets one problem it will find."""
    ok = set(fixed).__contains__
    account = session.account_id
    company = random.Random(str(user_id)).choice(COMPANIES)
    suffix = account[-6:]

    def bucket_name(purpose):
        return f"{company}-{purpose}-{suffix}"

    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    logs = session.client("logs")
    backend = iam_backends[account]["global"]
    # moto keeps naive UTC times, so match it.
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # Root account
    backend.account_summary._account_mfa_enabled = 1 if ok("iam.root_mfa") else 0
    backend.account_summary._account_access_keys_present = 0 if ok("iam.root_access_keys") else 1

    # Password policy. Both settings live in one policy, and with neither fixed there is no policy at all.
    if ok("iam.password_length") or ok("iam.password_reuse"):
        iam.update_account_password_policy(
            MinimumPasswordLength=16 if ok("iam.password_length") else 8,
            PasswordReusePrevention=24 if ok("iam.password_reuse") else 0,
            RequireSymbols=True,
            RequireNumbers=True,
        )

    # People and their permissions
    read_policy = iam.create_policy(
        PolicyName="ReadAppData",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket_name('app-data')}", f"arn:aws:s3:::{bucket_name('app-data')}/*"]}]}
        ),
    )["Policy"]  # fmt: skip
    iam.create_group(GroupName="engineers")
    iam.attach_group_policy(GroupName="engineers", PolicyArn=read_policy["Arn"])
    iam.attach_group_policy(GroupName="engineers", PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")

    contractor_statement = (
        {"Effect": "Allow", "Action": ["ec2:Describe*", "cloudwatch:Get*"], "Resource": "*"}
        if ok("iam.admin_policies")
        else {"Effect": "Allow", "Action": "*", "Resource": "*"}
    )
    contractor_policy = iam.create_policy(
        PolicyName="ContractorAccess", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [contractor_statement]})
    )["Policy"]
    iam.create_group(GroupName="contractors")
    iam.attach_group_policy(GroupName="contractors", PolicyArn=contractor_policy["Arn"])

    def console_user(name, group, mfa=True):
        iam.create_user(UserName=name)
        iam.add_user_to_group(GroupName=group, UserName=name)
        iam.create_login_profile(UserName=name, Password=f"Demo-{name}-password-2026!")
        if mfa:
            device = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)["VirtualMFADevice"]
            iam.enable_mfa_device(UserName=name, SerialNumber=device["SerialNumber"], AuthenticationCode1="123456", AuthenticationCode2="654321")  # fmt: skip

    console_user("amira.haddad", "engineers")
    console_user("leo.martin", "contractors", mfa=ok("iam.user_mfa"))
    if not ok("iam.user_policies"):
        iam.attach_user_policy(UserName="leo.martin", PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")

    if not ok("iam.unused_credentials"):
        # Someone who left: the account was never closed and hasn't been used for months.
        console_user("old-reporting", "engineers")
        backend.users["old-reporting"].create_date = now - timedelta(days=210)

    iam.create_user(UserName="deploy-bot")
    iam.add_user_to_group(GroupName="engineers", UserName="deploy-bot")
    key = iam.create_access_key(UserName="deploy-bot")["AccessKey"]["AccessKeyId"]
    stored = next(k for k in backend.users["deploy-bot"].access_keys if k.access_key_id == key)
    # In daily use, so it is never "unused". Whether it is old depends on rotation.
    stored.last_used = AccessKeyLastUsed(timestamp=now - timedelta(hours=3), service="s3", region=REGION)
    if not ok("iam.key_rotation"):
        stored.create_date = now - timedelta(days=187)
    if not ok("iam.one_active_key"):
        spare = iam.create_access_key(UserName="deploy-bot")["AccessKey"]["AccessKeyId"]
        spare_key = next(k for k in backend.users["deploy-bot"].access_keys if k.access_key_id == spare)
        spare_key.last_used = AccessKeyLastUsed(timestamp=now - timedelta(days=2), service="ec2", region=REGION)

    if ok("iam.support_role"):
        iam.create_role(RoleName="aws-support", AssumeRolePolicyDocument=TRUST_ACCOUNT.format(account=account))
        iam.attach_role_policy(RoleName="aws-support", PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess")
    if not ok("iam.expired_certificates"):
        iam.upload_server_certificate(
            ServerCertificateName=f"{company}-shop-2023", CertificateBody="-----BEGIN CERTIFICATE-----\ndemo\n-----END CERTIFICATE-----",
            PrivateKey="-----BEGIN PRIVATE KEY-----\ndemo\n-----END PRIVATE KEY-----",
        )  # fmt: skip
    service_role = iam.create_role(
        RoleName="service-delivery", AssumeRolePolicyDocument=TRUST_SERVICE.format(service="cloudtrail.amazonaws.com")
    )["Role"]["Arn"]

    # S3
    if ok("s3.account_public_access_block"):
        session.client("s3control").put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=BLOCK_ALL)

    def https_statement(name):
        return {
            "Sid": "DenyPlainHttp", "Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }  # fmt: skip

    def make_bucket(purpose, public=False, blocked=True, https=True):
        name = bucket_name(purpose)
        s3.create_bucket(Bucket=name)
        statements = [https_statement(name)] if https else []
        if public:
            s3.put_bucket_acl(Bucket=name, ACL="public-read")
            statements.append({"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{name}/*"})
        if statements:
            s3.put_bucket_policy(Bucket=name, Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}))
        # Bucket-level Block Public Access also cancels a public policy or ACL, just as it does in AWS.
        if blocked and (not public or ok("s3.bucket_public_access_block")):
            s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=BLOCK_ALL)
        return name

    make_bucket("app-data")
    make_bucket("backups", https=ok("s3.https_only"))
    make_bucket("marketing-assets", blocked=ok("s3.bucket_public_access_block"))
    if not ok("s3.public_buckets"):
        make_bucket("customer-exports", public=True)
    trail_bucket = make_bucket("cloudtrail")
    access_logs = make_bucket("access-logs")
    s3.put_bucket_acl(Bucket=access_logs, ACL="log-delivery-write")
    config_bucket = make_bucket("config")
    if ok("cloudtrail.bucket_logging"):
        s3.put_bucket_logging(
            Bucket=trail_bucket, BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": access_logs, "TargetPrefix": "cloudtrail/"}}
        )

    # Storage
    if ok("ec2.ebs_default_encryption"):
        ec2.enable_ebs_encryption_by_default()
    session.client("rds").create_db_instance(
        DBInstanceIdentifier="orders-db", DBInstanceClass="db.t3.medium", Engine="postgres", MasterUsername="orders",
        MasterUserPassword="demo-database-password", AllocatedStorage=100,
        StorageEncrypted=ok("rds.encryption"), PubliclyAccessible=not ok("rds.public"),
        AutoMinorVersionUpgrade=ok("rds.minor_upgrades"),
    )  # fmt: skip

    # Keys and logging
    kms = session.client("kms")
    trail_key = kms.create_key(Description="CloudTrail logs")["KeyMetadata"]
    kms.enable_key_rotation(KeyId=trail_key["KeyId"])
    secrets_key = kms.create_key(Description="Application secrets")["KeyMetadata"]
    if ok("kms.rotation"):
        kms.enable_key_rotation(KeyId=secrets_key["KeyId"])

    logs.create_log_group(logGroupName="cloudtrail")
    cloudtrail = session.client("cloudtrail")
    trail = {
        "Name": "org-trail",
        "S3BucketName": trail_bucket,
        "IsMultiRegionTrail": ok("cloudtrail.all_regions"),
        "EnableLogFileValidation": ok("cloudtrail.log_validation"),
        "CloudWatchLogsLogGroupArn": f"arn:aws:logs:{REGION}:{account}:log-group:cloudtrail:*",
        "CloudWatchLogsRoleArn": service_role,
    }
    if ok("cloudtrail.kms"):
        trail["KmsKeyId"] = trail_key["Arn"]
    cloudtrail.create_trail(**trail)
    cloudtrail.put_event_selectors(TrailName="org-trail", EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}])
    cloudtrail.start_logging(Name="org-trail")

    sns = session.client("sns")
    topic = sns.create_topic(Name="security-alerts")["TopicArn"]
    sns.subscribe(TopicArn=topic, Protocol="email", Endpoint=f"security@{company}.example")
    cloudwatch = session.client("cloudwatch")
    from .scanner.checks.monitoring import IAM_POLICY_EVENTS, TRAIL_EVENTS

    patterns = {"monitoring.iam_policy_changes": _event_pattern(IAM_POLICY_EVENTS), "monitoring.trail_changes": _event_pattern(TRAIL_EVENTS)}
    for check_id, (name, pattern) in ALARMS.items():
        if not ok(check_id):
            continue
        logs.put_metric_filter(
            logGroupName="cloudtrail", filterName=name, filterPattern=pattern or patterns[check_id],
            metricTransformations=[{"metricName": name, "metricNamespace": "CISBenchmark", "metricValue": "1"}],
        )  # fmt: skip
        cloudwatch.put_metric_alarm(
            AlarmName=name, MetricName=name, Namespace="CISBenchmark", Statistic="Sum", Period=300, EvaluationPeriods=1,
            Threshold=1, ComparisonOperator="GreaterThanOrEqualToThreshold", AlarmActions=[topic],
        )  # fmt: skip

    if ok("config.recorder"):
        config = session.client("config")
        config.put_configuration_recorder(
            ConfigurationRecorder={"name": "default", "roleARN": service_role, "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}}
        )
        config.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": config_bucket})
        config.start_configuration_recorder(ConfigurationRecorderName="default")

    # Network
    vpc = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
    if ok("vpc.flow_logs"):
        logs.create_log_group(logGroupName="vpc-flow-logs")
        ec2.create_flow_logs(ResourceIds=[vpc], ResourceType="VPC", TrafficType="REJECT", LogGroupName="vpc-flow-logs", DeliverLogsPermissionArn=service_role)  # fmt: skip
    if ok("ec2.nacl_admin_ports"):
        acl = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkAcls"][0]["NetworkAclId"]
        for number, port in ((80, 443), (90, 80)):
            ec2.create_network_acl_entry(
                NetworkAclId=acl, RuleNumber=number, Protocol="6", RuleAction="allow", Egress=False,
                CidrBlock="0.0.0.0/0", PortRange={"From": port, "To": port},
            )  # fmt: skip
        ec2.replace_network_acl_entry(
            NetworkAclId=acl, RuleNumber=100, Protocol="6", RuleAction="allow", Egress=False,
            CidrBlock="10.0.0.0/8", PortRange={"From": 0, "To": 65535},
        )  # fmt: skip
    if ok("ec2.default_security_group"):
        default_group = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"][0]
        if default_group.get("IpPermissionsEgress"):
            ec2.revoke_security_group_egress(GroupId=default_group["GroupId"], IpPermissions=default_group["IpPermissionsEgress"])
        if default_group.get("IpPermissions"):
            ec2.revoke_security_group_ingress(GroupId=default_group["GroupId"], IpPermissions=default_group["IpPermissions"])

    def group(name, description, rules):
        group_id = ec2.create_security_group(GroupName=name, Description=description, VpcId=vpc)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=rules)
        return group_id

    web = group("web", "Public web servers", [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
    ])  # fmt: skip
    bastion = group("bastion", "SSH for the ops team", [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.0/24" if ok("ec2.sg_admin_ports_ipv4") else "0.0.0.0/0"}]},
    ])  # fmt: skip
    group("windows-jump", "RDP into the reporting server", [
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32" if ok("ec2.sg_admin_ports_ipv6") else "::/0"}]},
    ])  # fmt: skip

    tokens = "required" if ok("ec2.imdsv2") else "optional"
    for groups in ([web], [bastion]):
        ec2.run_instances(
            ImageId="ami-12c6146b", MinCount=1, MaxCount=1, InstanceType="t3.small", SecurityGroupIds=groups,
            MetadataOptions={"HttpTokens": tokens, "HttpEndpoint": "enabled"},
        )  # fmt: skip


def target(user, fixes):
    """A scan target for a demo visitor. The account is built when the scan starts and dropped when it ends."""
    account = demo_account_id(user["id"])

    def connect():
        session = DemoSession(account)
        forget(account)  # In case an earlier scan on this instance stopped before cleaning up.
        build(session, user["id"], ALREADY_FINE | with_dependencies(fixes))
        return session

    return ScanTarget("demo", connect, [REGION], disconnect=lambda: forget(account))
