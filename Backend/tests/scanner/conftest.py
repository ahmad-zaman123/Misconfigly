"""Two simulated AWS accounts in moto: one set up the way CIS asks, and one that gets everything wrong."""

import json
from contextlib import contextmanager

import boto3
import pytest
from moto import mock_aws
from moto.core import DEFAULT_ACCOUNT_ID
from moto.iam.models import iam_backends

REGION = "us-east-1"
ACCOUNT = DEFAULT_ACCOUNT_ID

ALARMS = {
    "unauthorized-api-calls": '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
    "console-without-mfa": '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
    "root-usage": '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
    "iam-policy-changes": "{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy)"
    " || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy)"
    " || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion)"
    " || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy)"
    " || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy)"
    " || ($.eventName=DetachGroupPolicy) }",
    "trail-changes": "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail)"
    " || ($.eventName = StartLogging) || ($.eventName = StopLogging) }",
}
TRUST_EC2 = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


@contextmanager
def simulated_aws():
    """A fresh, empty moto account. Fake credentials make sure nothing can reach real AWS."""
    with pytest.MonkeyPatch.context() as patch:
        for name, value in {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SESSION_TOKEN": "testing",
            "AWS_DEFAULT_REGION": REGION,
        }.items():
            patch.setenv(name, value)
        with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
            yield boto3.Session(region_name=REGION)


@pytest.fixture
def aws():
    with simulated_aws() as session:
        yield session


def root_summary(mfa=False, access_keys=False):
    summary = iam_backends[ACCOUNT]["global"].account_summary
    summary._account_mfa_enabled = int(mfa)
    summary._account_access_keys_present = int(access_keys)


def https_only_policy(bucket):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyPlainHttp",
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
    )


def make_bucket(s3, name, block=True):
    s3.create_bucket(Bucket=name)
    s3.put_bucket_policy(Bucket=name, Policy=https_only_policy(name))
    if block:
        s3.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration={k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
        )


def default_vpc(ec2):
    return ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"][0]["VpcId"]


def build_secure_account(session):
    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    root_summary(mfa=True)

    iam.update_account_password_policy(MinimumPasswordLength=16, PasswordReusePrevention=24)
    policy = iam.create_policy(
        PolicyName="ReadAppData",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-app-data/*"}]}
        ),
    )["Policy"]
    iam.create_group(GroupName="engineers")
    iam.attach_group_policy(GroupName="engineers", PolicyArn=policy["Arn"])
    iam.create_user(UserName="alice")
    iam.add_user_to_group(GroupName="engineers", UserName="alice")
    iam.create_login_profile(UserName="alice", Password="a-long-and-careful-password")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice")["VirtualMFADevice"]
    iam.enable_mfa_device(UserName="alice", SerialNumber=device["SerialNumber"], AuthenticationCode1="123456", AuthenticationCode2="654321")
    iam.create_access_key(UserName="alice")
    iam.create_role(RoleName="support", AssumeRolePolicyDocument=json.dumps(TRUST_EC2))
    iam.attach_role_policy(RoleName="support", PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess")

    session.client("s3control").put_public_access_block(
        AccountId=ACCOUNT,
        PublicAccessBlockConfiguration={k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
    )
    for name in ("acme-app-data", "acme-cloudtrail", "acme-access-logs", "acme-config"):
        make_bucket(s3, name)
    s3.put_bucket_acl(Bucket="acme-access-logs", ACL="log-delivery-write")
    s3.put_bucket_logging(
        Bucket="acme-cloudtrail",
        BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "acme-access-logs", "TargetPrefix": "cloudtrail/"}},
    )

    ec2.enable_ebs_encryption_by_default()
    session.client("rds").create_db_instance(
        DBInstanceIdentifier="orders-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="app",
        MasterUserPassword="a-long-db-password",
        AllocatedStorage=20,
        StorageEncrypted=True,
        PubliclyAccessible=False,
        AutoMinorVersionUpgrade=True,
    )

    kms = session.client("kms")
    key = kms.create_key(Description="CloudTrail logs")["KeyMetadata"]
    kms.enable_key_rotation(KeyId=key["KeyId"])

    logs = session.client("logs")
    logs.create_log_group(logGroupName="cloudtrail")
    group_arn = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:cloudtrail:*"
    role = iam.create_role(RoleName="cloudtrail-to-logs", AssumeRolePolicyDocument=json.dumps(TRUST_EC2))["Role"]
    cloudtrail = session.client("cloudtrail")
    cloudtrail.create_trail(
        Name="org-trail",
        S3BucketName="acme-cloudtrail",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        KmsKeyId=key["Arn"],
        CloudWatchLogsLogGroupArn=group_arn,
        CloudWatchLogsRoleArn=role["Arn"],
    )
    cloudtrail.put_event_selectors(
        TrailName="org-trail", EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}]
    )
    cloudtrail.start_logging(Name="org-trail")

    sns = session.client("sns")
    topic = sns.create_topic(Name="security-alerts")["TopicArn"]
    sns.subscribe(TopicArn=topic, Protocol="email", Endpoint="security@acme.example")
    cloudwatch = session.client("cloudwatch")
    for name, pattern in ALARMS.items():
        logs.put_metric_filter(
            logGroupName="cloudtrail",
            filterName=name,
            filterPattern=pattern,
            metricTransformations=[{"metricName": name, "metricNamespace": "CISBenchmark", "metricValue": "1"}],
        )
        cloudwatch.put_metric_alarm(
            AlarmName=name,
            MetricName=name,
            Namespace="CISBenchmark",
            Statistic="Sum",
            Period=300,
            EvaluationPeriods=1,
            Threshold=1,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            AlarmActions=[topic],
        )

    config = session.client("config")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": role["Arn"],
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
        }
    )
    config.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "acme-config"})
    config.start_configuration_recorder(ConfigurationRecorderName="default")

    vpc = default_vpc(ec2)
    logs.create_log_group(logGroupName="vpc-flow-logs")
    ec2.create_flow_logs(
        ResourceIds=[vpc],
        ResourceType="VPC",
        TrafficType="ALL",
        LogGroupName="vpc-flow-logs",
        DeliverLogsPermissionArn=role["Arn"],
    )
    acl = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkAcls"][0]["NetworkAclId"]
    ec2.replace_network_acl_entry(
        NetworkAclId=acl, RuleNumber=100, Protocol="6", RuleAction="allow", Egress=False,
        CidrBlock="0.0.0.0/0", PortRange={"From": 443, "To": 443},
    )  # fmt: skip
    default_group = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]
    if default_group.get("IpPermissionsEgress"):
        ec2.revoke_security_group_egress(GroupId=default_group["GroupId"], IpPermissions=default_group["IpPermissionsEgress"])
    if default_group.get("IpPermissions"):
        ec2.revoke_security_group_ingress(GroupId=default_group["GroupId"], IpPermissions=default_group["IpPermissions"])
    web = ec2.create_security_group(GroupName="web", Description="Web servers", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=web,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        ],
    )
    ec2.run_instances(
        ImageId="ami-12c6146b", MinCount=1, MaxCount=1, InstanceType="t3.micro", SecurityGroupIds=[web],
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
    )  # fmt: skip


def build_insecure_account(session):
    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    root_summary(mfa=False, access_keys=True)

    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="password123")
    iam.create_access_key(UserName="bob")
    iam.create_access_key(UserName="bob")
    admin = iam.create_policy(
        PolicyName="EverythingEverywhere",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
    )["Policy"]
    iam.attach_user_policy(UserName="bob", PolicyArn=admin["Arn"])
    iam.upload_server_certificate(
        ServerCertificateName="old-shop-cert", CertificateBody="-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----",
        PrivateKey="-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----",
    )  # fmt: skip

    s3.create_bucket(Bucket="acme-public-site")
    s3.put_bucket_acl(Bucket="acme-public-site", ACL="public-read")
    s3.put_bucket_policy(
        Bucket="acme-public-site",
        Policy=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::acme-public-site/*"}]}
        ),
    )
    s3.create_bucket(Bucket="acme-trail-logs")

    session.client("rds").create_db_instance(
        DBInstanceIdentifier="legacy-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="password123",
        AllocatedStorage=20,
        StorageEncrypted=False,
        PubliclyAccessible=True,
        AutoMinorVersionUpgrade=False,
    )
    session.client("kms").create_key(Description="App secrets")
    session.client("cloudtrail").create_trail(Name="local-trail", S3BucketName="acme-trail-logs")

    vpc = default_vpc(ec2)
    open_door = ec2.create_security_group(GroupName="open-door", Description="Quick test", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=open_door,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        ],
    )
    ec2.run_instances(
        ImageId="ami-12c6146b", MinCount=1, MaxCount=1, InstanceType="t3.micro", SecurityGroupIds=[open_door],
        MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"},
    )  # fmt: skip
