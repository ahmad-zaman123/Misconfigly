"""How to fix each check: why it matters, console steps, an AWS CLI command and Terraform.

Commands use {resource}, {region}, {account}, {user}, {key} and {group_id}, which are filled in from the finding.
Words in CAPITALS are for the reader to replace, such as LOG_BUCKET.
"""

import re
from dataclasses import dataclass

from .checks.monitoring import IAM_POLICY_EVENTS, TRAIL_EVENTS


@dataclass(frozen=True)
class Fix:
    why: str
    console: tuple[str, ...]
    cli: str | None = None
    terraform: str | None = None


PLACEHOLDER = re.compile(r"\{(resource|region|account|user|key|group_id)\}")
BLOCK_ALL = "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"


def _sg_revoke(cidr_flag, cidr):
    return "\n".join(
        f"aws ec2 revoke-security-group-ingress --group-id {{group_id}} --protocol tcp --port {port} {cidr_flag} {cidr} --region {{region}}"
        for port in (22, 3389)
    )


def _alarm_fix(name, pattern, about):
    return Fix(
        why=f"Without an alarm, {about} can happen without anyone hearing about it until much later.",
        console=(
            "Make sure a trail that covers every region sends its logs to CloudWatch Logs (CloudTrail > Trails > CloudWatch Logs).",
            "In CloudWatch > Log groups, open that log group and choose Metric filters > Create metric filter.",
            "Paste the filter pattern from the CLI tab, and name the metric in the CISBenchmark namespace.",
            "Create an alarm on the new metric (threshold 1 or more in 5 minutes) that notifies an SNS topic.",
            "Subscribe the security team's email or chat channel to that topic and confirm the subscription.",
        ),
        cli=(
            f"aws logs put-metric-filter --log-group-name LOG_GROUP --filter-name {name} \\\n"
            f"  --metric-transformations metricName={name},metricNamespace=CISBenchmark,metricValue=1 \\\n"
            f"  --filter-pattern '{pattern}'\n"
            f"aws cloudwatch put-metric-alarm --alarm-name {name} --metric-name {name} --namespace CISBenchmark \\\n"
            "  --statistic Sum --period 300 --evaluation-periods 1 --threshold 1 \\\n"
            "  --comparison-operator GreaterThanOrEqualToThreshold --alarm-actions SNS_TOPIC_ARN"
        ),
        terraform=(
            f'resource "aws_cloudwatch_log_metric_filter" "{name.replace("-", "_")}" {{\n'
            f'  name           = "{name}"\n'
            "  log_group_name = \"LOG_GROUP\"\n"
            f"  pattern        = {_hcl_string(pattern)}\n\n"
            "  metric_transformation {\n"
            f'    name      = "{name}"\n'
            '    namespace = "CISBenchmark"\n'
            '    value     = "1"\n'
            "  }\n}\n\n"
            f'resource "aws_cloudwatch_metric_alarm" "{name.replace("-", "_")}" {{\n'
            f'  alarm_name          = "{name}"\n'
            f'  metric_name         = "{name}"\n'
            '  namespace           = "CISBenchmark"\n'
            '  statistic           = "Sum"\n'
            "  period              = 300\n"
            "  evaluation_periods  = 1\n"
            "  threshold           = 1\n"
            '  comparison_operator = "GreaterThanOrEqualToThreshold"\n'
            '  alarm_actions       = ["SNS_TOPIC_ARN"]\n'
            "}"
        ),
    )


def _hcl_string(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _event_pattern(names):
    return "{ " + " || ".join(f"($.eventName = {n})" for n in names) + " }"


FIXES = {
    "iam.root_access_keys": Fix(
        why="A root access key can do anything in the account, and nothing can restrict it. If it leaks, the whole account is lost.",
        console=(
            "Sign in to the AWS console as the root user.",
            "Open your account name > Security credentials.",
            "Under Access keys, make the key inactive, check nothing broke, then delete it.",
            "Use IAM roles or IAM Identity Center users for anything that needed the key.",
        ),
    ),
    "iam.root_mfa": Fix(
        why="The root user can close the account or change its billing. A password alone is one phishing email away from being stolen.",
        console=(
            "Sign in to the AWS console as the root user.",
            "Open your account name > Security credentials > Multi-factor authentication.",
            "Choose Assign MFA device and register a passkey, security key or authenticator app.",
            "Keep a second device registered so losing one doesn't lock you out.",
        ),
    ),
    "iam.password_length": Fix(
        why="Short passwords are guessed or cracked far faster. CIS asks for at least 14 characters.",
        console=(
            "Open IAM > Account settings > Password policy > Edit.",
            "Choose Custom and set the minimum length to 14 or more.",
            "Save changes. Existing passwords keep working until they're next changed.",
        ),
        cli=(
            "# This replaces the whole policy, so include any settings you already rely on.\n"
            "aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24 \\\n"
            "  --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters"
        ),
        terraform=(
            'resource "aws_iam_account_password_policy" "cis" {\n'
            "  minimum_password_length      = 14\n"
            "  password_reuse_prevention    = 24\n"
            "  require_symbols              = true\n"
            "  require_numbers              = true\n"
            "  require_uppercase_characters = true\n"
            "  require_lowercase_characters = true\n"
            "}"
        ),
    ),
    "iam.password_reuse": Fix(
        why="If old passwords can be reused, a password that leaked in the past can come back into use.",
        console=(
            "Open IAM > Account settings > Password policy > Edit.",
            "Choose Custom, turn on Prevent password reuse and set it to 24.",
            "Save changes.",
        ),
        cli=(
            "# This replaces the whole policy, so include any settings you already rely on.\n"
            "aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24"
        ),
        terraform=(
            'resource "aws_iam_account_password_policy" "cis" {\n'
            "  minimum_password_length   = 14\n"
            "  password_reuse_prevention = 24\n"
            "}"
        ),
    ),
    "iam.user_mfa": Fix(
        why="A console user with only a password can be taken over with one stolen or reused password.",
        console=(
            "Open IAM > Users and choose {resource}.",
            "Open the Security credentials tab and choose Assign MFA device.",
            "Have the user register a passkey, security key or authenticator app.",
            "Consider a policy that denies everything except setting up MFA until it is on.",
        ),
        cli=(
            "aws iam create-virtual-mfa-device --virtual-mfa-device-name {resource} \\\n"
            "  --outfile {resource}-mfa.png --bootstrap-method QRCodePNG\n"
            "# Scan the QR code, then enter two codes in a row:\n"
            "aws iam enable-mfa-device --user-name {resource} \\\n"
            "  --serial-number arn:aws:iam::{account}:mfa/{resource} \\\n"
            "  --authentication-code1 CODE1 --authentication-code2 CODE2"
        ),
    ),
    "iam.unused_credentials": Fix(
        why="Passwords and keys nobody uses are easy to forget about, and nobody notices when someone else starts using them.",
        console=(
            "Open IAM > Users and choose {resource}.",
            "On the Security credentials tab, remove the console password if it isn't needed.",
            "Make unused access keys inactive. Delete them once you're sure nothing depends on them.",
        ),
        cli=(
            "aws iam delete-login-profile --user-name {resource}\n"
            "aws iam list-access-keys --user-name {resource}\n"
            "aws iam update-access-key --user-name {resource} --access-key-id ACCESS_KEY_ID --status Inactive"
        ),
    ),
    "iam.one_active_key": Fix(
        why="Two active keys double the chance of a leak and usually mean an old key was never retired.",
        console=(
            "Open IAM > Users and choose {resource}.",
            "On the Security credentials tab, check which key is still in use from its Last used column.",
            "Make the other key inactive, then delete it once nothing breaks.",
        ),
        cli=(
            "aws iam list-access-keys --user-name {resource}\n"
            "aws iam update-access-key --user-name {resource} --access-key-id OLD_ACCESS_KEY_ID --status Inactive\n"
            "aws iam delete-access-key --user-name {resource} --access-key-id OLD_ACCESS_KEY_ID"
        ),
    ),
    "iam.key_rotation": Fix(
        why="The longer a key lives, the more places it gets copied to, and the longer a leaked copy stays useful.",
        console=(
            "Open IAM > Users and choose {user}.",
            "Create a second access key and switch the application to it.",
            "Make the old key {key} inactive, watch for errors, then delete it.",
            "Better still, replace long-lived keys with an IAM role.",
        ),
        cli=(
            "aws iam create-access-key --user-name {user}\n"
            "# Switch the application to the new key, then:\n"
            "aws iam update-access-key --user-name {user} --access-key-id {key} --status Inactive\n"
            "aws iam delete-access-key --user-name {user} --access-key-id {key}"
        ),
    ),
    "iam.user_policies": Fix(
        why="Permissions attached to single users are hard to review and tend to pile up. Groups keep them in one place.",
        console=(
            "Open IAM > User groups and create a group for this role, or pick an existing one.",
            "Attach the policies {resource} needs to the group.",
            "Add {resource} to the group.",
            "On the user's Permissions tab, remove the policies attached directly.",
        ),
        cli=(
            "aws iam add-user-to-group --user-name {resource} --group-name GROUP_NAME\n"
            "aws iam list-attached-user-policies --user-name {resource}\n"
            "aws iam detach-user-policy --user-name {resource} --policy-arn POLICY_ARN\n"
            "aws iam list-user-policies --user-name {resource}\n"
            "aws iam delete-user-policy --user-name {resource} --policy-name INLINE_POLICY_NAME"
        ),
        terraform=(
            'resource "aws_iam_group" "team" {\n'
            '  name = "GROUP_NAME"\n'
            "}\n\n"
            'resource "aws_iam_group_policy_attachment" "team" {\n'
            "  group      = aws_iam_group.team.name\n"
            '  policy_arn = "POLICY_ARN"\n'
            "}\n\n"
            'resource "aws_iam_user_group_membership" "member" {\n'
            '  user   = "{resource}"\n'
            "  groups = [aws_iam_group.team.name]\n"
            "}"
        ),
    ),
    "iam.admin_policies": Fix(
        why='A custom "*:*" policy gives full admin rights, usually to more people or services than intended.',
        console=(
            "Open IAM > Policies and choose {resource}.",
            "On Entities attached, note who uses it and what they really need.",
            "Edit the policy so it lists only those actions and resources, and save it as the default version.",
            "Give the few people who need full admin rights the AWS managed AdministratorAccess policy, with MFA.",
        ),
        cli=(
            "aws iam list-entities-for-policy --policy-arn arn:aws:iam::{account}:policy/{resource}\n"
            "aws iam create-policy-version --policy-arn arn:aws:iam::{account}:policy/{resource} \\\n"
            "  --policy-document file://least-privilege.json --set-as-default"
        ),
        terraform=(
            'data "aws_iam_policy_document" "scoped" {\n'
            "  statement {\n"
            '    actions   = ["s3:GetObject", "s3:PutObject"]\n'
            '    resources = ["arn:aws:s3:::BUCKET_NAME/*"]\n'
            "  }\n}\n\n"
            'resource "aws_iam_policy" "scoped" {\n'
            '  name   = "{resource}"\n'
            "  policy = data.aws_iam_policy_document.scoped.json\n"
            "}"
        ),
    ),
    "iam.support_role": Fix(
        why="Without a support role, people who need to open support cases are often given far broader rights.",
        console=(
            "Open IAM > Roles > Create role.",
            "Choose AWS account, this account, and require MFA.",
            "Attach the AWSSupportAccess policy and name the role, for example aws-support.",
        ),
        cli=(
            "aws iam create-role --role-name aws-support \\\n"
            "  --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
            "\"Principal\":{\"AWS\":\"arn:aws:iam::{account}:root\"},\"Action\":\"sts:AssumeRole\"}]}'\n"
            "aws iam attach-role-policy --role-name aws-support --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess"
        ),
        terraform=(
            'resource "aws_iam_role" "support" {\n'
            '  name = "aws-support"\n'
            "  assume_role_policy = jsonencode({\n"
            '    Version = "2012-10-17"\n'
            "    Statement = [{\n"
            '      Effect    = "Allow"\n'
            '      Principal = { AWS = "arn:aws:iam::{account}:root" }\n'
            '      Action    = "sts:AssumeRole"\n'
            "    }]\n"
            "  })\n"
            "}\n\n"
            'resource "aws_iam_role_policy_attachment" "support" {\n'
            "  role       = aws_iam_role.support.name\n"
            '  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"\n'
            "}"
        ),
    ),
    "iam.expired_certificates": Fix(
        why="An expired certificate can be attached to a load balancer by mistake and break HTTPS for your users.",
        console=(
            "IAM server certificates can't be managed in the console.",
            "Check nothing still uses {resource}, then delete it with the CLI command.",
            "Use AWS Certificate Manager for new certificates, which renews them for you.",
        ),
        cli="aws iam delete-server-certificate --server-certificate-name {resource}",
    ),
    "s3.account_public_access_block": Fix(
        why="One setting for the whole account stops any bucket, now or later, from being opened to the internet by mistake.",
        console=(
            "Open S3 > Block Public Access settings for this account > Edit.",
            "Turn on Block all public access and save.",
            "If a bucket must stay public, such as a website, serve it through CloudFront instead.",
        ),
        cli=f"aws s3control put-public-access-block --account-id {{account}} \\\n  --public-access-block-configuration {BLOCK_ALL}",
        terraform=(
            'resource "aws_s3_account_public_access_block" "account" {\n'
            "  block_public_acls       = true\n"
            "  ignore_public_acls      = true\n"
            "  block_public_policy     = true\n"
            "  restrict_public_buckets = true\n"
            "}"
        ),
    ),
    "s3.bucket_public_access_block": Fix(
        why="Without Block Public Access, a single policy or ACL change can expose everything in the bucket.",
        console=(
            "Open S3 > Buckets > {resource} > Permissions.",
            "Under Block public access, choose Edit, turn on Block all public access and save.",
        ),
        cli=f"aws s3api put-public-access-block --bucket {{resource}} \\\n  --public-access-block-configuration {BLOCK_ALL}",
        terraform=(
            'resource "aws_s3_bucket_public_access_block" "this" {\n'
            '  bucket                  = "{resource}"\n'
            "  block_public_acls       = true\n"
            "  ignore_public_acls      = true\n"
            "  block_public_policy     = true\n"
            "  restrict_public_buckets = true\n"
            "}"
        ),
    ),
    "s3.public_buckets": Fix(
        why="Anyone on the internet can read this bucket. Public buckets are one of the most common causes of data leaks.",
        console=(
            "Open S3 > Buckets > {resource} > Permissions.",
            "Under Block public access, choose Edit, turn on Block all public access and save.",
            "Remove the public statement from the bucket policy, and any Everyone grants from the ACL.",
            "If the files really must be public, serve them through CloudFront with origin access control.",
        ),
        cli=(
            f"aws s3api put-public-access-block --bucket {{resource}} \\\n  --public-access-block-configuration {BLOCK_ALL}\n"
            "aws s3api put-bucket-acl --bucket {resource} --acl private\n"
            "aws s3api get-bucket-policy --bucket {resource}\n"
            "# Remove the Principal \"*\" statement, then:\n"
            "aws s3api put-bucket-policy --bucket {resource} --policy file://policy.json"
        ),
        terraform=(
            'resource "aws_s3_bucket_public_access_block" "this" {\n'
            '  bucket                  = "{resource}"\n'
            "  block_public_acls       = true\n"
            "  ignore_public_acls      = true\n"
            "  block_public_policy     = true\n"
            "  restrict_public_buckets = true\n"
            "}"
        ),
    ),
    "s3.https_only": Fix(
        why="Requests over plain HTTP can be read or changed by anyone on the network path.",
        console=(
            "Open S3 > Buckets > {resource} > Permissions > Bucket policy > Edit.",
            "Add the DenyPlainHttp statement from the CLI tab to the existing statements.",
            "Save changes.",
        ),
        cli=(
            "# put-bucket-policy replaces the whole policy, so merge this statement into the current one.\n"
            "aws s3api put-bucket-policy --bucket {resource} --policy '{\n"
            '  "Version": "2012-10-17",\n'
            '  "Statement": [{\n'
            '    "Sid": "DenyPlainHttp",\n'
            '    "Effect": "Deny",\n'
            '    "Principal": "*",\n'
            '    "Action": "s3:*",\n'
            '    "Resource": ["arn:aws:s3:::{resource}", "arn:aws:s3:::{resource}/*"],\n'
            '    "Condition": {"Bool": {"aws:SecureTransport": "false"}}\n'
            "  }]\n}'"
        ),
        terraform=(
            'data "aws_iam_policy_document" "https_only" {\n'
            "  statement {\n"
            '    sid     = "DenyPlainHttp"\n'
            '    effect  = "Deny"\n'
            '    actions = ["s3:*"]\n'
            '    resources = ["arn:aws:s3:::{resource}", "arn:aws:s3:::{resource}/*"]\n'
            "    principals {\n"
            '      type        = "*"\n'
            '      identifiers = ["*"]\n'
            "    }\n"
            "    condition {\n"
            '      test     = "Bool"\n'
            '      variable = "aws:SecureTransport"\n'
            '      values   = ["false"]\n'
            "    }\n"
            "  }\n}\n\n"
            'resource "aws_s3_bucket_policy" "https_only" {\n'
            '  bucket = "{resource}"\n'
            "  policy = data.aws_iam_policy_document.https_only.json\n"
            "}"
        ),
    ),
    "ec2.ebs_default_encryption": Fix(
        why="Unencrypted volumes and their snapshots can be read by anyone who gets a copy of them.",
        console=(
            "Open EC2 in {region} > Settings > Data protection and security.",
            "Under EBS encryption, choose Manage, tick Always encrypt new EBS volumes and save.",
            "Repeat in every region you use. Existing volumes have to be copied to encrypt them.",
        ),
        cli="aws ec2 enable-ebs-encryption-by-default --region {region}",
        terraform='resource "aws_ebs_encryption_by_default" "this" {\n  enabled = true\n}',
    ),
    "rds.encryption": Fix(
        why="Unencrypted databases leave the data and every snapshot readable to anyone who obtains a copy.",
        console=(
            "Encryption can't be turned on for a running database, so it has to be copied.",
            "In RDS > Snapshots, take a snapshot of {resource}.",
            "Choose Copy snapshot, tick Enable encryption and pick a KMS key.",
            "Restore the encrypted copy as a new instance, point the application at it, then delete the old one.",
        ),
        cli=(
            "aws rds create-db-snapshot --db-instance-identifier {resource} --db-snapshot-identifier {resource}-plain --region {region}\n"
            "aws rds copy-db-snapshot --source-db-snapshot-identifier {resource}-plain \\\n"
            "  --target-db-snapshot-identifier {resource}-encrypted --kms-key-id alias/aws/rds --region {region}\n"
            "aws rds restore-db-instance-from-db-snapshot --db-instance-identifier {resource}-new \\\n"
            "  --db-snapshot-identifier {resource}-encrypted --region {region}"
        ),
        terraform=(
            'resource "aws_db_instance" "this" {\n'
            '  identifier        = "{resource}"\n'
            "  storage_encrypted = true\n"
            "  # Changing this replaces the database, so restore from an encrypted snapshot first.\n"
            "}"
        ),
    ),
    "rds.minor_upgrades": Fix(
        why="Minor versions carry security fixes. Without automatic upgrades the database falls behind on patches.",
        console=(
            "Open RDS > Databases > {resource} > Modify.",
            "Under Maintenance, turn on Auto minor version upgrade.",
            "Choose Apply during the next maintenance window.",
        ),
        cli="aws rds modify-db-instance --db-instance-identifier {resource} --auto-minor-version-upgrade --region {region}",
        terraform='resource "aws_db_instance" "this" {\n  identifier                 = "{resource}"\n  auto_minor_version_upgrade = true\n}',
    ),
    "rds.public": Fix(
        why="A public database endpoint lets anyone on the internet try passwords and known exploits against it.",
        console=(
            "Open RDS > Databases > {resource} > Modify.",
            "Under Connectivity > Additional configuration, choose Not publicly accessible.",
            "Apply immediately, then reach the database from inside the VPC or through a bastion or VPN.",
        ),
        cli="aws rds modify-db-instance --db-instance-identifier {resource} --no-publicly-accessible --apply-immediately --region {region}",
        terraform='resource "aws_db_instance" "this" {\n  identifier          = "{resource}"\n  publicly_accessible = false\n}',
    ),
    "cloudtrail.all_regions": Fix(
        why="Without a trail in every region, an attacker can work in a region you don't use and leave no record.",
        console=(
            "Open CloudTrail > Trails > Create trail, or edit an existing trail.",
            "Turn on Enable for all accounts or All regions, and choose a log bucket.",
            "Under Events, record Management events with both Read and Write.",
            "Make sure Logging is on.",
        ),
        cli=(
            "aws cloudtrail create-trail --name org-trail --s3-bucket-name LOG_BUCKET \\\n"
            "  --is-multi-region-trail --enable-log-file-validation --region {region}\n"
            "aws cloudtrail put-event-selectors --trail-name org-trail --region {region} \\\n"
            "  --event-selectors '[{\"ReadWriteType\": \"All\", \"IncludeManagementEvents\": true}]'\n"
            "aws cloudtrail start-logging --name org-trail --region {region}"
        ),
        terraform=(
            'resource "aws_cloudtrail" "org" {\n'
            '  name                       = "org-trail"\n'
            '  s3_bucket_name             = "LOG_BUCKET"\n'
            "  is_multi_region_trail      = true\n"
            "  enable_log_file_validation = true\n"
            "  enable_logging             = true\n\n"
            "  event_selector {\n"
            '    read_write_type           = "All"\n'
            "    include_management_events = true\n"
            "  }\n}"
        ),
    ),
    "cloudtrail.log_validation": Fix(
        why="Without validation, someone who gets into the log bucket can edit or delete logs and nobody can prove it.",
        console=(
            "Open CloudTrail > Trails > {resource} > General details > Edit.",
            "Under Additional settings, turn on Log file validation and save.",
        ),
        cli="aws cloudtrail update-trail --name {resource} --enable-log-file-validation",
        terraform='resource "aws_cloudtrail" "this" {\n  name                       = "{resource}"\n  enable_log_file_validation = true\n}',
    ),
    "config.recorder": Fix(
        why="AWS Config keeps a history of how each resource was set up, which is what you need after an incident.",
        console=(
            "Open AWS Config in {region} and choose Get started, or Settings > Edit.",
            "Record all resource types, including global ones in one region.",
            "Choose a bucket for the history and save, then make sure recording is on.",
        ),
        cli=(
            "aws configservice put-configuration-recorder --region {region} \\\n"
            "  --configuration-recorder name=default,roleARN=arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig \\\n"
            "  --recording-group allSupported=true,includeGlobalResourceTypes=true\n"
            "aws configservice put-delivery-channel --region {region} --delivery-channel name=default,s3BucketName=CONFIG_BUCKET\n"
            "aws configservice start-configuration-recorder --configuration-recorder-name default --region {region}"
        ),
        terraform=(
            'resource "aws_config_configuration_recorder" "this" {\n'
            '  name     = "default"\n'
            '  role_arn = "arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"\n\n'
            "  recording_group {\n"
            "    all_supported                 = true\n"
            "    include_global_resource_types = true\n"
            "  }\n}\n\n"
            'resource "aws_config_delivery_channel" "this" {\n'
            '  name           = "default"\n'
            '  s3_bucket_name = "CONFIG_BUCKET"\n'
            "  depends_on     = [aws_config_configuration_recorder.this]\n"
            "}\n\n"
            'resource "aws_config_configuration_recorder_status" "this" {\n'
            "  name       = aws_config_configuration_recorder.this.name\n"
            "  is_enabled = true\n"
            "  depends_on = [aws_config_delivery_channel.this]\n"
            "}"
        ),
    ),
    "cloudtrail.bucket_logging": Fix(
        why="Access logs on the audit bucket show who read or tried to change your audit trail.",
        console=(
            "Open S3 > Buckets > {resource} > Properties.",
            "Under Server access logging, choose Edit, turn it on and pick a separate log bucket.",
        ),
        cli=(
            "aws s3api put-bucket-logging --bucket {resource} --bucket-logging-status \\\n"
            "  '{\"LoggingEnabled\": {\"TargetBucket\": \"ACCESS_LOG_BUCKET\", \"TargetPrefix\": \"{resource}/\"}}'"
        ),
        terraform=(
            'resource "aws_s3_bucket_logging" "trail" {\n'
            '  bucket        = "{resource}"\n'
            '  target_bucket = "ACCESS_LOG_BUCKET"\n'
            '  target_prefix = "{resource}/"\n'
            "}"
        ),
    ),
    "cloudtrail.kms": Fix(
        why="A KMS key adds a second lock: reading the logs then needs permission on the key as well as the bucket.",
        console=(
            "Create a KMS key whose policy lets cloudtrail.amazonaws.com encrypt with it.",
            "Open CloudTrail > Trails > {resource} > General details > Edit.",
            "Turn on SSE-KMS encryption, choose the key and save.",
        ),
        cli="aws cloudtrail update-trail --name {resource} --kms-key-id alias/cloudtrail",
        terraform='resource "aws_cloudtrail" "this" {\n  name       = "{resource}"\n  kms_key_id = "KMS_KEY_ARN"\n}',
    ),
    "kms.rotation": Fix(
        why="Yearly rotation limits how much data any one version of the key protects. AWS keeps old versions for decryption.",
        console=(
            "Open KMS in {region} > Customer managed keys > {resource}.",
            "On the Key rotation tab, tick Automatically rotate this KMS key every year and save.",
        ),
        cli="aws kms enable-key-rotation --key-id {resource} --region {region}",
        terraform='resource "aws_kms_key" "this" {\n  enable_key_rotation = true\n}',
    ),
    "vpc.flow_logs": Fix(
        why="Flow logs record which addresses talked to what, which you need to spot and investigate an intrusion.",
        console=(
            "Open VPC in {region} > Your VPCs > {resource}.",
            "On the Flow logs tab, choose Create flow log.",
            "Record at least Reject traffic, and send it to S3 or CloudWatch Logs.",
        ),
        cli=(
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids {resource} --traffic-type REJECT \\\n"
            "  --log-destination-type s3 --log-destination arn:aws:s3:::FLOW_LOG_BUCKET --region {region}"
        ),
        terraform=(
            'resource "aws_flow_log" "this" {\n'
            '  vpc_id               = "{resource}"\n'
            '  traffic_type         = "REJECT"\n'
            '  log_destination_type = "s3"\n'
            '  log_destination      = "arn:aws:s3:::FLOW_LOG_BUCKET"\n'
            "}"
        ),
    ),
    "monitoring.unauthorized_calls": _alarm_fix(
        "unauthorized-api-calls",
        '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
        "someone probing what a stolen key can do",
    ),
    "monitoring.console_without_mfa": _alarm_fix(
        "console-without-mfa",
        '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
        "a console sign-in without MFA",
    ),
    "monitoring.root_usage": _alarm_fix(
        "root-usage",
        '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
        "use of the root account",
    ),
    "monitoring.iam_policy_changes": _alarm_fix(
        "iam-policy-changes", _event_pattern(IAM_POLICY_EVENTS), "a change to who can do what"
    ),
    "monitoring.trail_changes": _alarm_fix(
        "trail-changes", _event_pattern(TRAIL_EVENTS), "someone switching off or changing CloudTrail"
    ),
    "ec2.nacl_admin_ports": Fix(
        why="SSH and RDP open to the whole internet are scanned and attacked within minutes of going live.",
        console=(
            "Open VPC in {region} > Network ACLs > {resource} > Inbound rules > Edit.",
            "Add deny rules for TCP 22 and 3389 from 0.0.0.0/0 with lower numbers than the allow rule.",
            "Or narrow the allow rule to the ports and addresses you really need.",
        ),
        cli=(
            "aws ec2 create-network-acl-entry --network-acl-id {resource} --ingress --rule-number 50 --protocol tcp \\\n"
            "  --port-range From=22,To=22 --cidr-block 0.0.0.0/0 --rule-action deny --region {region}\n"
            "aws ec2 create-network-acl-entry --network-acl-id {resource} --ingress --rule-number 51 --protocol tcp \\\n"
            "  --port-range From=3389,To=3389 --cidr-block 0.0.0.0/0 --rule-action deny --region {region}"
        ),
        terraform=(
            'resource "aws_network_acl_rule" "deny_ssh" {\n'
            '  network_acl_id = "{resource}"\n'
            "  rule_number    = 50\n"
            "  egress         = false\n"
            '  protocol       = "tcp"\n'
            '  rule_action    = "deny"\n'
            '  cidr_block     = "0.0.0.0/0"\n'
            "  from_port      = 22\n"
            "  to_port        = 22\n"
            "}\n\n"
            'resource "aws_network_acl_rule" "deny_rdp" {\n'
            '  network_acl_id = "{resource}"\n'
            "  rule_number    = 51\n"
            "  egress         = false\n"
            '  protocol       = "tcp"\n'
            '  rule_action    = "deny"\n'
            '  cidr_block     = "0.0.0.0/0"\n'
            "  from_port      = 3389\n"
            "  to_port        = 3389\n"
            "}"
        ),
    ),
    "ec2.sg_admin_ports_ipv4": Fix(
        why="SSH and RDP open to the whole internet are scanned and attacked within minutes of going live.",
        console=(
            "Open EC2 in {region} > Security groups > {group_id} > Inbound rules > Edit.",
            "Delete the rules for port 22 or 3389 with source 0.0.0.0/0.",
            "Allow your office or VPN range instead, or use Systems Manager Session Manager with no open port.",
        ),
        cli=_sg_revoke("--cidr", "0.0.0.0/0"),
        terraform=(
            'resource "aws_vpc_security_group_ingress_rule" "ssh_from_office" {\n'
            '  security_group_id = "{group_id}"\n'
            '  ip_protocol       = "tcp"\n'
            "  from_port         = 22\n"
            "  to_port           = 22\n"
            '  cidr_ipv4         = "OFFICE_CIDR"\n'
            "}"
        ),
    ),
    "ec2.sg_admin_ports_ipv6": Fix(
        why="SSH and RDP open to every IPv6 address are as exposed as when open to every IPv4 address.",
        console=(
            "Open EC2 in {region} > Security groups > {group_id} > Inbound rules > Edit.",
            "Delete the rules for port 22 or 3389 with source ::/0.",
            "Allow a specific range instead, or use Systems Manager Session Manager with no open port.",
        ),
        cli="\n".join(
            "aws ec2 revoke-security-group-ingress --group-id {group_id} --region {region} \\\n"
            f"  --ip-permissions 'IpProtocol=tcp,FromPort={port},ToPort={port},Ipv6Ranges=[{{CidrIpv6=::/0}}]'"
            for port in (22, 3389)
        ),
        terraform=(
            'resource "aws_vpc_security_group_ingress_rule" "ssh_from_office" {\n'
            '  security_group_id = "{group_id}"\n'
            '  ip_protocol       = "tcp"\n'
            "  from_port         = 22\n"
            "  to_port           = 22\n"
            '  cidr_ipv6         = "OFFICE_IPV6_CIDR"\n'
            "}"
        ),
    ),
    "ec2.default_security_group": Fix(
        why="Resources land in the default group when nobody picks one. With no rules, that mistake can't expose them.",
        console=(
            "Open EC2 in {region} > Security groups > {group_id}.",
            "Move anything still using it to a purpose-made security group.",
            "Delete every inbound and outbound rule from the default group.",
        ),
        cli=(
            "aws ec2 revoke-security-group-ingress --group-id {group_id} --region {region} --ip-permissions \\\n"
            "  \"$(aws ec2 describe-security-groups --group-ids {group_id} --region {region} --query 'SecurityGroups[0].IpPermissions')\"\n"
            "aws ec2 revoke-security-group-egress --group-id {group_id} --region {region} --ip-permissions \\\n"
            "  \"$(aws ec2 describe-security-groups --group-ids {group_id} --region {region} --query 'SecurityGroups[0].IpPermissionsEgress')\""
        ),
        terraform=(
            "# With no ingress or egress blocks, Terraform removes every rule from the default group.\n"
            'resource "aws_default_security_group" "default" {\n'
            '  vpc_id = "VPC_ID"\n'
            "}"
        ),
    ),
    "ec2.imdsv2": Fix(
        why="IMDSv1 answers simple GET requests, so a server-side request forgery bug can read the instance's AWS credentials.",
        console=(
            "Open EC2 in {region} > Instances > {resource}.",
            "Choose Actions > Instance settings > Modify instance metadata options.",
            "Set IMDSv2 to Required and save. Check that the software on the instance uses a current AWS SDK.",
        ),
        cli="aws ec2 modify-instance-metadata-options --instance-id {resource} --http-tokens required --http-endpoint enabled --region {region}",
        terraform=(
            'resource "aws_instance" "this" {\n'
            "  metadata_options {\n"
            '    http_tokens   = "required"\n'
            '    http_endpoint = "enabled"\n'
            "  }\n}"
        ),
    ),
}


def finding_values(resource, region, account):
    first = resource.split(" ")[0]
    user, _, key = resource.partition(" / ")
    return {
        "resource": resource,
        "region": region or "us-east-1",
        "account": account,
        "group_id": first,
        "user": user,
        "key": key,
    }


def render(template, values):
    """Fills in {resource} and the other names. Other braces, such as JSON, are left alone."""
    if template is None:
        return None
    return PLACEHOLDER.sub(lambda m: values[m.group(1)], template)
