"""CIS section 4: a CloudWatch alarm with a subscriber for each risky kind of event in the CloudTrail logs."""

import re

from ..core import check, failed, paginate, passed
from .logging import complete_trails

IAM_POLICY_EVENTS = (
    "DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy", "PutRolePolicy",
    "PutUserPolicy", "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion",
    "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy",
    "DetachGroupPolicy",
)  # fmt: skip
TRAIL_EVENTS = ("CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging")


def _normalize(pattern):
    """Filter patterns differ only in spacing and quoting, so compare them without either."""
    return re.sub(r"[\s\"']", "", pattern or "")


def _matches(pattern, terms):
    flat = _normalize(pattern)
    # The lookahead keeps CreatePolicy from matching inside CreatePolicyVersion.
    return all(re.search(re.escape(_normalize(term)) + r"(?![\w])", flat) for term in terms)


def _log_group(arn):
    # arn:aws:logs:REGION:ACCOUNT:log-group:NAME:*
    parts = arn.split(":")
    return parts[3], parts[6]


def _alerting_trail(ctx):
    for trail in complete_trails(ctx):
        if trail.get("CloudWatchLogsLogGroupArn"):
            return trail
    return None


def _has_subscriber(ctx, region, alarm):
    sns = ctx.client("sns", region)
    for action in alarm.get("AlarmActions", []):
        if action.startswith("arn:aws:sns:") and any(
            True for _ in paginate(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=action)
        ):
            return True
    return False


def _watched(ctx, terms):
    """The name of an alarm that fires on log events matching all the terms and notifies someone, if any."""
    trail = _alerting_trail(ctx)
    if trail is None:
        return None, "No trail that covers every region sends its logs to CloudWatch Logs"
    region, group = _log_group(trail["CloudWatchLogsLogGroupArn"])
    logs = ctx.client("logs", region)
    cloudwatch = ctx.client("cloudwatch", region)
    filters = [
        f for f in paginate(logs, "describe_metric_filters", "metricFilters", logGroupName=group)
        if _matches(f.get("filterPattern"), terms)
    ]  # fmt: skip
    if not filters:
        return None, f"No metric filter on {group} picks out these events"
    for metric_filter in filters:
        for metric in metric_filter.get("metricTransformations", []):
            alarms = cloudwatch.describe_alarms_for_metric(
                MetricName=metric["metricName"], Namespace=metric["metricNamespace"]
            ).get("MetricAlarms", [])
            for alarm in alarms:
                if _has_subscriber(ctx, region, alarm):
                    return alarm["AlarmName"], None
    return None, f"The metric filter {filters[0]['filterName']} has no alarm that notifies anyone"


def _alarm_check(ctx, terms):
    alarm, problem = _watched(ctx, terms)
    if alarm:
        yield passed(alarm)
    else:
        yield failed("CloudWatch alarms", problem)


@check("monitoring.unauthorized_calls", "4.1", "An alarm fires on unauthorized API calls", "CloudWatch", "low")
def unauthorized_calls(ctx):
    yield from _alarm_check(ctx, ['$.errorCode="*UnauthorizedOperation"', '$.errorCode="AccessDenied*"'])


@check("monitoring.console_without_mfa", "4.2", "An alarm fires on console sign-ins without MFA", "CloudWatch", "medium")
def console_without_mfa(ctx):
    yield from _alarm_check(ctx, ['$.eventName="ConsoleLogin"', '$.additionalEventData.MFAUsed!="Yes"'])


@check("monitoring.root_usage", "4.3", "An alarm fires when the root account is used", "CloudWatch", "high")
def root_usage(ctx):
    yield from _alarm_check(
        ctx, ['$.userIdentity.type="Root"', "$.userIdentity.invokedBy NOT EXISTS", '$.eventType!="AwsServiceEvent"']
    )


@check("monitoring.iam_policy_changes", "4.4", "An alarm fires on IAM policy changes", "CloudWatch", "medium")
def iam_policy_changes(ctx):
    yield from _alarm_check(ctx, [f"$.eventName={name}" for name in IAM_POLICY_EVENTS])


@check("monitoring.trail_changes", "4.5", "An alarm fires on CloudTrail changes", "CloudWatch", "medium")
def trail_changes(ctx):
    yield from _alarm_check(ctx, [f"$.eventName={name}" for name in TRAIL_EVENTS])
