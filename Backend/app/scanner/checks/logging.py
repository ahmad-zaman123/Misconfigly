from botocore.exceptions import ClientError

from ..core import check, error_code, failed, paginate, passed, unknown


def trails(ctx):
    """Every trail in the scanned regions, with its status and whether it records all management events."""

    def load():
        # Shadow trails are included so an organization trail run from another account still counts.
        unique = {}
        for region in ctx.regions:
            for trail in ctx.client("cloudtrail", region).describe_trails(includeShadowTrails=True).get("trailList", []):
                unique.setdefault(trail["TrailARN"], trail)
        found = []
        for arn, trail in sorted(unique.items()):
            region = trail.get("HomeRegion") or ctx.regions[0]
            client = ctx.client("cloudtrail", region)
            status = client.get_trail_status(Name=arn)
            selectors = client.get_event_selectors(TrailName=arn)
            found.append(
                {
                    **trail,
                    "Region": region,
                    "IsLogging": status.get("IsLogging", False),
                    "AllManagementEvents": _all_management_events(selectors),
                }
            )
        return found

    return ctx.cached("cloudtrail_trails", load)


def _all_management_events(selectors):
    for selector in selectors.get("EventSelectors", []):
        if selector.get("IncludeManagementEvents") and selector.get("ReadWriteType") == "All":
            return True
    for selector in selectors.get("AdvancedEventSelectors", []):
        fields = {f["Field"]: f for f in selector.get("FieldSelectors", [])}
        category = fields.get("eventCategory", {}).get("Equals", [])
        # A readOnly filter means only reads or only writes are kept.
        if "Management" in category and "readOnly" not in fields:
            return True
    return False


def complete_trails(ctx):
    """Trails that log every region and every management event, and are switched on."""
    return [t for t in trails(ctx) if t.get("IsMultiRegionTrail") and t["IsLogging"] and t["AllManagementEvents"]]


@check("cloudtrail.all_regions", "3.1", "CloudTrail records every region", "CloudTrail", "critical")
def all_regions(ctx):
    complete = complete_trails(ctx)
    if complete:
        yield passed(complete[0]["Name"], "Logs management events in every region")
        return
    if not trails(ctx):
        yield failed("CloudTrail", "There is no trail, so API activity in this account isn't recorded")
        return
    for trail in trails(ctx):
        gaps = []
        if not trail.get("IsMultiRegionTrail"):
            gaps.append(f"covers only {trail['Region']}")
        if not trail["IsLogging"]:
            gaps.append("is switched off")
        if not trail["AllManagementEvents"]:
            gaps.append("doesn't record all management events")
        yield failed(trail["Name"], "This trail " + ", ".join(gaps))


@check("cloudtrail.log_validation", "3.2", "CloudTrail log file validation is on", "CloudTrail", "medium")
def log_validation(ctx):
    for trail in trails(ctx):
        if trail.get("LogFileValidationEnabled"):
            yield passed(trail["Name"])
        else:
            yield failed(trail["Name"], "Changed or deleted log files couldn't be detected")


@check("config.recorder", "3.3", "AWS Config is recording", "Config", "medium", regional=True)
def config_recorder(ctx, region):
    client = ctx.client("config", region)
    recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
    statuses = {
        s["name"]: s for s in client.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    }
    for recorder in recorders:
        group = recorder.get("recordingGroup", {})
        if statuses.get(recorder["name"], {}).get("recording") and group.get("allSupported"):
            yield passed(recorder["name"])
            return
    if recorders:
        yield failed(recorders[0]["name"], "The recorder is stopped or doesn't record every resource type")
    else:
        yield failed("AWS Config", "Config isn't set up, so there is no history of resource changes")


@check("cloudtrail.bucket_logging", "3.4", "The CloudTrail bucket logs who reads it", "CloudTrail", "low")
def bucket_logging(ctx):
    s3 = ctx.client("s3")
    for name in sorted({t["S3BucketName"] for t in trails(ctx) if t.get("S3BucketName")}):
        try:
            setting = s3.get_bucket_logging(Bucket=name)
        except ClientError as error:
            if error_code(error) in {"NoSuchBucket", "AccessDenied"}:
                yield unknown(name, "This bucket is missing or in another account, so it couldn't be checked")
                continue
            raise
        if setting.get("LoggingEnabled"):
            yield passed(name)
        else:
            yield failed(name, "Server access logging is off, so reads of the audit logs aren't recorded")


@check("cloudtrail.kms", "3.5", "CloudTrail logs are encrypted with KMS", "CloudTrail", "medium")
def trail_kms(ctx):
    for trail in trails(ctx):
        if trail.get("KmsKeyId"):
            yield passed(trail["Name"])
        else:
            yield failed(trail["Name"], "Logs use S3's default encryption, not a KMS key you control")


@check("kms.rotation", "3.6", "Customer KMS keys rotate every year", "KMS", "medium", regional=True)
def kms_rotation(ctx, region):
    kms = ctx.client("kms", region)
    for key in paginate(kms, "list_keys", "Keys"):
        meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
        if (
            meta.get("KeyManager") != "CUSTOMER"
            or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"
            or meta.get("KeyState") != "Enabled"
            or meta.get("Origin", "AWS_KMS") != "AWS_KMS"
        ):
            continue
        if kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]:
            yield passed(key["KeyId"])
        else:
            yield failed(key["KeyId"], "Automatic rotation is off")


@check("vpc.flow_logs", "3.7", "VPC flow logs are on", "VPC", "medium", regional=True)
def flow_logs(ctx, region):
    ec2 = ctx.client("ec2", region)
    logged = {f["ResourceId"] for f in paginate(ec2, "describe_flow_logs", "FlowLogs")}
    for vpc in paginate(ec2, "describe_vpcs", "Vpcs"):
        if vpc["VpcId"] in logged:
            yield passed(vpc["VpcId"])
        else:
            yield failed(vpc["VpcId"], "Network traffic in this VPC isn't logged")
