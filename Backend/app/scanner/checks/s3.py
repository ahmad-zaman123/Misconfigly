import json

from botocore.exceptions import ClientError

from ..core import check, error_code, failed, passed, unknown

BLOCK_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "everyone",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "any AWS account",
}
NOT_FOUND = {"NoSuchBucket", "AccessDenied", "AllAccessDisabled"}


def _buckets(ctx):
    return ctx.cached("s3_buckets", lambda: [b["Name"] for b in ctx.client("s3").list_buckets().get("Buckets", [])])


def _optional(call, missing_code, **kwargs):
    try:
        return call(**kwargs)
    except ClientError as error:
        if error_code(error) == missing_code:
            return None
        raise


def _account_block(ctx):
    def load():
        found = _optional(
            ctx.client("s3control").get_public_access_block,
            "NoSuchPublicAccessBlockConfiguration",
            AccountId=ctx.account_id,
        )
        return found["PublicAccessBlockConfiguration"] if found else {}

    return ctx.cached("s3_account_block", load)


def _bucket_block(ctx, bucket):
    found = _optional(ctx.client("s3").get_public_access_block, "NoSuchPublicAccessBlockConfiguration", Bucket=bucket)
    return found["PublicAccessBlockConfiguration"] if found else {}


def _policy(ctx, bucket):
    found = _optional(ctx.client("s3").get_bucket_policy, "NoSuchBucketPolicy", Bucket=bucket)
    return json.loads(found["Policy"]) if found else None


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _all_on(settings):
    return all(settings.get(name) for name in BLOCK_SETTINGS)


def _effective_block(ctx, bucket):
    """A setting is on when either the account or the bucket turns it on."""
    account, own = _account_block(ctx), _bucket_block(ctx, bucket)
    return {name: bool(account.get(name) or own.get(name)) for name in BLOCK_SETTINGS}


def _denies_plain_http(policy):
    for statement in _as_list((policy or {}).get("Statement", [])):
        if statement.get("Effect") != "Deny":
            continue
        actions = _as_list(statement.get("Action", []))
        if not ({"s3:*", "*"} & set(actions)):
            continue
        secure = statement.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
        if str(secure).lower() == "false":
            return True
    return False


def _public_principal(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return "*" in _as_list(principal.get("AWS", []))
    return False


def _public_grants(policy):
    """Allow statements open to anyone with no condition to narrow them down."""
    return [
        s
        for s in _as_list((policy or {}).get("Statement", []))
        if s.get("Effect") == "Allow" and _public_principal(s.get("Principal")) and not s.get("Condition")
    ]


@check("s3.account_public_access_block", "2.1.4", "Block Public Access is on for the whole account", "S3", "high")
def account_public_access_block(ctx):
    settings = _account_block(ctx)
    if _all_on(settings):
        yield passed("Account")
    else:
        off = [name for name in BLOCK_SETTINGS if not settings.get(name)]
        yield failed("Account", "Off at account level: " + ", ".join(off))


@check("s3.bucket_public_access_block", "2.1.4", "Every bucket blocks public access", "S3", "medium")
def bucket_public_access_block(ctx):
    covered = _all_on(_account_block(ctx))
    for bucket in _buckets(ctx):
        if covered:
            yield passed(bucket, "Covered by the account setting")
            continue
        try:
            settings = _bucket_block(ctx, bucket)
        except ClientError as error:
            if error_code(error) in NOT_FOUND:
                yield unknown(bucket, "The bucket's settings couldn't be read")
                continue
            raise
        if _all_on(settings):
            yield passed(bucket)
        else:
            off = [name for name in BLOCK_SETTINGS if not settings.get(name)]
            yield failed(bucket, "Off for this bucket: " + ", ".join(off))


@check("s3.public_buckets", "2.1.4", "No bucket is open to the public", "S3", "critical")
def public_buckets(ctx):
    s3 = ctx.client("s3")
    for bucket in _buckets(ctx):
        block = _effective_block(ctx, bucket)
        reasons = []
        if not (block["BlockPublicPolicy"] or block["RestrictPublicBuckets"]):
            for statement in _public_grants(_policy(ctx, bucket)):
                actions = ", ".join(_as_list(statement.get("Action", [])))
                reasons.append(f"its bucket policy allows {actions} to anyone")
        if not block["IgnorePublicAcls"]:
            for grant in s3.get_bucket_acl(Bucket=bucket).get("Grants", []):
                who = PUBLIC_GROUPS.get(grant.get("Grantee", {}).get("URI"))
                if who:
                    reasons.append(f"its ACL gives {who} {grant['Permission']}")
        if reasons:
            yield failed(bucket, "Public: " + "; ".join(reasons))
        else:
            yield passed(bucket)


@check("s3.https_only", "2.1.1", "Buckets refuse plain HTTP requests", "S3", "medium")
def https_only(ctx):
    for bucket in _buckets(ctx):
        if _denies_plain_http(_policy(ctx, bucket)):
            yield passed(bucket)
        else:
            yield failed(bucket, "The bucket policy doesn't deny requests made without TLS (aws:SecureTransport)")
