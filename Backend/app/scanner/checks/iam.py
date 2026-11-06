import json
from datetime import timedelta
from urllib.parse import unquote

from botocore.exceptions import ClientError

from ..core import check, error_code, failed, paginate, passed

ROOT = "Root account"
MIN_PASSWORD_LENGTH = 14
PASSWORD_REUSE = 24
UNUSED_AFTER = timedelta(days=45)
ROTATE_AFTER = timedelta(days=90)
SUPPORT_POLICY = "arn:aws:iam::aws:policy/AWSSupportAccess"


def _summary(ctx):
    return ctx.cached("iam_summary", lambda: ctx.client("iam").get_account_summary()["SummaryMap"])


def _password_policy(ctx):
    def load():
        try:
            return ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as error:
            if error_code(error) == "NoSuchEntity":
                return None
            raise

    return ctx.cached("password_policy", load)


def _users(ctx):
    """Every IAM user with what the checks need: console password, MFA devices, access keys and policies."""

    def load():
        iam = ctx.client("iam")
        users = []
        for user in paginate(iam, "list_users", "Users"):
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
                has_password = True
            except ClientError as error:
                if error_code(error) != "NoSuchEntity":
                    raise
                has_password = False
            keys = []
            for key in paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=name):
                last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
                keys.append({**key, "LastUsedDate": last.get("LastUsedDate")})
            users.append(
                {
                    **user,
                    "HasPassword": has_password,
                    "MFADevices": list(paginate(iam, "list_mfa_devices", "MFADevices", UserName=name)),
                    "AccessKeys": keys,
                    "AttachedPolicies": list(
                        paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)
                    ),
                    "InlinePolicies": list(paginate(iam, "list_user_policies", "PolicyNames", UserName=name)),
                }
            )
        return users

    return ctx.cached("iam_users", load)


def _days(delta):
    return f"{delta.days} day{'' if delta.days == 1 else 's'}"


@check("iam.root_access_keys", "1.4", "The root account has no access keys", "IAM", "critical")
def root_access_keys(ctx):
    if _summary(ctx).get("AccountAccessKeysPresent"):
        yield failed(ROOT, "The root account has an access key. Anyone holding it has full control of the account")
    else:
        yield passed(ROOT)


@check("iam.root_mfa", "1.5", "The root account uses MFA", "IAM", "critical")
def root_mfa(ctx):
    if _summary(ctx).get("AccountMFAEnabled"):
        yield passed(ROOT)
    else:
        yield failed(ROOT, "The root account signs in with only a password")


@check("iam.password_length", "1.8", "Passwords are at least 14 characters", "IAM", "medium")
def password_length(ctx):
    policy = _password_policy(ctx)
    if policy is None:
        yield failed("Password policy", "No password policy is set, so AWS accepts 8 characters")
    elif policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
        yield failed("Password policy", f"The minimum length is {policy.get('MinimumPasswordLength')} characters")
    else:
        yield passed("Password policy", f"The minimum length is {policy['MinimumPasswordLength']} characters")


@check("iam.password_reuse", "1.9", "The last 24 passwords can't be reused", "IAM", "low")
def password_reuse(ctx):
    policy = _password_policy(ctx)
    remembered = (policy or {}).get("PasswordReusePrevention", 0)
    if remembered >= PASSWORD_REUSE:
        yield passed("Password policy", f"The last {remembered} passwords are remembered")
    elif remembered:
        yield failed("Password policy", f"Only the last {remembered} passwords are remembered")
    else:
        yield failed("Password policy", "Users can reuse an old password")


@check("iam.user_mfa", "1.10", "Users with a console password use MFA", "IAM", "high")
def user_mfa(ctx):
    for user in _users(ctx):
        if not user["HasPassword"]:
            continue
        if user["MFADevices"]:
            yield passed(user["UserName"])
        else:
            yield failed(user["UserName"], "Signs in to the console with only a password")


@check("iam.unused_credentials", "1.12", "Credentials unused for 45 days are turned off", "IAM", "medium")
def unused_credentials(ctx):
    for user in _users(ctx):
        name = user["UserName"]
        problems = []
        if user["HasPassword"]:
            since = ctx.now - (user.get("PasswordLastUsed") or user["CreateDate"])
            if since > UNUSED_AFTER:
                problems.append(f"its console password hasn't been used for {_days(since)}")
        for key in user["AccessKeys"]:
            if key["Status"] != "Active":
                continue
            since = ctx.now - (key["LastUsedDate"] or key["CreateDate"])
            if since > UNUSED_AFTER:
                problems.append(f"access key {key['AccessKeyId']} hasn't been used for {_days(since)}")
        if problems:
            yield failed(name, "Still active, but " + " and ".join(problems))
        elif user["HasPassword"] or any(k["Status"] == "Active" for k in user["AccessKeys"]):
            yield passed(name)


@check("iam.one_active_key", "1.13", "Each user has at most one active access key", "IAM", "low")
def one_active_key(ctx):
    for user in _users(ctx):
        active = [k for k in user["AccessKeys"] if k["Status"] == "Active"]
        if len(active) > 1:
            yield failed(user["UserName"], f"Has {len(active)} active access keys")
        elif active:
            yield passed(user["UserName"])


@check("iam.key_rotation", "1.14", "Access keys are rotated every 90 days", "IAM", "medium")
def key_rotation(ctx):
    for user in _users(ctx):
        for key in user["AccessKeys"]:
            if key["Status"] != "Active":
                continue
            resource = f"{user['UserName']} / {key['AccessKeyId']}"
            age = ctx.now - key["CreateDate"]
            if age > ROTATE_AFTER:
                yield failed(resource, f"Created {_days(age)} ago")
            else:
                yield passed(resource)


@check("iam.user_policies", "1.15", "Users get permissions only through groups", "IAM", "low")
def user_policies(ctx):
    for user in _users(ctx):
        direct = [p["PolicyName"] for p in user["AttachedPolicies"]] + user["InlinePolicies"]
        if direct:
            yield failed(user["UserName"], "Has policies attached directly: " + ", ".join(sorted(direct)))
        else:
            yield passed(user["UserName"])


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _allows_everything(document):
    if isinstance(document, str):
        document = json.loads(unquote(document))
    for statement in _as_list(document.get("Statement", [])):
        if (
            statement.get("Effect") == "Allow"
            and "*" in _as_list(statement.get("Action", []))
            and "*" in _as_list(statement.get("Resource", []))
        ):
            return True
    return False


@check("iam.admin_policies", "1.16", "No custom policy grants full admin rights", "IAM", "high")
def admin_policies(ctx):
    iam = ctx.client("iam")
    for policy in paginate(iam, "list_policies", "Policies", Scope="Local", OnlyAttached=True):
        version = iam.get_policy_version(PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])
        if _allows_everything(version["PolicyVersion"]["Document"]):
            yield failed(policy["PolicyName"], 'Allows every action on every resource ("*:*") and is attached')
        else:
            yield passed(policy["PolicyName"])


@check("iam.support_role", "1.17", "A role exists for AWS Support access", "IAM", "low")
def support_role(ctx):
    roles = ctx.client("iam").list_entities_for_policy(PolicyArn=SUPPORT_POLICY, EntityFilter="Role")["PolicyRoles"]
    if roles:
        yield passed("AWSSupportAccess", "Attached to " + ", ".join(r["RoleName"] for r in roles))
    else:
        yield failed("AWSSupportAccess", "No role has the AWSSupportAccess policy, so nobody can open support cases without broad rights")


@check("iam.expired_certificates", "1.19", "Expired server certificates are removed", "IAM", "low")
def expired_certificates(ctx):
    for cert in paginate(ctx.client("iam"), "list_server_certificates", "ServerCertificateMetadataList"):
        name = cert["ServerCertificateName"]
        if cert["Expiration"] < ctx.now:
            yield failed(name, f"Expired on {cert['Expiration']:%Y-%m-%d}")
        else:
            yield passed(name, f"Expires on {cert['Expiration']:%Y-%m-%d}")
