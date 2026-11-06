"""How Misconfigly reaches a customer's AWS account, without any AWS access keys.

1. On Vercel, the request carries a short-lived OIDC token. AWS exchanges it for the MisconfiglyScanner role
   (AssumeRoleWithWebIdentity). Locally, your own AWS CLI profile stands in for that role.
2. The scanner role assumes the customer's MisconfiglyAudit role, which only trusts it, and only with the customer's
   own ExternalId. That role has AWS's read-only SecurityAudit policy.
"""

import re
import secrets

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

AUDIT_ROLE_NAME = "MisconfiglyAudit"
ROLE_ARN = re.compile(r"^arn:aws:iam::(\d{12}):role/(?:[\w+=,.@-]+/)*([\w+=,.@-]{1,64})$")
SESSION_SECONDS = 3600
STS_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=15)
# The web identity exchange needs no signature. Unsigned, it can't pick up credentials from the environment by mistake.
UNSIGNED_STS = STS_CONFIG.merge(Config(signature_version=UNSIGNED))

NOT_SET_UP = "Connecting AWS accounts isn't set up on this server yet."
NO_TOKEN = "Misconfigly couldn't get its own AWS sign-in token. Please try again in a moment."
SCANNER_DENIED = "Misconfigly couldn't sign in to AWS as itself. Please try again later."
WRONG_ROLE = f"The role must be the {AUDIT_ROLE_NAME} role created by the stack. Copy the RoleArn from the stack's Outputs tab."
ROLE_DENIED = (
    "Misconfigly couldn't use this role. Check that the stack finished creating, that you copied the RoleArn from its "
    "Outputs tab, and that it was created with the ExternalId shown on this page."
)
AWS_UNREACHABLE = "AWS didn't respond. Please try again in a moment."


class ConnectionFailed(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def new_external_id():
    return "mcfg-" + secrets.token_hex(16)


def parse_role_arn(role_arn):
    """The account ID in a MisconfiglyAudit role ARN, or ConnectionFailed if it is anything else."""
    match = ROLE_ARN.match(role_arn.strip())
    if not match or match.group(2) != AUDIT_ROLE_NAME:
        raise ConnectionFailed(WRONG_ROLE)
    return match.group(1)


def _session(credentials, region):
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


class AwsAccess:
    def __init__(self, scanner_role_arn="", on_vercel=False, region="us-east-1", sessions=boto3.Session):
        self.scanner_role_arn = scanner_role_arn
        self.on_vercel = on_vercel
        self.region = region
        self._sessions = sessions  # Swapped out in tests.

    @property
    def configured(self):
        return bool(self.scanner_role_arn)

    def scanner_session(self, oidc_token):
        """Misconfigly's own identity: the scanner role on Vercel, or your AWS CLI profile when run locally."""
        if not self.configured:
            raise ConnectionFailed(NOT_SET_UP)
        if not oidc_token:
            if self.on_vercel:
                raise ConnectionFailed(NO_TOKEN)
            return self._sessions(region_name=self.region)
        sts = self._sessions(region_name=self.region).client("sts", config=UNSIGNED_STS)
        try:
            credentials = sts.assume_role_with_web_identity(
                RoleArn=self.scanner_role_arn,
                RoleSessionName="misconfigly-scanner",
                WebIdentityToken=oidc_token,
                DurationSeconds=SESSION_SECONDS,
            )["Credentials"]
        except ClientError as error:
            raise ConnectionFailed(SCANNER_DENIED) from error
        except BotoCoreError as error:
            raise ConnectionFailed(AWS_UNREACHABLE) from error
        return _session(credentials, self.region)

    def customer_session(self, oidc_token, role_arn, external_id, user_id):
        """A session in the customer's account through their audit role. It lasts an hour and is never stored."""
        expected_account = parse_role_arn(role_arn)
        sts = self.scanner_session(oidc_token).client("sts", config=STS_CONFIG)
        try:
            credentials = sts.assume_role(
                RoleArn=role_arn.strip(),
                RoleSessionName=f"misconfigly-{str(user_id)[:8]}",
                ExternalId=external_id,
                DurationSeconds=SESSION_SECONDS,
            )["Credentials"]
            session = _session(credentials, self.region)
            account = session.client("sts", config=STS_CONFIG).get_caller_identity()["Account"]
        except ClientError as error:
            raise ConnectionFailed(ROLE_DENIED) from error
        except BotoCoreError as error:
            raise ConnectionFailed(AWS_UNREACHABLE) from error
        if account != expected_account:
            raise ConnectionFailed(ROLE_DENIED)
        return session
