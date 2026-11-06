import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low")
GLOBAL_REGION = "us-east-1"
MAX_WORKERS = 16
BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "standard"}, connect_timeout=5, read_timeout=30)
DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "AuthFailure",
}


@dataclass(frozen=True)
class Check:
    id: str
    cis: str
    title: str
    service: str
    severity: str
    regional: bool
    run: Callable


@dataclass(frozen=True)
class Result:
    status: str
    resource: str
    detail: str


def passed(resource, detail=""):
    return Result("pass", resource, detail)


def failed(resource, detail):
    return Result("fail", resource, detail)


def unknown(resource, detail):
    """A resource the check couldn't judge, such as a bucket in another account."""
    return Result("error", resource, detail)


@dataclass(frozen=True)
class Finding:
    check_id: str
    status: str
    region: str | None
    resource: str
    detail: str

    @property
    def check(self):
        return CHECKS[self.check_id]


@dataclass
class ScanResult:
    account_id: str
    regions: list[str]
    started_at: datetime
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)


CHECKS: dict[str, Check] = {}


def check(id, cis, title, service, severity, regional=False):
    """Registers a check. It's called as run(ctx) or, when regional, run(ctx, region), and yields Results."""
    if severity not in SEVERITIES:
        raise ValueError(f"Unknown severity {severity}")

    def register(run):
        if id in CHECKS:
            raise ValueError(f"Check {id} is registered twice")
        CHECKS[id] = Check(id, cis, title, service, severity, regional, run)
        return run

    return register


def error_code(error):
    return error.response.get("Error", {}).get("Code", "")


def paginate(client, operation, key, **kwargs):
    if client.can_paginate(operation):
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(key, [])
    else:
        yield from getattr(client, operation)(**kwargs).get(key, [])


class ScanContext:
    """What every check shares in one scan: the session, the clock, boto3 clients and data loaded once."""

    def __init__(self, session, regions, now=None):
        self.session = session
        self.regions = list(regions)
        self.now = now or datetime.now(timezone.utc)
        self._clients = {}
        self._client_lock = threading.Lock()
        self._cache = {}
        self._cache_locks = {}
        self._cache_lock = threading.Lock()

    def client(self, service, region=GLOBAL_REGION):
        key = (service, region)
        # Creating clients from one session isn't thread safe, but using them is.
        with self._client_lock:
            if key not in self._clients:
                self._clients[key] = self.session.client(service, region_name=region, config=BOTO_CONFIG)
            return self._clients[key]

    def cached(self, key, load):
        """load() runs once per scan for each key, even when several checks ask for it at the same time."""
        with self._cache_lock:
            lock = self._cache_locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._cache:
                self._cache[key] = load()
            return self._cache[key]

    @property
    def account_id(self):
        return self.cached("account_id", lambda: self.client("sts").get_caller_identity()["Account"])


def enabled_regions(session):
    ec2 = session.client("ec2", region_name=session.region_name or GLOBAL_REGION, config=BOTO_CONFIG)
    return sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"])


def _run_one(ctx, check, region):
    try:
        results = list(check.run(ctx, region) if check.regional else check.run(ctx))
    except ClientError as error:
        code = error_code(error)
        operation = error.operation_name
        if code in DENIED_CODES:
            detail = f"Misconfigly's role isn't allowed to call {operation}, so this check couldn't run"
        else:
            logger.warning("Check %s failed in %s: %s", check.id, region, error)
            detail = f"AWS returned {code or 'an error'} for {operation}, so this check couldn't run"
        return [Finding(check.id, "error", region, ctx.account_id, detail)]
    except BotoCoreError as error:
        logger.warning("Check %s failed in %s: %s", check.id, region, error)
        return [Finding(check.id, "error", region, ctx.account_id, "AWS couldn't be reached, so this check couldn't run")]
    if not results:
        return [Finding(check.id, "pass", region, ctx.account_id, "Nothing of this kind to check")]
    return [Finding(check.id, r.status, region, r.resource, r.detail) for r in results]


def run_scan(session, regions=None, now=None, only=None):
    """Runs every check (or the ids in `only`) and returns all findings, ordered by check and region."""
    started_at = datetime.now(timezone.utc)
    regions = sorted(regions) if regions else enabled_regions(session)
    ctx = ScanContext(session, regions, now)
    account_id = ctx.account_id
    selected = [c for c in CHECKS.values() if only is None or c.id in only]
    jobs = [(c, r) for c in selected for r in (regions if c.regional else [None])]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        batches = list(pool.map(lambda job: _run_one(ctx, *job), jobs))

    findings = [f for batch in batches for f in batch]
    return ScanResult(account_id, regions, started_at, datetime.now(timezone.utc), findings)
