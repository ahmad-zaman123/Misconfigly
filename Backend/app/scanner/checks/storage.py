from ..core import check, failed, paginate, passed


def _databases(ctx, region):
    return ctx.cached(
        ("rds_instances", region),
        lambda: list(paginate(ctx.client("rds", region), "describe_db_instances", "DBInstances")),
    )


@check("ec2.ebs_default_encryption", "2.2.1", "New EBS volumes are encrypted by default", "EC2", "medium", regional=True)
def ebs_default_encryption(ctx, region):
    if ctx.client("ec2", region).get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        yield passed("EBS default encryption")
    else:
        yield failed("EBS default encryption", "New volumes in this region are created unencrypted unless someone asks")


@check("rds.encryption", "2.3.1", "RDS databases are encrypted at rest", "RDS", "high", regional=True)
def rds_encryption(ctx, region):
    for db in _databases(ctx, region):
        if db.get("StorageEncrypted"):
            yield passed(db["DBInstanceIdentifier"])
        else:
            yield failed(db["DBInstanceIdentifier"], "Storage and snapshots are unencrypted")


@check("rds.minor_upgrades", "2.3.2", "RDS databases get minor version upgrades", "RDS", "low", regional=True)
def rds_minor_upgrades(ctx, region):
    for db in _databases(ctx, region):
        if db.get("AutoMinorVersionUpgrade"):
            yield passed(db["DBInstanceIdentifier"])
        else:
            yield failed(db["DBInstanceIdentifier"], "Security patches in minor versions aren't applied automatically")


@check("rds.public", "2.3.3", "RDS databases aren't publicly accessible", "RDS", "critical", regional=True)
def rds_public(ctx, region):
    for db in _databases(ctx, region):
        if db.get("PubliclyAccessible"):
            yield failed(db["DBInstanceIdentifier"], "Has a public endpoint that the internet can try to connect to")
        else:
            yield passed(db["DBInstanceIdentifier"])
