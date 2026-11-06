from ..core import check, failed, paginate, passed

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
ANYWHERE_V4 = "0.0.0.0/0"
ANYWHERE_V6 = "::/0"
TCP = {"6", "tcp"}
ALL = {"-1", "all"}


def _security_groups(ctx, region):
    return ctx.cached(
        ("security_groups", region),
        lambda: list(paginate(ctx.client("ec2", region), "describe_security_groups", "SecurityGroups")),
    )


def _open_ports(protocol, low, high):
    """The admin ports a rule lets in. A rule for all protocols has no port range, so it covers them all."""
    protocol = str(protocol).lower()
    if protocol in ALL:
        return list(ADMIN_PORTS)
    if protocol not in TCP:
        return []
    low = 0 if low is None else low
    high = 65535 if high is None else high
    return [port for port in ADMIN_PORTS if low <= port <= high]


def _describe(ports):
    return " and ".join(f"{ADMIN_PORTS[p]} ({p})" for p in sorted(ports))


def _group_name(group):
    return f"{group['GroupId']} ({group.get('GroupName', '')})"


def _exposed_groups(ctx, region, range_key, cidr_key, anywhere):
    for group in _security_groups(ctx, region):
        ports = set()
        for rule in group.get("IpPermissions", []):
            if any(r.get(cidr_key) == anywhere for r in rule.get(range_key, [])):
                ports.update(_open_ports(rule.get("IpProtocol"), rule.get("FromPort"), rule.get("ToPort")))
        yield group, ports


@check("ec2.nacl_admin_ports", "5.1", "Network ACLs don't let the internet reach SSH or RDP", "VPC", "medium", regional=True)
def nacl_admin_ports(ctx, region):
    for acl in paginate(ctx.client("ec2", region), "describe_network_acls", "NetworkAcls"):
        ports = set()
        # Entries are read lowest rule number first, and the first match wins, so a deny can hide a later allow.
        settled = set()
        for entry in sorted(acl.get("Entries", []), key=lambda e: e["RuleNumber"]):
            if entry.get("Egress") or (entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")) not in (ANYWHERE_V4, ANYWHERE_V6):
                continue
            span = entry.get("PortRange", {})
            covered = set(_open_ports(entry.get("Protocol"), span.get("From"), span.get("To"))) - settled
            if entry.get("RuleAction") == "allow":
                ports |= covered
            settled |= covered
        if ports:
            yield failed(acl["NetworkAclId"], f"Lets anyone on the internet reach {_describe(ports)}")
        else:
            yield passed(acl["NetworkAclId"])


@check("ec2.sg_admin_ports_ipv4", "5.2", "Security groups don't open SSH or RDP to any IPv4 address", "EC2", "high", regional=True)
def sg_admin_ports_ipv4(ctx, region):
    for group, ports in _exposed_groups(ctx, region, "IpRanges", "CidrIp", ANYWHERE_V4):
        if ports:
            yield failed(_group_name(group), f"Opens {_describe(ports)} to 0.0.0.0/0")
        else:
            yield passed(_group_name(group))


@check("ec2.sg_admin_ports_ipv6", "5.3", "Security groups don't open SSH or RDP to any IPv6 address", "EC2", "high", regional=True)
def sg_admin_ports_ipv6(ctx, region):
    for group, ports in _exposed_groups(ctx, region, "Ipv6Ranges", "CidrIpv6", ANYWHERE_V6):
        if ports:
            yield failed(_group_name(group), f"Opens {_describe(ports)} to ::/0")
        else:
            yield passed(_group_name(group))


@check("ec2.default_security_group", "5.4", "Default security groups allow no traffic", "EC2", "medium", regional=True)
def default_security_group(ctx, region):
    for group in _security_groups(ctx, region):
        if group.get("GroupName") != "default":
            continue
        rules = len(group.get("IpPermissions", [])) + len(group.get("IpPermissionsEgress", []))
        if rules:
            yield failed(_group_name(group), f"Has {rules} rule{'' if rules == 1 else 's'}, so anything placed in it by default can talk")
        else:
            yield passed(_group_name(group))


@check("ec2.imdsv2", "5.6", "EC2 instances require IMDSv2", "EC2", "high", regional=True)
def imdsv2(ctx, region):
    for reservation in paginate(ctx.client("ec2", region), "describe_instances", "Reservations"):
        for instance in reservation.get("Instances", []):
            if instance.get("State", {}).get("Name") == "terminated":
                continue
            options = instance.get("MetadataOptions", {})
            if options.get("HttpTokens") == "required" or options.get("HttpEndpoint") == "disabled":
                yield passed(instance["InstanceId"])
            else:
                yield failed(instance["InstanceId"], "The metadata service answers IMDSv1 requests, which SSRF bugs can abuse to steal credentials")
