#!/usr/bin/env python3
"""
AWS ingress exposure scanner WITH route validation (read-only).

Two-phase per account/region:
  1. Find resources whose CONFIG exposes them (open SG, public RDS,
     internet-facing LB, public S3).
  2. Validate the NETWORK PATH: does the resource's subnet actually route
     0.0.0.0/0 to an Internet Gateway (direct path = TIC bypass candidate),
     to a Transit Gateway (likely central inspection), or nowhere
     (config-public but not internet-reachable = false positive for bypass)?

ticConformant verdicts:
  non_conformant_direct_igw     - direct IGW path; bypass candidate
  review_tgw_path               - routed to a TGW; conformant IF that TGW
                                  is your inspection path (see --inspection-tgw)
  conformant_inspected          - routed to a known inspection TGW
  conformant_no_path            - config-public but no internet route
  non_conformant_public_endpoint- public S3 bucket (public policy/ACL)
  unattached                    - open SG attached to no live ENI

routeValidated = True whenever the path was actually resolved.

Prereqs: pip install boto3 ; run sso_login.py first.

Usage:
  py aws_scan.py --sso-fragment example-directory --sso-region us-gov-west-1
  py aws_scan.py --sso-fragment example-directory --sso-region us-gov-west-1 \
      --inspection-tgw tgw-0abc123,tgw-0def456
"""

import argparse
import csv
import glob
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

BOTO_CFG = Config(retries={"max_attempts": 5, "mode": "adaptive"},
                  connect_timeout=15, read_timeout=30)

CSV_COLUMNS = [
    "resourceName", "exposureType", "address", "fqdn", "filterVerdict",
    "exposureConfidence", "skuInfo", "resourceType", "resourceGroup",
    "subscriptionId", "location", "resourceId", "routeValidated",
    "ticConformant", "ingressPoint", "bypassReason", "discoveredUtc",
]

INSPECTION_TGWS = set()   # populated from --inspection-tgw

print_lock = threading.Lock()
def log(msg):
    with print_lock:
        print(msg, flush=True)


# ----------------------------- token / sessions -----------------------------

def load_token(fragment):
    cache_dir = os.path.expanduser("~/.aws/sso/cache")
    best = None
    for path in glob.glob(os.path.join(cache_dir, "*.json")):
        try:
            with open(path) as f:
                d = json.load(f)
        except Exception:
            continue
        if "accessToken" not in d or "expiresAt" not in d:
            continue
        if fragment not in d.get("startUrl", ""):
            continue
        exp = datetime.fromisoformat(d["expiresAt"].replace("Z", "+00:00"))
        if exp <= datetime.now(timezone.utc):
            continue
        if best is None or exp > best[0]:
            best = (exp, d["accessToken"])
    if not best:
        raise RuntimeError("No valid token for '%s'. Re-run sso_login.py." % fragment)
    return best[1]


def list_accounts(sso, token):
    out = []
    for page in sso.get_paginator("list_accounts").paginate(accessToken=token):
        out.extend(page["accountList"])
    return out


def pick_role(sso, token, account_id, role_suffix):
    for page in sso.get_paginator("list_account_roles").paginate(
        accessToken=token, accountId=account_id
    ):
        roles = [r["roleName"] for r in page["roleList"]]
        if role_suffix:
            for r in roles:
                if r.endswith(role_suffix):
                    return r
        if roles:
            return roles[0]
    return None


def session_for(sso, token, account_id, role_name, region):
    creds = sso.get_role_credentials(
        roleName=role_name, accountId=account_id, accessToken=token
    )["roleCredentials"]
    return boto3.Session(
        aws_access_key_id=creds["accessKeyId"],
        aws_secret_access_key=creds["secretAccessKey"],
        aws_session_token=creds["sessionToken"],
        region_name=region,
    )


# --------------------------- network path map -------------------------------

def build_network_map(sess, region):
    """Per account/region: subnet -> default-route target, SG -> attached ENIs."""
    ec2 = sess.client("ec2", region_name=region, config=BOTO_CFG)
    nm = {"subnet_default": {}, "subnet_vpc": {}, "sg_enis": {}, "vpc_igw": set()}

    # Internet gateways -> which VPCs have one
    try:
        for page in ec2.get_paginator("describe_internet_gateways").paginate():
            for igw in page["InternetGateways"]:
                for att in igw.get("Attachments", []):
                    if att.get("VpcId"):
                        nm["vpc_igw"].add(att["VpcId"])
    except (ClientError, EndpointConnectionError):
        return nm

    # Route tables -> default-route target per RT; associations
    main_rt_by_vpc, explicit, rt_default = {}, {}, {}
    try:
        rts = []
        for page in ec2.get_paginator("describe_route_tables").paginate():
            rts.extend(page["RouteTables"])
    except (ClientError, EndpointConnectionError):
        rts = []
    for rt in rts:
        rid = rt["RouteTableId"]
        target = ("none", None)
        for r in rt.get("Routes", []):
            dest = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock")
            if dest in ("0.0.0.0/0", "::/0"):
                gw = r.get("GatewayId", "") or ""
                if gw.startswith("igw-"):
                    target = ("igw", gw)
                elif r.get("TransitGatewayId"):
                    target = ("tgw", r["TransitGatewayId"])
                elif r.get("NatGatewayId"):
                    target = ("nat", r["NatGatewayId"])
                elif gw.startswith("vgw-"):
                    target = ("vgw", gw)
        rt_default[rid] = target
        for assoc in rt.get("Associations", []):
            if assoc.get("Main"):
                main_rt_by_vpc[rt["VpcId"]] = rid
            elif assoc.get("SubnetId"):
                explicit[assoc["SubnetId"]] = rid

    # Subnets -> resolved default route (explicit RT else VPC main RT)
    try:
        for page in ec2.get_paginator("describe_subnets").paginate():
            for sn in page["Subnets"]:
                sid, vpc = sn["SubnetId"], sn["VpcId"]
                nm["subnet_vpc"][sid] = vpc
                rid = explicit.get(sid) or main_rt_by_vpc.get(vpc)
                nm["subnet_default"][sid] = rt_default.get(rid, ("none", None))
    except (ClientError, EndpointConnectionError):
        pass

    # ENIs -> map SG to attached interfaces + whether each has a public IP
    try:
        for page in ec2.get_paginator("describe_network_interfaces").paginate():
            for eni in page["NetworkInterfaces"]:
                assoc = eni.get("Association") or {}
                pub_ip = assoc.get("PublicIp")
                info = {
                    "public_ip": pub_ip,
                    "private_ip": eni.get("PrivateIpAddress"),
                    "subnet": eni.get("SubnetId"),
                    "eni_id": eni.get("NetworkInterfaceId"),
                    "instance_id": (eni.get("Attachment") or {}).get("InstanceId"),
                    "public_dns": assoc.get("PublicDnsName"),
                }
                for g in eni.get("Groups", []):
                    nm["sg_enis"].setdefault(g["GroupId"], []).append(info)
    except (ClientError, EndpointConnectionError):
        pass

    return nm


def classify_subnet(nm, subnet_id):
    """Return ticConformant verdict for a subnet's internet path."""
    target, gwid = nm["subnet_default"].get(subnet_id, ("none", None))
    if target == "igw":
        return "non_conformant_direct_igw", gwid
    if target == "tgw":
        if gwid in INSPECTION_TGWS:
            return "conformant_inspected", gwid
        return "review_tgw_path", gwid
    return "conformant_no_path", None


def worst_of(verdicts):
    """Pick the most severe verdict across multiple subnets."""
    order = ["non_conformant_direct_igw", "review_tgw_path",
             "conformant_inspected", "conformant_no_path"]
    for v in order:
        if v in verdicts:
            return v
    return "conformant_no_path"


# ------------------------------- row builder --------------------------------

def row(name, exposure_type, address, fqdn, verdict, confidence, sku,
        rtype, account_name, account_id, region, resource_id,
        route_validated, tic_conformant, ingress_point="", bypass_reason=""):
    return {
        "resourceName": name,
        "exposureType": exposure_type,
        "address": address or "",
        "fqdn": fqdn or "",
        "filterVerdict": verdict,
        "exposureConfidence": confidence,
        "skuInfo": sku or "",
        "resourceType": rtype,
        "resourceGroup": account_name,
        "subscriptionId": account_id,
        "location": region,
        "resourceId": resource_id,
        "routeValidated": route_validated,
        "ticConformant": tic_conformant,
        "ingressPoint": ingress_point,
        "bypassReason": bypass_reason,
        "discoveredUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ------------------------------ exposure checks ------------------------------

def check_s3(sess, account_name, account_id):
    findings = []
    s3 = sess.client("s3", config=BOTO_CFG)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        log(f"  [s3] {account_id} list_buckets: {e.response['Error']['Code']}")
        return findings

    for b in buckets:
        name = b["Name"]
        public, confidence, reasons = False, "low", []
        try:
            bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all([bpa.get("BlockPublicAcls"), bpa.get("IgnorePublicAcls"),
                        bpa.get("BlockPublicPolicy"), bpa.get("RestrictPublicBuckets")]):
                public, _ = True, reasons.append("BPA_incomplete")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                public, _ = True, reasons.append("no_BPA")
        try:
            if s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"].get("IsPublic"):
                public, confidence = True, "high"
                reasons.append("public_policy")
        except ClientError:
            pass
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            region = loc or "us-east-1"
        except ClientError:
            region = "unknown"

        if public:
            if confidence != "high":
                confidence = "medium"
            reason = f"S3 public service; {'/'.join(reasons)}"
            findings.append(row(
                name, "PaaS_PublicEndpoint", None, f"{name}.s3.amazonaws.com",
                "open", confidence, ";".join(reasons), "aws.s3/bucket",
                account_name, account_id, region, f"arn:aws:s3:::{name}",
                True, "non_conformant_public_endpoint",
                ingress_point=f"https://{name}.s3.amazonaws.com",
                bypass_reason=reason,
            ))
    return findings


def check_security_groups(sess, nm, account_name, account_id, region):
    findings = []
    ec2 = sess.client("ec2", region_name=region, config=BOTO_CFG)
    try:
        pages = list(ec2.get_paginator("describe_security_groups").paginate())
    except (ClientError, EndpointConnectionError):
        return findings

    for page in pages:
        for sg in page["SecurityGroups"]:
            open_ports = []
            for perm in sg.get("IpPermissions", []):
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) \
                   or any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
                    proto = perm.get("IpProtocol", "-1")
                    open_ports.append(f"{proto}:{perm.get('FromPort','all')}-{perm.get('ToPort','all')}")
            if not open_ports:
                continue

            sgid = sg["GroupId"]
            enis = nm["sg_enis"].get(sgid, [])
            ports = ";".join(open_ports)
            if not enis:
                findings.append(row(
                    sg.get("GroupName", sgid), "SecurityGroup_OpenIngress",
                    None, None, "open", "low", ports,
                    "aws.ec2/securitygroup", account_name, account_id, region,
                    sgid, True, "unattached",
                    ingress_point=ports,
                    bypass_reason="0.0.0.0/0 ingress but SG not attached to any live ENI",
                ))
                continue

            # Validate: attached to a public-IP ENI in an internet-routed subnet?
            verdicts, public_hit, path_gw = [], False, None
            pub_ip, pub_dns, hit_eni, hit_instance = None, None, None, None
            for eni in enis:
                v, gw = classify_subnet(nm, eni["subnet"])
                verdicts.append(v)
                if v.startswith("non_conformant_direct") or v == "review_tgw_path":
                    path_gw = path_gw or gw
                if eni.get("public_ip") and v.startswith("non_conformant_direct"):
                    public_hit = True
                    pub_ip = pub_ip or eni.get("public_ip")
                    pub_dns = pub_dns or eni.get("public_dns")
                    hit_eni = hit_eni or eni.get("eni_id")
                    hit_instance = hit_instance or eni.get("instance_id")
            verdict = worst_of(verdicts)
            conf = "high" if public_hit else (
                "medium" if verdict.startswith("non_conformant") or verdict == "review_tgw_path"
                else "low")
            # address = public IP if we found one; fqdn = public DNS
            addr = pub_ip
            fqdn = pub_dns
            ipoint = f"{pub_ip} [{ports}]" if pub_ip else ports
            if verdict == "non_conformant_direct_igw":
                who = hit_instance or hit_eni or "ENI"
                reason = f"0.0.0.0/0 -> SG -> {who}(public {pub_ip or 'ip'}) -> subnet -> {path_gw or 'igw'}"
            elif verdict == "review_tgw_path":
                reason = f"0.0.0.0/0 -> SG -> ENI -> subnet -> {path_gw or 'tgw'} (confirm inspection)"
            elif verdict == "conformant_inspected":
                reason = f"0.0.0.0/0 -> SG -> subnet -> {path_gw} (inspected TGW)"
            else:
                reason = "0.0.0.0/0 ingress but subnet has no internet route"
            findings.append(row(
                sg.get("GroupName", sgid), "SecurityGroup_OpenIngress",
                addr, fqdn, "open", conf, ports,
                "aws.ec2/securitygroup", account_name, account_id, region,
                sgid, True, verdict,
                ingress_point=ipoint, bypass_reason=reason,
            ))
    return findings


def check_rds(sess, nm, account_name, account_id, region):
    findings = []
    rds = sess.client("rds", region_name=region, config=BOTO_CFG)
    try:
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                if not db.get("PubliclyAccessible"):
                    continue
                subnets = [s["SubnetIdentifier"]
                           for s in (db.get("DBSubnetGroup", {}) or {}).get("Subnets", [])]
                pairs = [classify_subnet(nm, s) for s in subnets] or [("conformant_no_path", None)]
                verdict = worst_of([p[0] for p in pairs])
                gw = next((g for v, g in pairs if g), None)
                conf = "high" if verdict == "non_conformant_direct_igw" else (
                    "medium" if verdict == "review_tgw_path" else "low")
                ep = db.get("Endpoint", {}) or {}
                addr, port = ep.get("Address"), ep.get("Port")
                ipoint = f"{addr}:{port}" if addr else db["DBInstanceIdentifier"]
                if verdict == "non_conformant_direct_igw":
                    reason = f"PubliclyAccessible=true -> subnet -> {gw or 'igw'}"
                elif verdict == "review_tgw_path":
                    reason = f"PubliclyAccessible=true -> subnet -> {gw or 'tgw'} (confirm inspection)"
                else:
                    reason = "PubliclyAccessible=true but subnet has no internet route"
                findings.append(row(
                    db["DBInstanceIdentifier"], "PaaS_PublicEndpoint", None,
                    addr, "open", conf, db.get("DBInstanceClass", ""),
                    "aws.rds/dbinstance", account_name, account_id, region,
                    db.get("DBInstanceArn", db["DBInstanceIdentifier"]),
                    True, verdict, ingress_point=ipoint, bypass_reason=reason,
                ))
    except (ClientError, EndpointConnectionError):
        pass
    return findings


def check_elb(sess, nm, account_name, account_id, region):
    findings = []
    elbv2 = sess.client("elbv2", region_name=region, config=BOTO_CFG)
    try:
        for page in elbv2.get_paginator("describe_load_balancers").paginate():
            for lb in page["LoadBalancers"]:
                if lb.get("Scheme") != "internet-facing":
                    continue
                subnets = [az.get("SubnetId") for az in lb.get("AvailabilityZones", [])]
                pairs = [classify_subnet(nm, s) for s in subnets if s] or [("non_conformant_direct_igw", None)]
                verdict = worst_of([p[0] for p in pairs])
                gw = next((g for v, g in pairs if g), None)
                conf = "high" if verdict == "non_conformant_direct_igw" else "medium"
                dns = lb.get("DNSName")
                reason = f"internet-facing scheme -> subnet -> {gw or 'igw'}"
                findings.append(row(
                    lb["LoadBalancerName"], "PublicFrontend_LB_AppGw", None,
                    dns, "open", conf, lb.get("Type", ""),
                    "aws.elasticloadbalancingv2/loadbalancer", account_name,
                    account_id, region, lb["LoadBalancerArn"], True, verdict,
                    ingress_point=dns, bypass_reason=reason,
                ))
    except (ClientError, EndpointConnectionError):
        pass
    elb = sess.client("elb", region_name=region, config=BOTO_CFG)
    try:
        for page in elb.get_paginator("describe_load_balancers").paginate():
            for lb in page["LoadBalancerDescriptions"]:
                if lb.get("Scheme") != "internet-facing":
                    continue
                subnets = lb.get("Subnets", [])
                pairs = [classify_subnet(nm, s) for s in subnets] or [("non_conformant_direct_igw", None)]
                verdict = worst_of([p[0] for p in pairs])
                gw = next((g for v, g in pairs if g), None)
                conf = "high" if verdict == "non_conformant_direct_igw" else "medium"
                dns = lb.get("DNSName")
                reason = f"internet-facing scheme -> subnet -> {gw or 'igw'}"
                findings.append(row(
                    lb["LoadBalancerName"], "PublicFrontend_LB_AppGw", None,
                    dns, "open", conf, "classic",
                    "aws.elasticloadbalancing/loadbalancer", account_name,
                    account_id, region, lb["LoadBalancerName"], True, verdict,
                    ingress_point=dns, bypass_reason=reason,
                ))
    except (ClientError, EndpointConnectionError):
        pass
    return findings


# ------------------------------ per-account job -----------------------------

def scan_account(sso_region, token, account, role_suffix, regions):
    account_id, account_name = account["accountId"], account["accountName"]
    sso = boto3.client("sso", region_name=sso_region, config=BOTO_CFG)
    findings = []
    try:
        role = pick_role(sso, token, account_id, role_suffix)
        if not role:
            log(f"  [skip] {account_name} ({account_id}): no assumable role")
            return findings

        sess0 = session_for(sso, token, account_id, role, regions[0])
        findings += check_s3(sess0, account_name, account_id)

        for region in regions:
            rsess = session_for(sso, token, account_id, role, region)
            nm = build_network_map(rsess, region)
            findings += check_security_groups(rsess, nm, account_name, account_id, region)
            findings += check_rds(rsess, nm, account_name, account_id, region)
            findings += check_elb(rsess, nm, account_name, account_id, region)

        bypass = sum(1 for f in findings if f["ticConformant"].startswith("non_conformant"))
        log(f"  [done] {account_name} ({account_id}): {len(findings)} findings, {bypass} non-conformant")
    except ClientError as e:
        log(f"  [err ] {account_name} ({account_id}): {e.response['Error']['Code']}")
    except Exception as e:
        log(f"  [err ] {account_name} ({account_id}): {type(e).__name__}: {e}")
    return findings


# ----------------------------------- main -----------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sso-fragment", required=True)
    ap.add_argument("--sso-region", required=True)
    ap.add_argument("--regions", default=None)
    ap.add_argument("--role-suffix", default="-prj-ro")
    ap.add_argument("--inspection-tgw", default="",
                    help="comma list of TGW ids that ARE your TIC inspection path")
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    global INSPECTION_TGWS
    INSPECTION_TGWS = {t.strip() for t in args.inspection_tgw.split(",") if t.strip()}

    if args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    elif args.sso_region.startswith("us-gov"):
        regions = ["us-gov-west-1", "us-gov-east-1"]
    else:
        regions = ["us-east-1", "us-west-2"]

    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    out = args.out or f"aws_ingress_candidates_{args.sso_fragment}_{ts}.csv"

    log(f"Loading token for '{args.sso_fragment}'...")
    token = load_token(args.sso_fragment)
    if INSPECTION_TGWS:
        log(f"Treating as inspection TGWs: {sorted(INSPECTION_TGWS)}")
    sso = boto3.client("sso", region_name=args.sso_region, config=BOTO_CFG)
    accounts = list_accounts(sso, token)
    log(f"Accounts: {len(accounts)}  | regions: {regions}\n")

    all_findings = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(scan_account, args.sso_region, token, a,
                             args.role_suffix, regions) for a in accounts]
        for fut in as_completed(futures):
            all_findings.extend(fut.result())

    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(all_findings)

    log(f"\nTotal findings: {len(all_findings)}")
    log(f"CSV written: {out}")

    by_verdict = {}
    for r in all_findings:
        by_verdict[r["ticConformant"]] = by_verdict.get(r["ticConformant"], 0) + 1
    log("\nBy TIC verdict:")
    for k, v in sorted(by_verdict.items(), key=lambda kv: -kv[1]):
        log(f"  {v:>5}  {k}")


if __name__ == "__main__":
    main()