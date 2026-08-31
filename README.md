# Cloud Security Automation Utilities

A focused Python portfolio demonstrating read-only cloud exposure analysis across AWS accounts. This public repository contains source code and generic examples only; customer data, generated reports, embedded runtimes, and organization-specific configuration are excluded.

## Projects

### AWS ingress exposure scanner

`aws_scan.py` evaluates whether apparently public AWS resources have a real network path to the internet. It correlates security groups, subnets, route tables, internet gateways, transit gateways, load balancers, RDS, and S3 configuration to distinguish direct exposure from configuration-only findings.

### AWS IAM Identity Center login helper

`sso_login.py` performs the AWS IAM Identity Center device-authorization flow with `boto3` and writes a standard local SSO cache entry. No static AWS access keys are required.

## Example

```bash
python sso_login.py \
  --start-url https://example-directory.awsapps.com/start \
  --sso-region us-east-1

python aws_scan.py \
  --sso-fragment example-directory \
  --sso-region us-east-1
```

## Installation

```bash
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## Security boundaries

- The scanner is read-only and should run under a least-privilege assessment role.
- SSO tokens remain in the standard local AWS cache; never commit that directory.
- Generated CSV findings may contain sensitive account and network information and must remain outside the repository.
- Exposure and reachability verdicts require analyst validation before remediation or risk acceptance.

## Portfolio provenance

These utilities are sanitized, generalized versions of automation created to reduce repeated cloud-security assessment work. Organization-specific names, paths, data, and credentials are not included.
