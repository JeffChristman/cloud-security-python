# Cloud Security Automation Utilities

A focused Python portfolio demonstrating read-only cloud exposure analysis and local security-report quality automation. The public version contains source code only and uses generic examples; customer data, generated reports, embedded runtimes, and organization-specific configuration are excluded.

## Projects

### AWS ingress exposure scanner

`aws_scan.py` evaluates whether apparently public AWS resources have a real network path to the internet. It correlates security groups, subnets, route tables, internet gateways, transit gateways, load balancers, RDS, and S3 configuration to separate direct exposure from scanner false positives.

`sso_login.py` performs the AWS IAM Identity Center device-authorization flow with `boto3` and writes a standard local SSO cache entry. No static AWS access keys are required.

Example:

```bash
python sso_login.py \
  --start-url https://example-directory.awsapps.com/start \
  --sso-region us-east-1

python aws_scan.py \
  --sso-fragment example-directory \
  --sso-region us-east-1
```

### Security-report normalizer and linter

`ReportNormalization/system_report_normalizer_v8.py` normalizes analyst-authored Word findings into a consistent field order and formatting model, ensures required summary tables exist, and produces QA results.

`ReportNormalization/normalizer_app.py` provides a local browser interface for the same workflow. Processing stays on the user's machine.

`report_linter.py` reviews Word reports without modifying the source document and produces a defect report or CSV for analyst correction.

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

- The AWS scanner is read-only and should run under a least-privilege assessment role.
- SSO tokens remain in the standard local AWS cache; never commit that directory.
- Report processing is local. Source reports and generated outputs may contain sensitive system information and must remain outside the repository.
- Findings and reachability verdicts require analyst validation before remediation or risk acceptance.

## Portfolio provenance

These utilities are sanitized, generalized versions of automation created to reduce repeated cloud-security assessment and reporting work. Organization-specific names, paths, controls, data, and credentials are not included.
