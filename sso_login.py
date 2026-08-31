#!/usr/bin/env python3
"""
Perform AWS IAM Identity Center (SSO) login WITHOUT the AWS CLI.

Replicates `aws sso login` using boto3's sso-oidc device authorization flow,
then writes the token to ~/.aws/sso/cache/ in the same format the CLI uses,
so aws_enum.py (the enumerator) can read it unchanged.

Prereqs:
    pip install boto3    # already installed

Usage:
    py sso_login.py --start-url https://start.us-gov-home.awsapps.com/directory/example-directory --sso-region us-gov-west-1
    py sso_login.py --start-url https://example-directory.awsapps.com/start --sso-region us-east-1
"""

import argparse
import hashlib
import json
import os
import sys
import time
import webbrowser
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def cache_path_for(start_url):
    """CLI derives the cache filename from a SHA1 of the start URL."""
    cache_dir = os.path.expanduser("~/.aws/sso/cache")
    os.makedirs(cache_dir, exist_ok=True)
    digest = hashlib.sha1(start_url.encode("utf-8")).hexdigest()
    return os.path.join(cache_dir, f"{digest}.json")


def do_login(start_url, sso_region):
    oidc = boto3.client("sso-oidc", region_name=sso_region)

    # 1. Register this script as an OIDC client.
    client = oidc.register_client(
        clientName="cloud-security-posture-scan", clientType="public"
    )
    client_id = client["clientId"]
    client_secret = client["clientSecret"]

    # 2. Start the device authorization flow.
    dev = oidc.start_device_authorization(
        clientId=client_id,
        clientSecret=client_secret,
        startUrl=start_url,
    )
    verification_uri = dev["verificationUriComplete"]
    device_code = dev["deviceCode"]
    interval = dev.get("interval", 5)
    expires_in = dev.get("expiresIn", 600)

    print("\n" + "=" * 70)
    print("Open this URL in your browser and approve the request:")
    print(f"\n    {verification_uri}\n")
    print(f"(User code: {dev['userCode']})")
    print("=" * 70 + "\n")
    try:
        webbrowser.open(verification_uri)
    except Exception:
        pass  # headless / blocked browser is fine, URL is printed above

    # 3. Poll for the token until the user approves (or it times out).
    print("Waiting for approval in browser...", end="", flush=True)
    deadline = time.time() + expires_in
    token_resp = None
    while time.time() < deadline:
        time.sleep(interval)
        try:
            token_resp = oidc.create_token(
                clientId=client_id,
                clientSecret=client_secret,
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=device_code,
            )
            break
        except oidc.exceptions.AuthorizationPendingException:
            print(".", end="", flush=True)
            continue
        except oidc.exceptions.SlowDownException:
            interval += 5
            continue
        except oidc.exceptions.ExpiredTokenException:
            raise RuntimeError("Device code expired before approval. Re-run.")
    print()

    if token_resp is None:
        raise RuntimeError("Timed out waiting for approval.")

    # 4. Write the token cache in the CLI-compatible format.
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=token_resp["expiresIn"]
    )
    cache = {
        "startUrl": start_url,
        "region": sso_region,
        "accessToken": token_resp["accessToken"],
        "expiresAt": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clientId": client_id,
        "clientSecret": client_secret,
        "registrationExpiresAt": datetime.fromtimestamp(
            client["clientSecretExpiresAt"], tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if "refreshToken" in token_resp:
        cache["refreshToken"] = token_resp["refreshToken"]

    path = cache_path_for(start_url)
    with open(path, "w") as f:
        json.dump(cache, f, indent=2)

    # Tighten perms on the token file where the OS supports it (POSIX).
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass

    print(f"Login successful. Token cached to:\n  {path}")
    print(f"Valid until {cache['expiresAt']} (UTC).")


def main():
    ap = argparse.ArgumentParser(
        description="Perform AWS IAM Identity Center (SSO) login without the AWS CLI."
    )
    ap.add_argument(
        "--start-url",
        required=True,
        help="SSO start URL, e.g. "
             "https://start.us-gov-home.awsapps.com/directory/example-directory",
    )
    ap.add_argument(
        "--sso-region",
        required=True,
        help="us-gov-west-1 for GovCloud, us-east-1 for commercial",
    )
    args = ap.parse_args()

    try:
        do_login(args.start_url, args.sso_region)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
    except RuntimeError as e:
        print(f"\nLogin failed: {e}")
        sys.exit(1)
    except (BotoCoreError, ClientError) as e:
        print(f"\nAWS error during login: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()