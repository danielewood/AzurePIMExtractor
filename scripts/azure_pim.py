#!/usr/bin/env -S uv run --script
# -*- coding: utf-8 -*-
#
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "requests",
#   "pyperclip",
#   "PyJWT",
#   "rich"
# ]
# ///
"""
Description: This script will request a PIM role for the user
"""

import requests
import sys
import os
import json
from datetime import datetime, timezone, timedelta
import argparse
import logging
import jwt  # from PyJWT

from rich.console import Console
from rich.logging import RichHandler
from rich import pretty

# Enable pretty printing for debugging objects
pretty.install()

# --- Add custom TRACE level (below DEBUG) ---
TRACE_LEVEL_NUM = 5
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kwargs)


logging.Logger.trace = trace

# --- Configure logging with Rich, sending logs to stderr ---
logging.basicConfig(
    level=TRACE_LEVEL_NUM,  # set to TRACE level to show all messages
    format="%(message)s",
    datefmt="%H:%M:%S",
    handlers=[RichHandler(rich_tracebacks=True, console=Console(stderr=True))]
)
logger = logging.getLogger("rich_logger")
console = Console()


def error(message):
    logger.error(message)
    sys.exit(1)


# Set the path to your custom certificate file (if available)
cert_file_path = os.path.expanduser("~/.config/cacerts.pem")
if not os.path.exists(cert_file_path):
    cert_file_path = None
logger.trace(f"Certificate file path set to: {cert_file_path}")


def parse_env(env_input):
    """Parse environment input from command line arguments."""
    logger.trace(f"parse_env called with: {env_input}")
    if isinstance(env_input, str):
        result = [e.strip() for e in env_input.split(",") if e.strip()]
    elif isinstance(env_input, list):
        environments = []
        for e in env_input:
            environments.extend(e.split(","))
        result = [env.strip() for env in environments if env.strip()]
    else:
        result = []
    logger.trace(f"parse_env returning: {result}")
    return result


def validate_token(token):
    """Validate and decode the JWT token."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        logger.debug(f"Decoded JWT token payload:\n{json.dumps(payload, indent=2)}")
        org_id = payload.get("oid")
        exp = payload.get("exp")
        if not org_id or not exp:
            error("Token missing required claims (oid or exp)")
        logger.info(f"oid: {org_id}")
        # Use timezone-aware UTC objects to avoid deprecation warnings
        expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        remaining_time = expiration_time - datetime.now(timezone.utc)
        if remaining_time.total_seconds() < 10:
            error(f"Token expired at {expiration_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        logger.info(f"Bearer Token will expire at {expiration_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        logger.info(f"Time remaining until expiration: {str(remaining_time)}")
        logger.trace(f"validate_token returning org_id: {org_id}")
        return org_id
    except jwt.InvalidTokenError as e:
        error(f"Invalid token: {str(e)}")


def parse_role_metadata(display_name):
    """Parse role display name into structured metadata."""
    logger.trace(f"parse_role_metadata called with display_name: {display_name}")
    meta = {
        "account_pim": display_name,
        "account_type": "n/a",
        "account_id": "n/a",
        "account_role": "n/a",
        "account_name": "n/a"
    }

    # Split by dash to handle all formats
    dash_parts = display_name.split("-")

    # Handle AAD-AWS format (e.g., AAD-AWS-457689639821-P-DevOps)
    if display_name.startswith("AAD-AWS"):
        if len(dash_parts) >= 5:
            meta.update({
                "account_id": dash_parts[2],
                "account_type": dash_parts[3],
                "account_role": dash_parts[4],
                "account_name": accounts.get(dash_parts[2], "unknown")
            })

    # Handle AWS/SPD format (e.g., AWS-ESSC-N-2/AVM_app_dev)
    elif display_name.startswith(("AWS-", "SPD-")):
        if len(dash_parts) >= 4:
            parts = display_name.split("/", 1)
            prefix = parts[0]  # e.g. "AWS-AWSI-P-6" from "AWS-AWSI-P-6/AVM_app_dev"
            account = parts[1] if len(parts) > 1 else display_name
            logger.debug(f"Extracted prefix: {prefix}, account: {account}")
            env_type = dash_parts[2]
            meta.update({
                "account_id": account,
                "account_type": env_type,
                "account_role": account.replace("-WA", ""),
                # For filtering purposes, store the entire original display name.
                "account_name": display_name
            })
    logger.trace(f"parse_role_metadata returning: {meta}")
    return meta


def get_sort_key(role):
    """Get a sort key for role ordering."""
    display_name = role.get("roleDefinition", {}).get("resource", {}).get("displayName", "")
    logger.trace(f"get_sort_key called for display_name: {display_name}")
    # For AAD-AWS format
    if display_name.startswith("AAD-AWS-"):
        parts = display_name.split("-")
        if len(parts) >= 3:
            account_id = parts[2]
            sort_key = accounts.get(account_id, "zzz" + account_id)
            logger.trace(f"get_sort_key returning: {sort_key} for AAD-AWS")
            return sort_key
    # For AWS/SPD format
    service_name = role.get("meta", {}).get("account_name", "")
    if service_name:
        sort_key = "yyy" + service_name
        logger.trace(f"get_sort_key returning: {sort_key} for AWS/SPD")
        return sort_key

    sort_key = "zzz" + display_name
    logger.trace(f"get_sort_key returning: {sort_key} default case")
    return sort_key


def process_role_assignment(role, url, headers, role_type, pim_ticket_number=None):
    """Process a single role assignment request."""
    current_role = role.get("roleDefinition", {}).get("resource", {}).get("displayName", "")
    logger.debug(f"Processing role assignment for: {current_role}")

    # Determine reason and ticket based on role type
    if f"-P-{role_type}" in current_role:
        if not pim_ticket_number:
            return (current_role, False, None, "PIM Ticket Number is required for Production roles")
        pim_reason = pim_ticket_number
        pim_ticket = pim_ticket_number
        pim_ticket_system = "JIRA"
    else:
        pim_reason = "None"
        pim_ticket = "None"
        pim_ticket_system = "None"

    payload = {
        "roleDefinitionId": role["roleDefinitionId"],
        "resourceId": role["resourceId"],
        "subjectId": role["subjectId"],
        "assignmentState": "Active",
        "type": "UserAdd",
        "reason": pim_reason,
        "ticketNumber": pim_ticket,
        "ticketSystem": pim_ticket_system,
        "schedule": {
            "type": "Once",
            "startDateTime": None,
            "endDateTime": None,
            "duration": "PT480M",
        },
        "linkedEligibleRoleAssignmentId": role["id"],
        "scopedResourceId": "",
    }
    logger.trace(f"process_role_assignment payload:\n{json.dumps(payload, indent=2)}")
    try:
        response = requests.post(url, headers=headers, json=payload, verify=cert_file_path)
        logger.debug(f"Response status code: {response.status_code}")
        try:
            response_json = response.json()
            logger.debug(f"Response JSON:\n{json.dumps(response_json, indent=2)}")
        except Exception:
            logger.debug("Response did not contain JSON")
            response_json = {}
        success = 200 <= response.status_code <= 299

        if success:
            if response.status_code == 208:
                return (current_role, True, 208, "RoleAssignmentExists")
            return (current_role, True, response.status_code, response_json.get("message", "Successfully assigned role"))

        return (current_role, False, response.status_code, response.text)
    except Exception as e:
        logger.exception("Exception during role assignment request:")
        return (current_role, False, None, str(e))


def execute_role_assignments(roles, url, headers, role_type, pim_ticket_number=None):
    """Execute role assignments in parallel."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    logger.debug("Executing role assignments in parallel")
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_role = {
            executor.submit(
                process_role_assignment,
                role,
                url,
                headers,
                role_type,
                pim_ticket_number
            ): role for role in roles
        }

        for future in as_completed(future_to_role):
            role = future_to_role[future]
            try:
                current_role, success, status_code, response_text = future.result()
                logger.info(f"Result for role {current_role}: success={success}, status_code={status_code}, response_text={response_text}")
                if success and status_code == 208:
                    logger.info(f"{current_role}: Role assignment already exists")
                elif success:
                    logger.info(f"{current_role}: Successfully assigned")
                elif not success and status_code is None:
                    logger.warning(f"{current_role}: {response_text}")
                else:
                    logger.error(f"Request failed for role: {current_role}, Status Code: {status_code}, Response: {response_text}")
            except Exception as exc:
                logger.exception(f"Role {role.get('meta', {}).get('account_name', 'Unknown')} generated an exception: {exc}")


def main():
    # Known AWS accounts mapping
    global accounts
    accounts = {}
    known_accounts_file = os.path.expanduser("~/.aws/known_accounts.json")
    if os.path.exists(known_accounts_file):
        try:
            with open(known_accounts_file, "r") as f:
                accounts = json.load(f)
        except Exception as e:
            logger.exception(f"Failed to load known accounts file: {str(e)}")
    logger.debug(f"Accounts mapping:\n{json.dumps(accounts, indent=2)}")

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Request PIM role")
    parser.add_argument("--role", help="Role type to request", default="DevOps")
    parser.add_argument("--ticket", help="PIM Ticket Number", default=None)
    parser.add_argument("--token", help="Bearer Token", default=None)
    parser.add_argument(
        "--env",
        help="Restrict request to specific environments (comma-separated list or multiple --env flags)",
        nargs="+",
        default=None,
        type=parse_env
    )
    args = parser.parse_args()
    role_type = args.role
    pim_ticket_number = args.ticket
    token = args.token
    requested_env = args.env[0] if args.env else None
    logger.info(f"Requested environments: {requested_env}")

    # Get token from clipboard if not provided
    if not token:
        try:
            import pyperclip
            token = pyperclip.paste()
            logger.debug(f"Token retrieved from clipboard: {token}")
        except ModuleNotFoundError:
            error("Please install the pyperclip module: pip install pyperclip")

    # Validate token and get org_id
    org_id = validate_token(token)

    # Get available role assignments
    url = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleAssignments"
    params = {
        "$expand": "linkedEligibleRoleAssignment,subject,scopedResource,roleDefinition($expand=resource)",
        "$filter": f"(subject/id eq '{org_id}') and (assignmentState eq 'Eligible')",
        "$count": "true",
    }
    headers = {
        "Accept-Language": "en",
        "Authorization": f"Bearer {token}",
        "x-ms-effective-locale": "en.en-us",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.57",
        "Accept": "application/json",
        "Referer": "https://portal.azure.com",
    }
    logger.debug(f"GET request URL: {url}")
    logger.debug(f"GET request params:\n{json.dumps(params, indent=2)}")
    try:
        response = requests.get(url, params=params, headers=headers, verify=cert_file_path)
        logger.debug(f"GET response status: {response.status_code}")
        try:
            data = response.json()
            logger.debug(f"GET response JSON:\n{json.dumps(data, indent=2)}")
        except Exception as e:
            logger.exception("Failed to decode GET response JSON")
            data = {}
    except requests.exceptions.RequestException as e:
        error(f"Failed to get role assignments: {str(e)}")

    # Process and filter roles
    avail_roles_data = data.get("value", [])
    logger.debug(f"Available roles data:\n{json.dumps(avail_roles_data, indent=2)}")

    for role in avail_roles_data:
        display_name = role.get("roleDefinition", {}).get("resource", {}).get("displayName", "")
        role["meta"] = parse_role_metadata(display_name)
        logger.info(f"Original: {display_name}")
        logger.info(f"Parsed: Type={role['meta']['account_type']}, ID={role['meta']['account_id']}, Role={role['meta']['account_role']}\n")

    # Sort and filter roles
    avail_roles_data_sorted = sorted(avail_roles_data, key=get_sort_key)
    roles = [
        item for item in avail_roles_data_sorted
        if f"-{role_type}" in item.get("roleDefinition", {}).get("resource", {}).get("displayName", "")
           or f"/{role_type}" in item.get("roleDefinition", {}).get("resource", {}).get("displayName", "")
    ]

    # Change filtering: use a substring match against the full display name ("account_pim")
    if requested_env:
        roles = [
            item for item in roles
            if any(str(env).lower() in item.get("meta", {}).get("account_pim", "").lower()
                   for env in requested_env)
        ]

    if not roles:
        logger.warning(f"No eligible roles found matching the criteria: role_type={role_type}, env={requested_env}")
        sys.exit(0)

    # Execute role assignments
    assignment_url = "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadGroups/roleAssignmentRequests"
    execute_role_assignments(roles, assignment_url, headers, role_type, pim_ticket_number)


if __name__ == "__main__":
    main()
