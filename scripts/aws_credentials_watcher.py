#!/usr/bin/env -S uv run --script
# -*- coding: utf-8 -*-
#
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "boto3",
#     "watchgod",
#     "keyring",
#     "coloredlogs"
# ]
# ///

import argparse
import datetime
import json
import logging
import os
import re
import sys
import time
import threading
from configparser import ConfigParser
from typing import Dict, List, Optional, Tuple

import boto3
import coloredlogs
import keyring
from botocore.exceptions import ClientError, NoCredentialsError
from watchgod import DefaultWatcher
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# This regex extracts the role name from the ARN, for example:
# arn:aws:sts::1111111111:assumed-role/MyOrg_ReadOnly/username@myorg.com becomes ReadOnly
ARN_ROLE_PATTERN = r"/[A-Za-z]+_(.*?)/"

TOKEN_VALIDITY_SECONDS = 28800
DEFAULT_PROFILE_KEYCHAIN_KEY = "default_profile"

AWS_TRUSTED_ROOTS_PEM_FULLPATH = "~/.config/cacerts.pem"
TARGET_CREDENTIALS_FULLPATH = "~/.aws/credentials"
LOCAL_CREDENTIALS_FULLPATH = "~/.aws/credentials.local"
SOURCE_CREDENTIALS_FULLPATH = "~/Downloads/credentials"

# Expanding the user's home directory in the path
AWS_TRUSTED_ROOTS_PEM_FULLPATH = os.path.expanduser(AWS_TRUSTED_ROOTS_PEM_FULLPATH)
TARGET_CREDENTIALS_FULLPATH = os.path.expanduser(TARGET_CREDENTIALS_FULLPATH)
LOCAL_CREDENTIALS_FULLPATH = os.path.expanduser(LOCAL_CREDENTIALS_FULLPATH)
SOURCE_CREDENTIALS_FULLPATH = os.path.expanduser(SOURCE_CREDENTIALS_FULLPATH)

# Get the directory name and file name for the source credentials file
SOURCE_CREDENTIALS_FILE_PATH, SOURCE_CREDENTIALS_FILE_NAME = os.path.split(
    SOURCE_CREDENTIALS_FULLPATH
)

# Set up a specific logger with desired severity
logger = logging.getLogger(__name__)

# Set up argument parsing
parser = argparse.ArgumentParser(
    description="Python Script with adjustable debug level."
)
parser.add_argument(
    "-v",
    "--verbose",
    help="Set verbosity level. Default is INFO.",
    default="INFO",
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
)

args = parser.parse_args()

# Set the log level based on command line arguments
levels = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}
logger.setLevel(levels[args.verbose])

# Create the log formatter
formatter = coloredlogs.ColoredFormatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level_styles={
        "debug": {"color": "green"},
        "info": {"color": "blue"},
        "warning": {"color": "yellow"},
        "error": {"color": "red"},
        "critical": {"color": "red", "bold": True},
    },
)

# Create a handler for the logger (logs will go to stderr)
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Global lock to ensure that updates (from file watcher or HTTP server) do not conflict.
update_lock = threading.Lock()


def store_in_keychain(service: str, username: str, data: Dict):
    """Stores data in the macOS keychain.

    Args:
        service (str): The name of the keychain service where the data is to be stored.
        username (str): The key under which the data is to be stored.
        data (dict): The data to be stored in the keychain.
    """
    keyring.set_password(service, username, json.dumps(data))


def get_from_keychain(service: str, username: str) -> Optional[Dict]:
    """Retrieves data from the macOS keychain.

    Args:
        service (str): The name of the keychain service where the data is stored.
        username (str): The key under which the data is stored.

    Returns:
        dict: The data retrieved from the keychain, or None if no data is found.
    """
    stored_data = keyring.get_password(service, username)
    if stored_data:
        return json.loads(stored_data)
    return None


def get_all_keychain_items(service: str) -> List[Tuple[str, Optional[Dict]]]:
    """Get all usernames and their data for a service in the macOS keychain.

    Args:
        service (str): The name of the keychain service where the data is stored.

    Returns:
        list: A list of tuples, where each tuple consists of a username and its associated data.
    """
    usernames = keyring.get_password(service, "known_usernames")
    if usernames:
        usernames = json.loads(usernames)
    else:
        usernames = []

    return [(username, get_from_keychain(service, username)) for username in usernames]


def watch_credentials_file() -> bool:
    """Watch the credentials file for any changes.

    Returns:
        bool: True if the credentials file has changed, otherwise loops indefinitely.
    """
    watcher = DefaultWatcher(SOURCE_CREDENTIALS_FILE_PATH)
    while True:
        try:
            time.sleep(1)  # wait 1 second between checks to allow Ctrl+C to be caught
            changes = watcher.check()
            for change in changes:
                _, file_path = change
                if "credentials" in file_path:
                    logger.info(f"Changed: {SOURCE_CREDENTIALS_FULLPATH}")
                    logger.debug(f"Detected change: {change}")
                    return True
        except KeyboardInterrupt:
            print("")
            logger.critical("Interrupted by user. Exiting...")
            exit(0)


def get_aws_info(
    profile_name: str = "default", credentials_file: Optional[str] = None
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Get AWS identity information.

    Args:
        profile_name (str, optional): The AWS profile name. Defaults to 'default'.
        credentials_file (str, optional): The path to the AWS credentials file. If None, the AWS profile name is used.

    Returns:
        tuple: A tuple of account, ARN, and role if the AWS info could be retrieved; otherwise, (None, None, None).
    """
    logger.debug(
        f"get_aws_info(profile_name={profile_name}, credentials_file={credentials_file})"
    )
    exception_prefix = (
        credentials_file if credentials_file is not None else profile_name
    )

    try:
        if credentials_file is not None:
            # Load the AWS credentials file and use the given profile
            config = ConfigParser()
            config.read(credentials_file)

            session = boto3.Session(
                aws_access_key_id=config.get(profile_name, "aws_access_key_id"),
                aws_secret_access_key=config.get(profile_name, "aws_secret_access_key"),
                aws_session_token=(
                    config.get(profile_name, "aws_session_token")
                    if config.has_option(profile_name, "aws_session_token")
                    else None
                ),
            )
        else:
            session = boto3.Session(profile_name=profile_name)
        logger.debug(f"boto3.Session={session}")

        sts = session.client("sts")
        identity = sts.get_caller_identity()
        logger.debug(f"{profile_name}: sts.get_caller_identity={identity}")

        account = identity["Account"]
        arn = identity["Arn"]
        logger.debug(f"{profile_name}: account={account}, arn={arn}")

        # Extract the role from the ARN
        role_match = re.search(ARN_ROLE_PATTERN, arn)
        role = role_match.group(1) if role_match else None

        return account, arn, role

    except NoCredentialsError as e:
        logger.warning(f"NoCredentialsError: {exception_prefix} / {e}")
        return None, None, None
    except ClientError as e:
        logger.warning(f"ClientError: {exception_prefix} / {e}")
        return None, None, None
    except Exception as e:
        logger.warning(f"UnhandledException: {exception_prefix} / {e}")
        return None, None, None


def load_known_accounts() -> Dict:
    """Load known accounts from the known_accounts.json file.

    Returns:
        dict: A dictionary of the known accounts.

    Raises:
        Exception: If the known_accounts.json file cannot be loaded.
    """
    try:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        known_accounts_path = os.path.join(script_dir, "known_accounts.json")
        known_accounts_path = os.path.expanduser("~/.aws/known_accounts.json")
        with open(known_accounts_path) as f:
            return json.load(f)
    except Exception as e:
        logger.critical("Could not load known_accounts.json")
        logger.critical(e)
        exit(1)


def store_credentials(
    profile_name: str, account: str, arn: str, role: str, known_accounts: Dict
):
    """Store the AWS credentials in the macOS keychain.

    Args:
        profile_name (str): The AWS profile name.
        account (str): The AWS account.
        arn (str): The AWS ARN.
        role (str): The AWS role.
        known_accounts (dict): The known accounts.
    """
    account_name = known_accounts.get(account)
    logger.debug(
        f"store_credentials(profile_name={profile_name}, account={account}, arn={arn}, role={role}, known_accounts={known_accounts})"
    )

    if not account_name:
        logger.error(f"No known account for account number {account}")
        profile_name = f"{account}_{role}"
    else:
        profile_name = f"{account_name}_{role}"

    credentials_path = SOURCE_CREDENTIALS_FULLPATH

    if not os.path.exists(credentials_path):
        logger.critical(
            f"{credentials_path} does not exist. Cannot source credentials."
        )
        return

    with open(credentials_path, "r") as f:
        lines = f.read().strip().splitlines()

    # Replace '[default]' with the new profile header
    lines = [line.replace("[default]", f"[{profile_name}]") for line in lines]
    credentials = "\n".join(lines)

    # Store the credentials in the keychain along with a timestamp
    data = {
        "credentials": credentials,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    store_in_keychain("AWS", profile_name, data)
    logger.debug(f"Stored in keychain under AWS/{profile_name}: {data}")

    # Update the list of known usernames
    known_usernames = keyring.get_password("AWS", "known_usernames")
    if known_usernames:
        known_usernames = json.loads(known_usernames)
    else:
        known_usernames = []
    if profile_name not in known_usernames:
        known_usernames.append(profile_name)
        keyring.set_password("AWS", "known_usernames", json.dumps(known_usernames))
        logger.debug(f"Updated known usernames: {json.dumps(known_usernames)}")

    # Set the new profile as the default
    keyring.set_password("AWS", DEFAULT_PROFILE_KEYCHAIN_KEY, json.dumps(profile_name))
    logger.info(f"Updated: {account} / {account_name} / {role}")


def timestampper_delta(timestamp: datetime.datetime, seconds: int) -> str:
    return (timestamp + datetime.timedelta(seconds=seconds)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def timestampper(timestamp: datetime.datetime) -> str:
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def update_credentials_from_file(file_path: str) -> bool:
    """Reads the credentials file, extracts AWS info and updates the keychain.

    Args:
        file_path (str): The path to the credentials file.

    Returns:
        bool: True if credentials were updated successfully; False otherwise.
    """
    known_accounts = load_known_accounts()
    account, arn, role = get_aws_info(credentials_file=file_path)
    if account and arn and role:
        store_credentials("default", account, arn, role, known_accounts)
        logger.info("Updated credentials from %s", file_path)
        return True
    else:
        logger.warning("Could not get AWS info from %s, skipping update", file_path)
        return False


def update_target_credentials_file() -> None:
    """Update the target credentials file (usually ~/.aws/credentials)
    by writing the default profile (if still valid) and all non‐expired profiles from the keychain.
    Also appends the content of ~/.aws/credentials.local if it exists.
    """
    target_credentials_file = TARGET_CREDENTIALS_FULLPATH

    default_profile = (
        json.loads(keyring.get_password("AWS", DEFAULT_PROFILE_KEYCHAIN_KEY) or "")
        if keyring.get_password("AWS", DEFAULT_PROFILE_KEYCHAIN_KEY)
        else None
    )
    default_profile_data = (
        get_from_keychain("AWS", default_profile) if default_profile else None
    )

    with open(target_credentials_file, "w") as f:
        # Write the default profile first
        if default_profile and default_profile_data:
            timestamp = datetime.datetime.fromisoformat(
                default_profile_data["timestamp"]
            )
            if datetime.datetime.now() - timestamp < datetime.timedelta(
                seconds=TOKEN_VALIDITY_SECONDS
            ):
                lines = default_profile_data["credentials"].split("\n")
                lines = [
                    line.replace(
                        f"[{default_profile}]", f"[default] # {default_profile}"
                    )
                    for line in lines
                ]
                default_profile_text = "\n".join(lines)
                f.write(default_profile_text)
                if os.path.exists(AWS_TRUSTED_ROOTS_PEM_FULLPATH):
                    f.write(f"\nca_bundle={AWS_TRUSTED_ROOTS_PEM_FULLPATH}")
                    logger.debug(f"Added ca_bundle to {default_profile}")
                else:
                    logger.warning(f"Could not find {AWS_TRUSTED_ROOTS_PEM_FULLPATH}")
                f.write(f"\n# updated: {timestampper(timestamp)}")
                f.write(
                    f"\n# expires: {timestampper_delta(timestamp, TOKEN_VALIDITY_SECONDS)}\n\n"
                )
                logger.info(
                    f"Updated default profile to {default_profile}, expires {timestampper_delta(timestamp, TOKEN_VALIDITY_SECONDS)}"
                )

        # Then write the rest of the profiles
        for profile_name, data in sorted(
            get_all_keychain_items("AWS"), key=lambda x: x[0]
        ):
            if data:
                timestamp = datetime.datetime.fromisoformat(data["timestamp"])
                expiration_time = timestamp + datetime.timedelta(
                    seconds=TOKEN_VALIDITY_SECONDS
                )
                if datetime.datetime.now() < expiration_time:
                    f.write(data["credentials"])
                    if os.path.exists(AWS_TRUSTED_ROOTS_PEM_FULLPATH):
                        f.write(f"\nca_bundle={AWS_TRUSTED_ROOTS_PEM_FULLPATH}")
                        logger.debug(f"Added ca_bundle to {profile_name}")
                    else:
                        logger.warning(
                            f"Could not find {AWS_TRUSTED_ROOTS_PEM_FULLPATH}"
                        )
                    f.write(f"\n# updated: {timestampper(timestamp)}")
                    f.write(
                        f"\n# expires: {timestampper_delta(timestamp, TOKEN_VALIDITY_SECONDS)}\n\n"
                    )
                    logger.info(
                        f"Added {profile_name} to credentials, expires {timestampper_delta(timestamp, TOKEN_VALIDITY_SECONDS)}"
                    )
                    logger.debug(f"Added {profile_name}: \n{data['credentials']}")
                else:
                    # delete expired profile
                    keyring.delete_password("AWS", profile_name)
                    logger.info(f"Deleted expired profile {profile_name}")

        # Append ~/.aws/credentials.local if it exists
        if os.path.exists(LOCAL_CREDENTIALS_FULLPATH):
            with open(LOCAL_CREDENTIALS_FULLPATH, "r") as local_f:
                local_content = local_f.read()
            f.write("\n" + local_content + "\n")
            logger.info(
                f"Added {LOCAL_CREDENTIALS_FULLPATH} to {target_credentials_file}"
            )


def process_credentials_update():
    """Wrap the update process (reading new credentials and writing out the target file)
    with a lock so that both the file-watcher and HTTP server do not run concurrently.
    """
    with update_lock:
        if update_credentials_from_file(SOURCE_CREDENTIALS_FULLPATH):
            update_target_credentials_file()


class CredentialsHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/credentials":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                post_data = self.rfile.read(content_length)
                credentials_text = post_data.decode("utf-8")

                # Write the posted credentials to the source credentials file.
                with open(SOURCE_CREDENTIALS_FULLPATH, "w") as f:
                    f.write(credentials_text)
                logger.info("Received new credentials via HTTP POST.")

                # Process the update (update keychain and target credentials file)
                process_credentials_update()

                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Credentials processed successfully.\n")
            except Exception as e:
                logger.error("Error processing credentials from POST: %s", e)
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Error processing credentials.\n")
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def log_message(self, format, *args):
        # Override to send HTTP server logs to our logger at DEBUG level.
        logger.debug("%s - - %s", self.client_address[0], format % args)


def main() -> None:
    # Start the HTTP server in a separate daemon thread.
    server_address = ("localhost", 32222)
    httpd = ThreadingHTTPServer(server_address, CredentialsHTTPRequestHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    logger.info(
        "Started HTTP server on http://localhost:32222/credentials for POST requests."
    )

    logger.info(f"Watching: {SOURCE_CREDENTIALS_FULLPATH}")
    while True:
        # Wait for file changes; when detected, process the new credentials.
        if watch_credentials_file():
            process_credentials_update()


if __name__ == "__main__":
    main()
