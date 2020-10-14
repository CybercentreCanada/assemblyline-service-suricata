import glob
import json
import logging
import os
import re
import shutil
import tempfile
import time
from typing import List, Dict, Any
from urllib.parse import urlparse
from zipfile import ZipFile

import certifi
import requests
import yaml
from assemblyline_client import get_client
from git import Repo

from assemblyline.common import log as al_log, forge
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.isotime import iso_to_epoch
from suricata_.suricata_importer import SuricataImporter

al_log.init_logging('updater.suricata')
classification = forge.get_classification()

LOGGER = logging.getLogger('assemblyline.updater.suricata')

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/suricata_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/suricata_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'suricata_updates')


def add_cacert(cert: str):
    # Add certificate to requests
    cafile = certifi.where()
    with open(cafile, 'a') as ca_editor:
        ca_editor.write(f"\n{cert}")


def url_download(source: Dict[str, Any], previous_update=None) -> List:
    """

    :param source:
    :param previous_update:
    :return:
    """
    name = source['name']
    uri = source['uri']
    pattern = source.get('pattern', None)
    username = source.get('username', None)
    password = source.get('password', None)
    ca_cert = source.get('ca_cert', None)
    ignore_ssl_errors = source.get('ssl_ignore_errors', False)
    auth = (username, password) if username and password else None

    headers = source.get('headers', None)

    LOGGER.info(f"{name} source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        LOGGER.info(f"A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    try:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)

        # Check the response header for the last modified date
        response = session.head(uri, auth=auth, headers=headers)
        last_modified = response.headers.get('Last-Modified', None)
        if last_modified:
            # Convert the last modified time to epoch
            last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

            # Compare the last modified time with the last updated time
            if previous_update and last_modified <= previous_update:
                # File has not been modified since last update, do nothing
                return []

        if previous_update:
            previous_update = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(previous_update))
            if headers:
                headers['If-Modified-Since'] = previous_update
            else:
                headers = {'If-Modified-Since': previous_update}

        response = session.get(uri, auth=auth, headers=headers)

        # Check the response code
        if response.status_code == requests.codes['not_modified']:
            # File has not been modified since last update, do nothing
            return []
        elif response.ok:
            if not os.path.exists(UPDATE_DIR):
                os.makedirs(UPDATE_DIR)

            file_name = os.path.basename(urlparse(uri).path)
            file_path = os.path.join(UPDATE_DIR, file_name)
            with open(file_path, 'wb') as f:
                f.write(response.content)

            rules_files = None
            if file_name.endswith('tar.gz'):
                extract_dir = os.path.join(UPDATE_DIR, name)
                shutil.unpack_archive(file_path, extract_dir=extract_dir)

                rules_files = set()
                for path_in_dir, _, files in os.walk(extract_dir):
                    for filename in files:
                        filepath = os.path.join(extract_dir, path_in_dir, filename)
                        if pattern:
                            if re.match(pattern, filename):
                                rules_files.add(filepath)
                        else:
                            rules_files.add(filepath)

            return [(f, get_sha256_for_file(f)) for f in rules_files or [file_path]]

    except requests.Timeout:
        # TODO: should we retry?
        pass
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        LOGGER.info(str(e))
        exit()
        # TODO: Should we exit even if one file fails to download? Or should we continue downloading other files?
    finally:
        # Close the requests session
        session.close()


def git_clone_repo(source: Dict[str, Any], previous_update=None) -> List:
    name = source['name']
    url = source['uri']
    pattern = source.get('pattern', None)
    key = source.get('private_key', None)
    ssl_ignore = source.get("ssl_ignore_errors", False)
    ca_cert = source.get("ca_cert")

    git_env = {}
    if ssl_ignore:
        git_env['GIT_SSL_NO_VERIFY'] = 1

    if ca_cert:
        LOGGER.info(f"A CA certificate has been provided with this source.")
        add_cacert(ca_cert)
        git_env['GIT_SSL_CAINFO'] = certifi.where()

    clone_dir = os.path.join(UPDATE_DIR, name)
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    if key:
        LOGGER.info(f"key found for {url}")
        # Save the key to a file
        git_ssh_identity_file = os.path.join(tempfile.gettempdir(), 'id_rsa')
        with open(git_ssh_identity_file, 'w') as key_fh:
            key_fh.write(key)
        os.chmod(git_ssh_identity_file, 0o0400)

        git_ssh_cmd = f"ssh -oStrictHostKeyChecking=no -i {git_ssh_identity_file}"
        git_env['GIT_SSH_COMMAND'] = git_ssh_cmd

    repo = Repo.clone_from(url, clone_dir, env=git_env)

    # Check repo last commit
    if previous_update:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)
        for c in repo.iter_commits():
            if c.committed_date < previous_update:
                return []
            break

    if pattern:
        files = [(os.path.join(clone_dir, f), get_sha256_for_file(f))
                 for f in os.listdir(clone_dir) if re.match(pattern, f)]
    else:
        files = [(f, get_sha256_for_file(f)) for f in glob.glob(os.path.join(clone_dir, '*.rules*'))]

    return files


def suricata_update() -> None:
    """
    Using an update configuration file as an input, which contains a list of sources, download all the file(s).
    """
    # noinspection PyBroadException
    try:
        # Load updater configuration
        update_config = {}
        if UPDATE_CONFIGURATION_PATH and os.path.exists(UPDATE_CONFIGURATION_PATH):
            with open(UPDATE_CONFIGURATION_PATH, 'r') as yml_fh:
                update_config = yaml.safe_load(yml_fh)
        else:
            LOGGER.error(f"Update configuration file doesn't exist: {UPDATE_CONFIGURATION_PATH}")
            exit()

        # Exit if no update sources given
        if 'sources' not in update_config.keys() or not update_config['sources']:
            LOGGER.error(f"Update configuration does not contain any source to update from")
            exit()

        # Initialise al_client
        server = update_config['ui_server']
        user = update_config['api_user']
        api_key = update_config['api_key']
        LOGGER.info(f"Connecting to Assemblyline API: {server}...")
        al_client = get_client(server, apikey=(user, api_key), verify=False)
        LOGGER.info(f"Connected!")

        # Parse updater configuration
        previous_update = update_config.get('previous_update', None)
        previous_hash = json.loads(update_config.get('previous_hash', None) or "{}")
        sources = {source['name']: source for source in update_config['sources']}
        files_sha256 = {}
        source_default_classification = {}

        # Go through each source and download file
        for source_name, source in sources.items():
            uri: str = source['uri']
            source_default_classification[source_name] = source.get('default_classification',
                                                                    classification.UNRESTRICTED)

            if uri.endswith('.git'):
                files = git_clone_repo(source, previous_update=previous_update)
                for file, sha256 in files:
                    files_sha256.setdefault(source_name, {})
                    if previous_hash.get(source_name, {}).get(file, None) != sha256:
                        files_sha256[source_name][file] = sha256
            else:
                files = url_download(source, previous_update=previous_update)
                for file, sha256 in files:
                    files_sha256.setdefault(source_name, {})
                    if previous_hash.get(source_name, {}).get(file, None) != sha256:
                        files_sha256[source_name][file] = sha256

        if files_sha256:
            LOGGER.info("Found new Suricata rule files to process!")

            suricata_importer = SuricataImporter(al_client, logger=LOGGER)

            for source, source_val in files_sha256.items():
                total_imported = 0
                default_classification = source_default_classification[source]
                for file in source_val.keys():
                    total_imported += suricata_importer.import_file(file, source,
                                                                    default_classification=default_classification)
                LOGGER.info(f"{total_imported} signatures were imported for source {source}")

        else:
            LOGGER.info('No new Suricata rule files to process')

        if al_client.signature.update_available(since=previous_update or '', sig_type='suricata')['update_available']:
            LOGGER.info("An update is available for download from the datastore")

            if not os.path.exists(UPDATE_OUTPUT_PATH):
                os.makedirs(UPDATE_OUTPUT_PATH)

            temp_zip_file = os.path.join(UPDATE_OUTPUT_PATH, 'temp.zip')
            al_client.signature.download(output=temp_zip_file,
                                         query="type:suricata AND (status:NOISY OR status:DEPLOYED)")

            if os.path.exists(temp_zip_file):
                with ZipFile(temp_zip_file, 'r') as zip_f:
                    zip_f.extractall(UPDATE_OUTPUT_PATH)

                os.remove(temp_zip_file)

            # Create the response yaml
            with open(os.path.join(UPDATE_OUTPUT_PATH, 'response.yaml'), 'w') as yml_fh:
                yaml.safe_dump(dict(hash=json.dumps(files_sha256)), yml_fh)

            LOGGER.info(f"New ruleset successfully downloaded and ready to use")

        LOGGER.info(f"Suricata updater completed successfully")
    except Exception:
        LOGGER.exception("Updater ended with an exception!")


if __name__ == '__main__':
    suricata_update()
