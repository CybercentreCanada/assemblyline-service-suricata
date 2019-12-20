import glob
import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from zipfile import ZipFile

import requests
import yaml
from assemblyline_client import get_client
from git import Repo

from assemblyline.common import log as al_log
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.isotime import now_as_iso
from suricata_.suricata_importer import SuricataImporter

al_log.init_logging('service_updater')

LOGGER = logging.getLogger('assemblyline.service_updater')

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', None)
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'suricata_updates')


def url_download(source: Dict[str, Any], previous_update: Optional[float] = None) -> (List, List):
    """

    :param source:
    :param previous_update:
    :return:
    """
    name = source['name']
    uri = source['uri']
    username = source.get('username', None)
    password = source.get('password', None)
    auth = (username, password) if username and password else None

    headers = source.get('headers', None)

    # Create a requests session
    session = requests.Session()

    try:
        # Check the response header for the last modified date
        response = session.head(uri, auth=auth, headers=headers)
        last_modified = response.headers.get('Last-Modified', None)
        if last_modified:
            # Convert the last modified time to epoch
            last_modified = time.mktime(time.strptime(last_modified, "%a, %d %b %Y %H:%M:%S %Z"))

            # Compare the last modified time with the last updated time
            if previous_update and last_modified < previous_update:
                # File has not been modified since last update, do nothing
                return [], []

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
            return
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
                        rules_files.add(filepath)

                # Delete the tar.gz file
                os.remove(file_path)

            return list(rules_files) or [file_path], [get_sha256_for_file(file_path)]
    except requests.Timeout:
        # TODO: should we retry?
        pass
    except Exception as e:
        # Catch all other types of exceptions such as ConnectionError, ProxyError, etc.
        LOGGER.info(str(e))
        exit()  # TODO: Should we exit even if one file fails to download? Or should we continue downloading other files?
    finally:
        # Close the requests session
        session.close()


def git_clone_repo(source: Dict[str, Any]) -> List[str] and List[str]:
    name = source['name']
    url = source['uri']
    pattern = source.get('pattern', None)
    key = source.get('private_key', None)

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
        Repo.clone_from(url, clone_dir, env={"GIT_SSH_COMMAND": git_ssh_cmd})

        # with Git().custom_environment(GIT_SSH_COMMAND=git_ssh_cmd):
        #     Repo.clone_from(url, clone_dir)
    else:
        Repo.clone_from(url, clone_dir)

    if pattern:
        files = [os.path.join(clone_dir, f) for f in os.listdir(clone_dir) if re.match(pattern, f)]
    else:
        files = glob.glob(os.path.join(clone_dir, '*.yar*'))

    files_sha256 = [get_sha256_for_file(x) for x in files]

    return files, files_sha256


def suricata_update() -> None:
    """
    Using an update configuration file as an input, which contains a list of sources, download all the file(s).
    """
    if os.path.exists(UPDATE_CONFIGURATION_PATH):
        with open(UPDATE_CONFIGURATION_PATH, 'r') as yml_fh:
            update_config = yaml.safe_load(yml_fh)
    else:
        LOGGER.exception(f"Update configuration file doesn't exist: {UPDATE_CONFIGURATION_PATH}")
        exit()

    # Exit if no update sources given
    if 'sources' not in update_config.keys() or not update_config['sources']:
        exit()

    sources = {source['name']: source for source in update_config['sources']}
    update_start_time = now_as_iso()
    files_sha256 = []

    suricata_sources = []
    # Go through each source and download file
    for source_name, source in sources.items():
        uri: str = source['uri']

        if uri.endswith('.git'):
            files, sha256 = git_clone_repo(source)
            if sha256:
                files_sha256.extend(sha256)
            clone_dir = os.path.join(UPDATE_DIR, source_name)
            suricata_sources.append(('local', clone_dir))
        else:
            suricata_sources.append(('url', source['uri']))
            previous_update = update_config.get('previous_update', None)
            files, sha256 = url_download(source, previous_update=previous_update)
            if sha256:
                files_sha256.extend(sha256)

    if not files_sha256:
        LOGGER.info('No Suricata rule file(s) downloaded')
        exit()

    # Check if the new update hash matches the previous update hash
    new_hash = hashlib.md5(' '.join(sorted(files_sha256)).encode('utf-8')).hexdigest()
    if new_hash == update_config.get('previous_hash', None):
        # Update file(s) not changed, delete the downloaded files and exit
        shutil.rmtree(UPDATE_OUTPUT_PATH, ignore_errors=True)
        exit()

    # # We're using the '--no-test' mode because otherwise a rule failing causes *no* updates to happen
    # # A few rules typically fail out of the box because the default value for HOME_NET is 'any'
    # # and some rules check for !$HOME_NET - which suricata errors on
    # command = ["suricata-update", f"-D /tmp/suricata_data_dir", f"-o {os.path.join(UPDATE_OUTPUT_PATH, 'rules')}", "--no-test", "--force", "--verbose"]
    # for rules_source in suricata_sources:
    #     if rules_source[0] == 'url':
    #         command.extend(["--url", rules_source[1]])
    #     elif rules_source[0] == 'local':
    #         command.extend(["--local", rules_source[1]])
    # LOGGER.info(command)
    # subprocess.call(command)
    # # subprocess.call(["touch", self.oinkmaster_update_file])

    files = glob.glob(UPDATE_OUTPUT_PATH+'/*')
    LOGGER.info(files)

    LOGGER.info("Suricata rule(s) file(s) successfully downloaded")

    server = update_config['ui_server']
    user = update_config['api_user']
    api_key = update_config['api_key']
    al_client = get_client(server, apikey=(user, api_key), verify=False)

    suricata_importer = SuricataImporter(al_client)

    for path_in_dir, _, files in os.walk(UPDATE_DIR):
        for filename in files:
            source_name = os.path.splitext(os.path.basename(filename))[0]
            filepath = os.path.join(UPDATE_DIR, path_in_dir, filename)
            suricata_importer.import_file(filepath, source_name)

    previous_update = update_config.get('previous_update', '')
    if al_client.signature.update_available(since=previous_update, sig_type='suricata')['update_available']:
        LOGGER.info("AN UPDATE IS AVAILABLE TO DOWNLOAD")

        temp_zip_file = os.path.join(UPDATE_OUTPUT_PATH, 'temp.zip')
        al_client.signature.download(output=temp_zip_file, query="type:suricata AND (status:TESTING OR status:DEPLOYED)")

        if os.path.exists(temp_zip_file):
            with ZipFile(temp_zip_file, 'r') as zip_f:
                zip_f.extractall(UPDATE_OUTPUT_PATH)

            os.remove(temp_zip_file)

    combined_suricata_rules_path = '/var/lib/suricata/rules/suricata.rules'
    output_path = os.path.join(UPDATE_OUTPUT_PATH, 'suricata.rules')
    if os.path.exists(combined_suricata_rules_path):
        shutil.copyfile(combined_suricata_rules_path, output_path)

    # Create the response yaml
    with open(os.path.join(UPDATE_OUTPUT_PATH, 'response.yaml'), 'w') as yml_fh:
        yaml.safe_dump(dict(
            hash='new_hash',  # TODO if this hash doesn't change, the updater doesn't restart the service
        ), yml_fh)


if __name__ == '__main__':
    suricata_update()
