import certifi
import glob
import logging
import os
import re
import requests
import shutil
import tempfile
import time

from git import Repo
from typing import List, Dict, Any
from urllib.parse import urlparse
from zipfile import ZipFile

from assemblyline_client import get_client
from assemblyline.common import log as al_log, forge
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.isotime import iso_to_epoch, epoch_to_iso
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key

from suricata_.suricata_importer import SuricataImporter

al_log.init_logging('updater.suricata')
classification = forge.get_classification()

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/suricata_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/suricata_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'suricata_updates')
LOGGER = logging.getLogger('assemblyline.updater.suricata')

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')


class SkipSource(RuntimeError):
    pass


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

    proxy = source.get('proxy', None)
    headers = source.get('headers', None)

    LOGGER.info(f"{name} source is configured to {'ignore SSL errors' if ignore_ssl_errors else 'verify SSL'}.")
    if ca_cert:
        LOGGER.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)

    # Create a requests session
    session = requests.Session()
    session.verify = not ignore_ssl_errors

    # Let https requests go through proxy
    if proxy:
        os.environ['https_proxy'] = proxy

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
                raise SkipSource()

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
            raise SkipSource()
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

            # Clear proxy setting
            if proxy:
                del os.environ['https_proxy']

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

    ignore_ssl_errors = source.get("ssl_ignore_errors", False)
    ca_cert = source.get("ca_cert")
    proxy = source.get('proxy', None)

    git_config = None
    git_env = {}

    if ignore_ssl_errors:
        git_env['GIT_SSL_NO_VERIFY'] = 1

    # Let https requests go through proxy
    if proxy:
        os.environ['https_proxy'] = proxy

    if ca_cert:
        LOGGER.info("A CA certificate has been provided with this source.")
        add_cacert(ca_cert)
        git_env['GIT_SSL_CAINFO'] = certifi.where()

    if key:
        LOGGER.info(f"key found for {url}")
        # Save the key to a file
        git_ssh_identity_file = os.path.join(tempfile.gettempdir(), 'id_rsa')
        with open(git_ssh_identity_file, 'w') as key_fh:
            key_fh.write(key)
        os.chmod(git_ssh_identity_file, 0o0400)

        git_ssh_cmd = f"ssh -oStrictHostKeyChecking=no -i {git_ssh_identity_file}"
        git_env['GIT_SSH_COMMAND'] = git_ssh_cmd

    clone_dir = os.path.join(UPDATE_DIR, name)
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)

    repo = Repo.clone_from(url, clone_dir, env=git_env, git_config=git_config)

    # Check repo last commit
    if previous_update:
        if isinstance(previous_update, str):
            previous_update = iso_to_epoch(previous_update)
        for c in repo.iter_commits():
            if c.committed_date < previous_update:
                raise SkipSource()
            break

    if pattern:
        files = [(os.path.join(clone_dir, f), get_sha256_for_file(f))
                 for f in os.listdir(clone_dir) if re.match(pattern, f)]
    else:
        files = [(f, get_sha256_for_file(f)) for f in glob.glob(os.path.join(clone_dir, '*.rules*'))]

    # Clear proxy setting
    if proxy:
        del os.environ['https_proxy']

    return files


class SuricataUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.updater_type = "suricata"

    def do_local_update(self) -> None:
        old_update_time = self.get_local_update_time()
        run_time = time.time()
        output_directory = tempfile.mkdtemp()

        self.log.info("Setup service account.")
        username = self.ensure_service_account()
        self.log.info("Create temporary API key.")
        with temporary_api_key(self.datastore, username) as api_key:
            self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}")
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)

            # Check if new signatures have been added
            self.log.info("Check for new signatures.")
            if al_client.signature.update_available(
                    since=epoch_to_iso(old_update_time) or '', sig_type=self.updater_type)['update_available']:
                self.log.info("An update is available for download from the datastore")

                extracted_zip = False
                attempt = 0

                # Sometimes a zip file isn't always returned, will affect service's use of signature source. Patience..
                while not extracted_zip and attempt < 5:
                    temp_zip_file = os.path.join(output_directory, 'temp.zip')
                    al_client.signature.download(
                        output=temp_zip_file, query=f"type:{self.updater_type} AND (status:NOISY OR status:DEPLOYED)")

                    if os.path.exists(temp_zip_file):
                        try:
                            with ZipFile(temp_zip_file, 'r') as zip_f:
                                zip_f.extractall(output_directory)
                                extracted_zip = True
                                self.log.info("Zip extracted.")
                        except Exception:
                            attempt += 1
                            self.log.warning(f"[{attempt}/5] Bad zip. Trying again after 30s...")
                            time.sleep(30)

                        os.remove(temp_zip_file)

                if attempt == 5:
                    self.log.error("Signatures aren't saved to disk. Check sources..")
                    shutil.rmtree(output_directory, ignore_errors=True)
                else:
                    self.log.info("New ruleset successfully downloaded and ready to use")
                    self.serve_directory(output_directory)
                    self.set_local_update_time(run_time)

    def do_source_update(self, service: Service) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)
            old_update_time = self.get_source_update_time()

            self.log.info("Connected!")

            # Parse updater configuration
            previous_hashes: dict[str, str] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s['name']: _s for _s in service.update_config.sources}
            files_sha256: dict[str, str] = {}
            source_default_classification = {}

            # Go through each source and download file
            for source_name, source_obj in sources.items():
                source = source_obj.as_primitives()
                uri: str = source['uri']
                cache_name = f"{source_name}.rules"
                source_default_classification[source_name] = source.get('default_classification',
                                                                        classification.UNRESTRICTED)
                try:
                    if uri.endswith('.git'):
                        files = git_clone_repo(source, previous_update=old_update_time)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256:
                                files_sha256[source_name][file] = sha256
                    else:
                        files = url_download(source, previous_update=old_update_time)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256:
                                files_sha256[source_name][file] = sha256
                except SkipSource:
                    if cache_name in previous_hashes:
                        files_sha256[cache_name] = previous_hashes[cache_name]
                    continue

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

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with SuricataUpdateServer() as server:
        server.serve_forever()
