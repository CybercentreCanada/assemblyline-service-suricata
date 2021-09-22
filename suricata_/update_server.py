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
from assemblyline_v4_service.updater.helper import git_clone_repo, url_download, SkipSource

from suricata_.suricata_importer import SuricataImporter

al_log.init_logging('updater.suricata')
classification = forge.get_classification()

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', "/tmp/suricata_updater_config.yaml")
UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/suricata_updater_output")
UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'suricata_updates')

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')


class SuricataUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.updater_type = "suricata"

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
                        files = git_clone_repo(source, old_update_time, "*.rules", self.log, UPDATE_DIR)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256:
                                files_sha256[source_name][file] = sha256
                    else:
                        files = url_download(source, old_update_time, self.log, UPDATE_DIR)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            if previous_hashes.get(source_name, {}).get(file, None) != sha256:
                                files_sha256[source_name][file] = sha256
                except SkipSource:
                    if cache_name in previous_hashes:
                        files_sha256[cache_name] = previous_hashes[cache_name]
                    continue

            if files_sha256:
                self.log.info("Found new Suricata rule files to process!")

                suricata_importer = SuricataImporter(al_client, logger=self.log)

                for source, source_val in files_sha256.items():
                    total_imported = 0
                    default_classification = source_default_classification[source]
                    for file in source_val.keys():
                        total_imported += suricata_importer.import_file(file, source,
                                                                        default_classification=default_classification)
                    self.log.info(f"{total_imported} signatures were imported for source {source}")

            else:
                self.log.info('No new Suricata rule files to process')

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with SuricataUpdateServer() as server:
        server.serve_forever()
