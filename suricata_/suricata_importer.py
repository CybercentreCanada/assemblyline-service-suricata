import logging
import os
from typing import List

from suricata.update.rule import Rule, parse_file

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)


class SuricataImporter:
    def __init__(self, al_client, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('suricata_importer')
            logger = logging.getLogger('assemblyline.suricata_importer')
            logger.setLevel(logging.INFO)

        self.update_client = al_client

        self.classification = forge.get_classification()
        self.log = logger

    def _save_signatures(self, signatures: List[Rule], source, cur_file, default_classification=None):
        order = 1
        upload_list = []
        for signature in signatures:
            name = signature.sid
            status = "DEPLOYED" if signature.enabled else "DISABLED"

            sig = Signature(dict(
                classification=default_classification or self.classification.UNRESTRICTED,
                data=signature.raw,
                name=signature.msg or name,
                order=order,
                revision=int(float(signature.rev)),
                signature_id=name,
                source=source,
                status=status,
                type="suricata",
            ))

            upload_list.append(sig.as_primitives())
            order += 1

        r = self.update_client.signature.add_update_many(source, 'suricata', upload_list, dedup_name=False)
        self.log.info(f"Imported {r['success']}/{order - 1} signatures"
                      f" from {os.path.basename(cur_file)} into Assemblyline")

        return r['success']

    def import_file(self, file_path: str, source: str, default_classification: str = None):
        self.log.info(f"Importing file: {file_path}")
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            signatures = parse_file(cur_file)
            return self._save_signatures(signatures, source, cur_file, default_classification=default_classification)
        else:
            raise Exception(f"File {cur_file} does not exists.")
