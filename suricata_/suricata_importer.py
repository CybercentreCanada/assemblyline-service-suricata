import logging
import os
from copy import deepcopy
from typing import List

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from suricata.update.rule import Rule, parse_file

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)

BATCH_SIZE_LIMIT = int(os.environ.get('SIG_BATCH_SIZE', 1000))


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
        order_completed = 0
        upload_list = []
        add_update_many = self.update_client.signature.add_update_many
        for signature in signatures:
            name = signature.msg or signature.sid
            status = "DEPLOYED" if signature.enabled else "DISABLED"

            # Update metadata to include reference to signature in Assemblyline
            orig_meta, new_meta = signature.metadata, deepcopy(signature.metadata)
            new_meta.append(f"al_signature {source}.{name}")
            signature.raw = signature.raw.replace(", ".join(orig_meta), ", ".join(new_meta))

            sig = Signature(dict(
                classification=default_classification or self.classification.UNRESTRICTED,
                data=signature.raw,
                name=name,
                order=order,
                revision=int(float(signature.rev)),
                signature_id=signature.sid,
                source=source,
                status=status,
                type="suricata",
            ))

            upload_list.append(sig.as_primitives())
            order += 1
            # If we hit the batch size limit, send to API
            if order % BATCH_SIZE_LIMIT == 0:
                self.log.info(f'Batch limit reached: {BATCH_SIZE_LIMIT}. Sending batch to Signature API..')
                order_completed += add_update_many(source, 'suricata', upload_list, dedup_name=False)['success']
                upload_list = []

        order_completed += add_update_many(source, 'suricata', upload_list, dedup_name=False)['success']
        self.log.info(f"Imported {order_completed}/{order - 1} signatures"
                      f" from {os.path.basename(cur_file)} into Assemblyline")

        return order_completed

    def import_file(self, file_path: str, source: str, default_classification: str = None):
        self.log.info(f"Importing file: {file_path}")
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            signatures = parse_file(cur_file)
            return self._save_signatures(signatures, source, cur_file, default_classification=default_classification)
        else:
            raise Exception(f"File {cur_file} does not exists.")
