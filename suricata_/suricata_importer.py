import logging
import os
from typing import List

from suricata.update.rule import Rule, parse_file

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
DEFAULT_STATUS = "TESTING"


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

    def _save_signatures(self, signatures: List[Rule], source, default_status=DEFAULT_STATUS):
        saved_sigs = []
        order = 1
        for signature in signatures:
            name = signature.sid
            status = "DEPLOYED" if signature.enabled else default_status

            sig = Signature(dict(
                classification=self.classification.UNRESTRICTED,
                data=signature.raw,
                name=signature.msg or name,
                order=order,
                revision=int(float(signature.rev)),
                signature_id=name,
                source=source,
                status=status,
                type="suricata",
            ))
            r = self.update_client.signature.add_update(sig.as_primitives())

            if r['success']:
                self.log.info(f"Successfully added signature {name} (ID: {r['id']})")
                saved_sigs.append(sig)
                order += 1
            else:
                self.log.warning(f"Failed to add signature {name}")

        self.log.info(f"Imported {order - 1} signatures from {source} into Assemblyline")

        return saved_sigs

    def import_file(self, file_path: str, source: str, default_status=DEFAULT_STATUS):
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            signatures = parse_file(cur_file)
            return self._save_signatures(signatures, source, default_status=default_status)
        else:
            raise Exception(f"File {cur_file} does not exists.")
