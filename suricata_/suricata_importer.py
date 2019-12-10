import logging
import os
from typing import List

from suricata.update.rule import Rule, parse_file

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
DEFAULT_STATUS = "TESTING"


class SuricataImporter(object):
    def __init__(self, al_client, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('suricata_importer')
            logger = logging.getLogger('assemblyline.suricata_importer')
            logger.setLevel(logging.INFO)

        self.update_client = al_client

        self.classification = forge.get_classification()
        self.log = logger

    # @staticmethod
    # def get_signature_name(signature):
    #     name = None
    #     for line in signature.splitlines():
    #         line = line.strip()
    #         if line.startswith("rule ") or line.startswith("private rule ") \
    #                 or line.startswith("global rule ") or line.startswith("global private rule "):
    #             name = line.split(":")[0].split("{")[0]
    #             name = name.replace("global ", "").replace("private ", "").replace("rule ", "")
    #             break
    #
    #     if name is None:
    #         return name
    #     return name.strip()

    # @staticmethod
    # def parse_meta(signature):
    #     meta = {}
    #     meta_started = False
    #     for line in signature.splitlines():
    #         line = line.strip()
    #         if not meta_started and line.startswith('meta') and line.endswith(':'):
    #             meta_started = True
    #             continue
    #
    #         if meta_started:
    #             if line.startswith("//") or line == "":
    #                 continue
    #
    #             if "=" not in line:
    #                 break
    #
    #             key, val = line.split("=", 1)
    #             key = key.strip()
    #             val = val.strip().strip('"')
    #             meta[key] = safe_str(val)
    #
    #     return meta

    def _save_signatures(self, signatures: List[Rule], source, default_status=DEFAULT_STATUS):
        saved_sigs = []
        order = 1
        for signature in signatures:
            # name = self.get_signature_name(signature)
            # classification = meta.get('classification', self.classification.UNRESTRICTED)

            # status = meta.get('status', meta.get('al_status', default_status))

            # # Convert CCCS YARA status to AL signature status
            # if status == "RELEASED":
            #     status = "DEPLOYED"
            # elif status == "DEPRECATED":
            #     status = "DISABLED"

            sig = Signature(dict(
                classification=self.classification.UNRESTRICTED,
                data=signature.raw,
                name=signature.sid,
                order=order,
                revision=int(float(signature.rev)),
                signature_id=signature.sid,
                source=source,
                status=default_status,
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

    # @ staticmethod
    # def _split_signatures(data):
    #     from suricata.update.rule import parse_file
    #     parse_file()
    #
    #     current_signature = []
    #     signatures = []
    #     in_rule = False
    #     for line in data.splitlines():
    #         temp_line = line.strip()
    #
    #         if in_rule:
    #             current_signature.append(line)
    #
    #             if temp_line == "}":
    #                 signatures.append("\n".join(current_signature))
    #                 current_signature = []
    #                 in_rule = False
    #         else:
    #             if temp_line.startswith("import ") \
    #                     or temp_line.startswith("rule ") \
    #                     or temp_line.startswith("private rule ") \
    #                     or temp_line.startswith("global rule ") \
    #                     or temp_line.startswith("global private rule "):
    #                 in_rule = True
    #                 current_signature.append(line)
    #
    #     return signatures

    # def import_data(self, yara_bin, source, default_status=DEFAULT_STATUS):
    #     return self._save_signatures(self._split_signatures(yara_bin), source, default_status=default_status)

    def import_file(self, file_path: str, source: str, default_status=DEFAULT_STATUS):
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            signatures = parse_file(cur_file)
            return self._save_signatures(signatures, source, default_status=default_status)

            # with open(cur_file, "r") as yara_file:
            #     yara_bin = yara_file.read()
            #     return self.import_data(yara_bin, source or os.path.basename(cur_file), default_status=default_status)
        else:
            raise Exception(f"File {cur_file} does not exists.")
