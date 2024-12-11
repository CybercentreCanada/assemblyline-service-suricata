import json
import os
import shutil
import tarfile
import tempfile
import time

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater, SIGNATURES_META_FILENAME, UPDATER_DIR, STATUS_FILE
from suricataparser import parse_file

classification = forge.get_classification()


class SuricataUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(
        self,
        files_sha256,
        source_name,
        default_classification=classification.UNRESTRICTED,
        *args,
        **kwargs
    ):
        signatures = []
        for file, _ in files_sha256:
            for rule_signature in parse_file(file):
                name = rule_signature.msg or rule_signature.sid
                status = "DEPLOYED" if rule_signature.enabled else "DISABLED"
                classification = default_classification or self.classification.UNRESTRICTED

                # Extract the rule's classification, if any
                for meta in rule_signature.metadata:
                    if meta.startswith("classification "):
                        classification = meta.replace("classification ", "")
                        break
                signatures.append(
                    Signature(
                        {
                            "classification": classification,
                            "data": rule_signature.raw,
                            "name": name,
                            "revision": int(float(rule_signature.rev)),
                            "signature_id": rule_signature.sid,
                            "source": source_name,
                            "status": status,
                            "type": "suricata",
                        }
                    )
                )

        total_imported = self.client.signature.add_update_many(source_name, self.updater_type, signatures)["success"]
        self.log.info(f"{total_imported} signatures were imported for source {source_name}")

    def serve_directory(self, new_directory: str, new_time: str):
        self.log.info("Update finished with new data.")
        new_tar = ""

        source_gid_map = {
            source: gid
            for gid, source in enumerate(self.datastore.signature.facet("source", query="type:suricata").keys())
        }

        # Before we package this bundle, modify the rules and insert a GID to deconflict rules with the same SID across sources
        suricata_dir = os.path.join(new_directory, "suricata")
        for source, gid in source_gid_map.items():
            source_path = os.path.join(suricata_dir, source)
            if not os.path.exists(source_path):
                continue

            # Parse and update rules with GID
            updated_rules = []
            for rule in parse_file(source_path):
                rule.add_option("gid", str(gid))
                updated_rules.append(rule.build_rule())

            # Write updated rules back to disk
            with open(source_path, "w") as file_handler:
                file_handler.write("\n".join(updated_rules))

        # Pull signature metadata from the API
        signature_map = {
            f"{source_gid_map[item['source']]}:{item['signature_id']}": item
            for item in self.datastore.signature.stream_search(
                query=self.signatures_query, fl="classification,source,status,signature_id,name", as_obj=False
            )
        }
        with open(os.path.join(new_directory, SIGNATURES_META_FILENAME), "w") as sig_file_handler:
            sig_file_handler.write(json.dumps(signature_map, indent=2))

        try:
            # Tar update directory
            with tempfile.NamedTemporaryFile(
                prefix="signatures_", dir=UPDATER_DIR, suffix=".tar.bz2", delete=False
            ) as new_tar:
                new_tar.close()
                new_tar = new_tar.name
                with tarfile.open(new_tar, "w:bz2") as tar_handle:
                    tar_handle.add(new_directory, "/")
                    tar_handle.close()

                # swap update directory with old one
                self._update_dir, new_directory = new_directory, self._update_dir
                self._update_tar, new_tar = new_tar, self._update_tar
                self._time_keeper, new_time = new_time, self._time_keeper

            # Write the new status file
            with tempfile.NamedTemporaryFile("w+", delete=False, dir="/tmp") as temp_status:
                json.dump(self.status(), temp_status.file)
                os.rename(temp_status.name, STATUS_FILE)
            self.log.info(f"Now serving: {self._update_dir} and {self._update_tar} ({self.get_local_update_time()})")
        finally:
            if new_tar and os.path.exists(new_tar):
                self.log.info(f"Remove old tar file: {new_tar}")
                time.sleep(3)
                os.unlink(new_tar)
            if new_directory and os.path.exists(new_directory):
                self.log.info(f"Remove old directory: {new_directory}")
                shutil.rmtree(new_directory, ignore_errors=True)
            if new_time and os.path.exists(new_time):
                self.log.info(f"Remove old time keeper file: {new_time}")
                os.unlink(new_time)

            # Cleanup old timekeepers/tars from unexpected termination(s) on persistent storage
            for file in os.listdir(UPDATER_DIR):
                file_path = os.path.join(UPDATER_DIR, file)
                if (
                    (file.startswith("signatures_") and file_path != self._update_tar)
                    or (file.startswith("time_keeper_") and file_path != self._time_keeper)
                    or (file.startswith("update_dir_") and file_path != self._update_dir)
                ):
                    try:
                        # Attempt to cleanup file from directory
                        os.unlink(file_path)
                    except IsADirectoryError:
                        # Remove directory using
                        shutil.rmtree(file_path, ignore_errors=True)
                    except FileNotFoundError:
                        # File has already been removed
                        pass


if __name__ == "__main__":
    with SuricataUpdateServer(default_pattern=".*\.rules") as server:
        server.serve_forever()
