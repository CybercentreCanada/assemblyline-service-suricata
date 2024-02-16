from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater
from suricata.update.rule import parse_file

classification = forge.get_classification()


class SuricataUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(
        self,
        files_sha256,
        source_name,
        default_classification=classification.UNRESTRICTED,
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
                        dict(
                            classification=classification,
                            data=rule_signature.raw,
                            name=name,
                            revision=int(float(rule_signature.rev)),
                            signature_id=rule_signature.sid,
                            source=source_name,
                            status=status,
                            type="suricata",
                        )
                    )
                )

        total_imported = self.client.signature.add_update_many(source_name, self.updater_type, signatures)["success"]
        self.log.info(f"{total_imported} signatures were imported for source {source_name}")


if __name__ == "__main__":
    with SuricataUpdateServer(default_pattern=".*\.rules") as server:
        server.serve_forever()
