from assemblyline.common import forge
from assemblyline_v4_service.updater.updater import ServiceUpdater
from suricata_.suricata_importer import SuricataImporter

classification = forge.get_classification()


class SuricataUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source_name, default_classification=classification.UNRESTRICTED):
        suricata_importer = SuricataImporter(client, logger=self.log)
        total_imported = 0
        for file, _ in files_sha256:
            total_imported += suricata_importer.import_file(file, source_name, default_classification)
        self.log.info(f"{total_imported} signatures were imported for source {source_name}")


if __name__ == '__main__':
    with SuricataUpdateServer(default_pattern=".*\.rules") as server:
        server.serve_forever()
