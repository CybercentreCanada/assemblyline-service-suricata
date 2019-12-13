import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid

import dateutil.parser as dateparser
import suricatasc
from retrying import retry

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection

SURICATA_BIN = "/usr/local/bin/suricata"
FILE_UPDATE_DIRECTORY = os.environ.get('FILE_UPDATE_DIRECTORY')


class Suricata(ServiceBase):
    def __init__(self, config=None):
        super(Suricata, self).__init__(config)
        self.suricata_socket = None
        self.suricata_sc = None
        self.suricata_process = None
        self.last_rule_reload = None
        self.home_net = self.config.get("home_net", "any")
        self.oinkmaster_update_file = '/etc/suricata/suricata-rules-update'
        self.run_dir = None
        self.suricata_rules_file = None

    # Use an external tool to strip frame headers
    def strip_frame_headers(self, filepath):
        new_filepath = os.path.join(os.path.dirname(filepath), "striped.pcap")
        command = ["/usr/local/bin/stripe", "-r", filepath, "-w", new_filepath]

        subprocess.call(command)

        return new_filepath

    def start(self):
        if not os.path.exists(FILE_UPDATE_DIRECTORY):
            raise Exception("Suricata rules directory not found")

        suricata_rules_dirs = [x for x in sorted(os.listdir(FILE_UPDATE_DIRECTORY), reverse=True) if
                               not x.startswith('.tmp')]

        for suricata_rules_dir in suricata_rules_dirs:
            self.suricata_rules_file = os.path.join(suricata_rules_dir, 'suricata.rules')
            self.run_dir = tempfile.mkdtemp(dir="/tmp")
            self.replace_suricata_config()
            self.start_suricata_if_necessary()
            if self.suricata_running():
                break

        if not self.suricata_running():
            raise Exception("Unable to start Suricata because no Suricata rules were found")

    def _get_suricata_version(self):
        version_string = subprocess.check_output(["suricata", "-V"]).strip().replace(b"This is Suricata version ",
                                                                                     b"").replace(b" ", b"_")
        return version_string.decode()

    def get_tool_version(self):
        """
        Use the modification timestamp of the rules file as well as the suricata version
        :return:
        """
        return f"{self._get_suricata_version()}-{os.path.getmtime(self.oinkmaster_update_file)}"

    # When we're shutting down, kill the Suricata child process as well
    def stop(self):
        self.kill_suricata()
        if self.run_dir is not None:
            if os.path.exists(self.run_dir):
                shutil.rmtree(self.run_dir)
            self.run_dir = None

    # Kill the process if it isn't ending
    def kill_suricata(self):
        if self.suricata_process:
            try:
                self.log.info(f"Trying to kill Suricata ({str(self.suricata_process.pid)})")
                self.suricata_process.kill()
            except Exception as e:
                self.log.exception(f"Failed to kill Suricata ({str(self.suricata_process.pid)}): {str(e)}")

    # Reapply our service configuration to the Suricata yaml configuration
    def replace_suricata_config(self):
        source_path = os.path.join(os.getcwd(), 'suricata_', 'conf', 'suricata.yaml')
        dest_path = os.path.join(self.run_dir, 'suricata.yaml')
        # home_net = re.sub(r"([/\[\]])", r"\\\1", self.home_net)
        home_net = self.home_net
        with open(source_path) as sp:
            with open(dest_path, "w") as dp:
                dp.write(sp.read().replace("__HOME_NET__", home_net))

    def reload_rules_if_necessary(self):
        if self.last_rule_reload < os.path.getmtime(self.oinkmaster_update_file):
            self.reload_rules()

    # Send the reload_rules command to the socket
    def reload_rules(self):
        self.log.info("Reloading suricata rules...")
        ret = self.suricata_sc.send_command("reload-rules")

        if not ret or ret.get("return", "") != "OK":
            self.log.exception("Failed to reload Suricata rules")
            return

        self.last_rule_reload = time.time()

        # Get rule stats
        ret = self.suricata_sc.send_command("ruleset-stats")
        if ret:
            self.log.info(f"Current ruleset stats: {str(ret.get('message'))}")

    def start_suricata_if_necessary(self):
        if not self.suricata_running():
            self.launch_suricata()

    # Try connecting to the Suricata socket
    def suricata_running(self):
        if self.suricata_sc is None:
            return False
        try:
            self.suricata_sc.connect()
        except suricatasc.SuricataException:
            return False
        return True

    # Retry with exponential backoff until we can actually connect to the Suricata socket
    @retry(retry_on_result=lambda x: x is False, wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_delay=120000)
    def suricata_running_retry(self):
        return self.suricata_running()

    # Launch Suricata using a UID socket
    def launch_suricata(self):
        self.suricata_socket = os.path.join(self.run_dir, str(uuid.uuid4()) + '.socket')

        command = [
            SURICATA_BIN,
            "-c", os.path.join(self.run_dir, 'suricata.yaml'),
            f"--unix-socket={self.suricata_socket}",
            "--pidfile", f"{self.run_dir}/suricata.pid",
            "--set", f"logging.outputs.1.file.filename={os.path.join(self.run_dir, 'suricata.log')}",
            "-S", self.suricata_rules_file,
        ]

        self.log.info(f"Launching Suricata: {' '.join(command)}")

        self.suricata_process = subprocess.Popen(command)

        self.suricata_sc = suricatasc.SuricataSC(self.suricata_socket)

        if not self.suricata_running_retry():
            raise Exception('Suricata could not be started.')
        self.last_rule_reload = time.time()

    def execute(self, request):
        file_path = request.file_path
        result = Result()

        # Report the version of suricata as the service context
        request.set_service_context(f"Suricata version: {self._get_suricata_version()}")

        # restart Suricata if we need to
        self.start_suricata_if_necessary()

        # Update our rules if they're stale,
        self.reload_rules_if_necessary()

        # Strip frame headers from the PCAP, since Suricata sometimes has trouble parsing strange PCAPs
        stripped_filepath = self.strip_frame_headers(file_path)

        # Check to make sure the size of the stripped file isn't 0 - this happens on pcapng files
        # TODO: there's probably a better way to do this - don't event strip it if it's pcapng
        if os.stat(stripped_filepath).st_size == 0:
            stripped_filepath = file_path

        # Pass the pcap file to Suricata via the socket
        ret = self.suricata_sc.send_command("pcap-file", {
            "filename": stripped_filepath,
            "output-dir": self.working_directory
        })

        if not ret or ret["return"] != "OK":
            self.log.exception(f"Failed to submit PCAP for processing: {ret['message']}")

        # Wait for the socket finish processing our PCAP
        while True:
            time.sleep(1)
            ret = self.suricata_sc.send_command("pcap-current")

            if ret and ret["message"] == "None":
                break

        alerts = {}
        signatures = {}
        domains = []
        ips = []
        urls = []
        net_email = []

        # tls stuff
        tls_dict = {}

        file_extracted_reported = False

        # Parse the json results of the service
        for line in open(os.path.join(self.working_directory, 'eve.json')):
            record = json.loads(line)

            timestamp = dateparser.parse(record['timestamp']).isoformat(' ')
            src_ip = record.get('src_ip')
            src_port = record.get('src_port')
            dest_ip = record.get('dest_ip')
            dest_port = record.get('dest_port')

            if src_ip is not None and src_ip not in ips:
                ips.append(src_ip)
            if dest_ip is not None and dest_ip not in ips:
                ips.append(dest_ip)

            if record['event_type'] == 'http':
                if 'hostname' not in record['http'] or 'url' not in record['http']:
                    continue

                domain = record['http']['hostname']
                if domain not in domains and domain not in ips:
                    domains.append(domain)
                url = "http://" + domain + record['http']['url']
                if url not in urls:
                    urls.append(url)

            if record['event_type'] == 'dns':
                if 'rrname' not in record['dns']:
                    continue
                domain = record['dns']['rrname']
                if domain not in domains and domain not in ips:
                    domains.append(domain)

            if record['event_type'] == 'alert':
                if 'signature_id' not in record['alert'] or 'signature' not in record['alert']:
                    continue
                signature_id = record['alert']['signature_id']
                signature = record['alert']['signature']

                if signature_id not in alerts:
                    alerts[signature_id] = []
                if signature_id not in signatures:
                    signatures[signature_id] = signature

                alerts[signature_id].append(f"{timestamp} {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

            if record["event_type"] == "smtp":
                # extract email metadata
                if "smtp" not in record:
                    continue
                if not isinstance(record["smtp"], dict):
                    continue

                mail_from = record["smtp"]["mail_from"]
                if mail_from is not None:
                    mail_from = mail_from.replace("<", "").replace(">", "")
                    if mail_from not in net_email:
                        net_email.append(mail_from)

                for email_addr in record["smtp"]["rcpt_to"]:
                    email_addr = email_addr.replace("<", "").replace(">", "")
                    if email_addr not in net_email:
                        net_email.append(email_addr)

            if record["event_type"] == "tls":
                if "tls" not in record:
                    continue
                if not isinstance(record["tls"], dict):
                    continue

                for tls_type, tls_value in record["tls"].items():
                    if tls_type not in tls_dict:
                        tls_dict[tls_type] = []
                    if tls_value not in tls_dict[tls_type]:
                        tls_dict[tls_type].append(tls_value)

            # Check to see if any files were extracted
            if request.get_param("extract_files") and record["event_type"] == "fileinfo":
                filename = os.path.basename(record["fileinfo"]["filename"])
                extracted_file_path = os.path.join(self.working_directory,
                                                   'filestore',
                                                   record["fileinfo"]["sha256"][:2].lower(),
                                                   record["fileinfo"]["sha256"])

                self.log.info(f"extracted file {filename}")

                request.add_extracted(extracted_file_path, filename, "Extracted by suricata")

                # Report a null score to indicate that files were extracted. If no sigs hit, it's not clear
                # where the extracted files came from
                if not file_extracted_reported:
                    file_extracted_reported = True
                    result.add_section(ResultSection("Files extracted by suricata"))

        # Add tags for the domains, urls, and IPs we've discovered
        root_section = ResultSection("Discovered IOCs")
        for domain in domains:
            root_section.add_tag('network.static.domain', domain)
        for url in urls:
            root_section.add_tag('network.static.uri', url)
        for ip in ips:
            # Make sure it's not a local IP
            if not (ip.startswith("127.")
                    or ip.startswith("192.168.")
                    or ip.startswith("10.")
                    or (ip.startswith("172.")
                        and 16 <= int(ip.split(".")[1]) <= 31)):
                root_section.add_tag('network.static.ip', ip)

        for eml in net_email:
            root_section.add_tag('network.email.address', eml)

        # Map between suricata key names and AL tag types
        tls_mappings = {
            "subject": 'cert.subject',
            "issuerdn": 'cert.issuer',
            "version": 'cert.version',
            "notbefore": 'cert.valid.start',
            "notafter": 'cert.valid.end',
            "fingerprint": 'cert.thumbprint',
            "sni": 'network.static.domain'
        }
        for tls_type, tls_values in tls_dict.items():
            if tls_type in tls_mappings:
                tag_type = tls_mappings[tls_type]

                if tag_type is not None:
                    for tls_value in tls_values:
                        if tls_type == "fingerprint":
                            # make sure the cert fingerprint/thumbprint matches other values,
                            # like from PEFile
                            tls_value = tls_value.replace(":", "").lower()
                        root_section.add_tag(tag_type, tls_value)

            elif tls_type == "ja3":
                for ja3_entry in tls_values:
                    ja3_hash = ja3_entry.get("hash")
                    ja3_string = ja3_entry.get("string")
                    if ja3_hash:
                        root_section.add_tag('network.tls.ja3_hash', ja3_hash)
                    if ja3_string:
                        root_section.add_tag('network.tls.ja3_string', ja3_string)

            else:
                # stick a message in the logs about a new TLS type found in suricata logs
                self.log.info(f"Found new TLS type {tls_type} with values {tls_values}")

        # Create the result sections if there are any hits
        if len(alerts) > 0:
            for signature_id, signature in signatures.items():
                section = ResultSection(f'{signature_id}: {signature}')
                if any(x in signature for x in self.config.get("sure_score")):
                    section.set_heuristic(1)

                if any(x in signature for x in self.config.get("vhigh_score")):
                    section.set_heuristic(2)

                for flow in alerts[signature_id][:10]:
                    section.add_line(flow)
                if len(alerts[signature_id]) > 10:
                    section.add_line(f'And {len(alerts[signature_id]) - 10} more flows')

                # Add a tag for the signature id and the message
                section.add_tag('network.signature.signature_id', str(signature_id))
                section.add_tag('network.signature.message', signature)

                result.add_section(section)

            # Add the original Suricata output as a supplementary file in the result
            request.add_supplementary(os.path.join(self.working_directory, 'eve.json'), 'SuricataEventLog.json', 'json')

        # Add the stats.log to the result, which can be used to determine service success
        if os.path.exists(os.path.join(self.working_directory, 'stats.log')):
            request.add_supplementary(os.path.join(self.working_directory, 'stats.log'), 'stats.log', 'log')

        request.result = result
