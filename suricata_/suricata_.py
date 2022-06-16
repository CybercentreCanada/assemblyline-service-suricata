import dateutil.parser as dateparser
import json
import os
import subprocess
import suricatasc
import sys
import time
import yaml

from copy import deepcopy
from io import StringIO
from retrying import retry, RetryError
from socket import getservbyport
from typing import Dict, Any

from assemblyline.common.exceptions import RecoverableError
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.ontology.results import NetworkConnection, Signature
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import MaxExtractedExceeded
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection

SURICATA_BIN = "/usr/local/bin/suricata"


class Suricata(ServiceBase):
    def __init__(self, config=None):
        super(Suricata, self).__init__(config)

        self.home_net = self.config.get("home_net", "any")
        self.rules_config = yaml.safe_dump({"rule-files": []})
        self.run_dir = "/var/run/suricata"
        self.suricata_socket = None
        self.suricata_sc = None
        self.suricata_process = None
        self.suricata_yaml = "/etc/suricata/suricata.yaml"
        self.suricata_log = "/var/log/suricata/suricata.log"

    # Use an external tool to strip frame headers
    @staticmethod
    def strip_frame_headers(filepath):
        new_filepath = os.path.join(os.path.dirname(filepath), "striped.pcap")
        command = ["/usr/local/bin/stripe", "-r", filepath, "-w", new_filepath]

        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, _ = p.communicate()

        return new_filepath

    def start(self):
        self.log.info(f"Suricata started with service version: {self.get_service_version()}")

    def _load_rules(self) -> None:
        if not self.rules_list:
            self.log.warning("No valid suricata ruleset found. Suricata will run without rules...")

        self.rules_config = yaml.safe_dump({"rule-files": self.rules_list})

        if not os.path.exists(self.run_dir):
            os.makedirs(self.run_dir)

        self.replace_suricata_config()
        self.start_suricata_if_necessary()

        if not self.suricata_running():
            raise Exception("Unable to start Suricata because no Suricata rules were found")

        # Get rule stats
        ret = self.suricata_sc.send_command("ruleset-stats")
        if ret:
            for ruleset in ret.get('message'):
                self.log.info(f"Ruleset {ruleset['id']}: {ruleset['rules_loaded']} rules loaded")
                if ruleset['rules_failed'] and ruleset['rules_loaded'] == 0:
                    self.log.error(f"Ruleset {ruleset['id']}: {ruleset['rules_failed']} rules failed to load")
                else:
                    self.log.warning(f"Ruleset {ruleset['id']}: {ruleset['rules_failed']} rules failed to load."
                                     "This can be due to duplication of rules among muliple rulesets being loaded.")

    def get_suricata_version(self):
        return safe_str(subprocess.check_output(["suricata", "-V"]).strip().replace(b"This is Suricata version ", b""))

    def get_tool_version(self):
        """
        Return the version of suricata used for processing
        :return:
        """
        return f'{self.get_suricata_version()}.r{self.rules_hash}'

    # When we're shutting down, kill the Suricata child process as well
    def stop(self):
        self.kill_suricata()

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
        dest_path = self.suricata_yaml
        # home_net = re.sub(r"([/\[\]])", r"\\\1", self.home_net)
        home_net = self.home_net
        with open(source_path) as sp:
            with open(dest_path, "w") as dp:
                dp.write(sp.read().replace("__HOME_NET__", home_net).replace("__RULE_FILES__", self.rules_config))

    # Send the reload_rules command to the socket
    def reload_rules(self):
        self.log.info("Reloading suricata rules...")
        ret = self.suricata_sc.send_command("reload-rules")

        if not ret or ret.get("return", "") != "OK":
            self.log.exception("Failed to reload Suricata rules")
            return

        # Get rule stats
        ret = self.suricata_sc.send_command("ruleset-stats")
        if ret:
            self.log.info(f"Current ruleset stats: {str(ret.get('message'))}")

    def start_suricata_if_necessary(self):
        if not self.suricata_running():
            try:
                self.launch_or_load_suricata()
            except RetryError as e:
                raise RecoverableError(e)

    # Try connecting to the Suricata socket
    def suricata_running(self):
        if self.suricata_sc is None:
            return False
        try:
            self.suricata_sc.connect()
        except suricatasc.SuricataException as e:
            if "Transport endpoint is already connected" in str(e):
                return True
            self.log.info(f"Suricata not started yet: {str(e)}")
            return False
        return True

    # Retry with exponential backoff until we can actually connect to the Suricata socket
    @retry(retry_on_result=lambda x: x is False, wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_delay=120000)
    def suricata_running_retry(self):
        return self.suricata_running()

    # Launch Suricata using a UID socket
    def launch_or_load_suricata(self):
        self.suricata_socket = os.path.join(self.run_dir, 'suricata.socket')

        if not os.path.exists(self.suricata_socket):
            command = [
                SURICATA_BIN,
                "-vvvv",  # Useful for debugging
                "-c", self.suricata_yaml,
                f"--unix-socket={self.suricata_socket}",
                "--pidfile", f"{self.run_dir}/suricata.pid",
                "--set", f"logging.outputs.1.file.filename={self.suricata_log}",
            ]

            self.log.info(f"Launching Suricata: {' '.join(command)}")

            self.suricata_process = subprocess.Popen(command)

        self.suricata_sc = suricatasc.SuricataSC(self.suricata_socket)

        if not self.suricata_running_retry():
            raise Exception('Suricata could not be started.')

    def parse_suricata_output(self):
        alerts = {}
        signatures = {}
        domains = []
        ips = []
        urls = []
        email_addresses = []
        tls_dict = {}
        extracted_files = {}

        reverse_lookup = {}
        event_types = {
            'dns': [],
            'http': [],
            'alert': [],
            'smpt': [],
            'tls': [],
            'fileinfo': [],
        }
        # Parse the json results of the service and organize them into certain categories
        for line in open(os.path.join(self.working_directory, 'eve.json')):
            record = json.loads(line)
            if record['event_type'] in event_types.keys():
                event_types[record['event_type']].append(record)

        ordered_records = []
        oid_lookup = dict()
        [ordered_records.extend(record) for record in event_types.values()]
        for record in ordered_records:
            timestamp = dateparser.parse(record['timestamp']).isoformat(' ')
            src_ip = record.get('src_ip')
            src_port = record.get('src_port')
            dest_ip = record.get('dest_ip')
            dest_port = record.get('dest_port')
            proto = record.get('proto', 'TCP').lower()
            connection_info = f"{src_ip}:{src_port} -> {dest_ip}:{dest_port}"

            network_data = {
                'objectid': {
                    'tag': f"{reverse_lookup.get(dest_ip, dest_ip)}" + f"{f':{dest_port}' if dest_port else ''}",
                    'time_observed': timestamp
                },
                'source_ip': src_ip,
                'source_port': src_port,
                'destination_ip': dest_ip,
                'destination_port': dest_port,
                'transport_layer_protocol': proto,
                'direction': 'outbound',
            }

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
                network_data['connection_type'] = 'http'
                http_details = record['http']
                network_data['http_details'] = {
                    'request_uri': http_details['hostname'] + http_details['url'],
                    'request_headers': {h['name'].replace('-', '_').lower(): h['value'] for h in http_details['request_headers']},
                    'request_method': http_details['http_method'].upper(),
                    'response_headers': {h['name'].replace('-', '_').lower(): h['value'] for h in http_details['response_headers']},
                    'response_status_code': http_details['status'],
                }
                network_data['objectid']['ontology_id'] = NetworkConnection.get_oid(network_data)
                self.ontology.add_result_part(NetworkConnection, network_data)
                # Add ObjectID to lookup for signatures/alerts
                oid_lookup[connection_info] = network_data['objectid']


            elif record['event_type'] == 'dns':
                if 'rrname' not in record['dns']:
                    continue
                domain = record['dns']['rrname']
                if domain not in domains and domain not in ips:
                    domains.append(domain)
                network_data['connection_type'] = 'dns'
                for lookup_type, resolved_ips in record["dns"].get("grouped", {}).items():
                    reverse_lookup.update({ip: domain for ip in resolved_ips})
                    network_data['objectid']['tag'] = f"{reverse_lookup.get(dest_ip, dest_ip)}" + \
                        f"{f':{dest_port}' if dest_port else ''}"

                    data = deepcopy(network_data)
                    data['dns_details'] = {
                        'domain': domain,
                        'resolved_ips': resolved_ips,
                        'lookup_type': lookup_type
                    }
                    data['objectid']['ontology_id'] = NetworkConnection.get_oid(data)
                    self.ontology.add_result_part(NetworkConnection, data)
                    # Add ObjectID to lookup for signatures/alerts
                    oid_lookup[connection_info] = data['objectid']

            elif record['event_type'] == 'alert':
                if 'signature_id' not in record['alert'] or 'signature' not in record['alert']:
                    continue
                signature_id = record['alert']['signature_id']
                signature = record['alert']['signature']
                if signature_id not in alerts:
                    alerts[signature_id] = []
                if signature_id not in signatures:
                    try:
                        proto = getservbyport(dest_port) if dest_port else 'http'
                    except OSError:
                        proto = 'http'

                    attribute = dict(source=oid_lookup[connection_info], domain=reverse_lookup.get(dest_ip))
                    if record.get('http'):
                        # Only alerts containing HTTP details can provide URI-relevant information
                        attribute.update({'uri': f"{proto}://{record['http']['hostname']+record['http']['url']}"})

                    signatures[signature_id] = {
                        "signature": signature,
                        "malware_family": record['alert'].get('metadata', {}).get('malware_family', []),
                        "al_signature": record['alert']['metadata'].get("al_signature", [None])[0],
                        'attributes': [attribute]
                    }
                alerts[signature_id].append(f"{timestamp} {connection_info}")

            elif record["event_type"] == "smtp":
                # extract email metadata
                if "smtp" not in record:
                    continue
                if not isinstance(record["smtp"], dict):
                    continue

                mail_from = record["smtp"].get("mail_from")
                if mail_from is not None:
                    mail_from = mail_from.replace("<", "").replace(">", "")
                    if mail_from not in email_addresses:
                        email_addresses.append(mail_from)

                for email_addr in record["smtp"].get("rcpt_to", []):
                    email_addr = email_addr.replace("<", "").replace(">", "")
                    if email_addr not in email_addresses:
                        email_addresses.append(email_addr)

            elif record["event_type"] == "tls":
                if "tls" not in record:
                    continue
                if not isinstance(record["tls"], dict):
                    continue

                for tls_type, tls_value in record["tls"].items():
                    if tls_type not in tls_dict:
                        tls_dict[tls_type] = []
                    if tls_value not in tls_dict[tls_type]:
                        tls_dict[tls_type].append(tls_value)

            elif record["event_type"] == "fileinfo":
                sha256_full = record['fileinfo']['sha256']
                if sha256_full not in extracted_files.keys():
                    sha256 = f"{sha256_full[:12]}.data"
                    extracted_files['sha256_full'] = {
                        'sha256': sha256, 'filename': os.path.basename(record["fileinfo"].get('filename', sha256)),
                        'extracted_file_path': os.path.join(
                            self.working_directory, 'filestore', sha256_full[: 2].lower(),
                            sha256_full)}
        return dict(alerts=alerts, signatures=signatures, domains=domains, ips=ips, urls=urls,
                    email_addresses=email_addresses, tls=tls_dict, extracted_files=extracted_files.values())

    def execute(self, request):
        file_path = request.file_path
        result = Result()

        # Report the version of suricata as the service context
        request.set_service_context(f"Suricata version: {self.get_suricata_version()}")

        # restart Suricata if we need to
        self.start_suricata_if_necessary()

        # Strip frame headers from the PCAP, since Suricata sometimes has trouble parsing strange PCAPs
        stripped_filepath = self.strip_frame_headers(file_path)

        # Check to make sure the size of the stripped file isn't 0 - this happens on pcapng files
        # TODO: there's probably a better way to do this - don't event strip it if it's pcapng
        if os.stat(stripped_filepath).st_size == 0:
            stripped_filepath = file_path

        # Switch stdout and stderr so we don't get our logs polluted
        mystdout = StringIO()
        old_stdout = sys.stdout
        sys.stdout = mystdout

        mystderr = StringIO()
        old_stderr = sys.stderr
        sys.stderr = mystderr

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
            try:
                ret = self.suricata_sc.send_command("pcap-current")
                if ret and ret["message"] == "None":
                    break
            except ConnectionResetError as e:
                raise RecoverableError(e)

        # Bring back stdout and stderr
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        # NOTE: for now we will ignore content of mystdout and mystderr but we have them just in case...

        alerts, signatures, domains, ips, urls, email_addresses, tls_dict, extracted_files = self.parse_suricata_output().values()

        file_extracted_section = ResultSection("File(s) extracted by Suricata")
        # Parse the json results of the service
        if request.get_param("extract_files"):
            for file in extracted_files:
                sha256, filename, extracted_file_path = file.values()
                self.log.info(f"extracted file {filename}")
                try:
                    if request.add_extracted(extracted_file_path, filename, "Extracted by Suricata",
                                             safelist_interface=self.api_interface):
                        file_extracted_section.add_line(filename)
                        if filename != sha256:
                            file_extracted_section.add_tag('file.name.extracted', filename)
                except FileNotFoundError as e:
                    # An intermittent issue, just try again
                    raise RecoverableError(e)
                except MaxExtractedExceeded:
                    # We've hit our limit
                    pass

        # Report a null score to indicate that files were extracted. If no sigs hit, it's not clear
        # where the extracted files came from
        if file_extracted_section.body:
            result.add_section(file_extracted_section)

        # Add tags for the domains, urls, and IPs we've discovered
        root_section = ResultSection("Discovered IOCs", parent=result)
        if domains:
            domain_section = ResultSection("Domains", parent=root_section)
            for domain in domains:
                domain_section.add_line(domain)
                domain_section.add_tag('network.dynamic.domain', domain)
        if ips:
            ip_section = ResultSection("IP Addresses", parent=root_section)
            for ip in ips:
                # Make sure it's not a local IP
                if not (ip.startswith("127.")
                        or ip.startswith("192.168.")
                        or ip.startswith("10.")
                        or (ip.startswith("172.")
                            and 16 <= int(ip.split(".")[1]) <= 31)):
                    ip_section.add_line(ip)
                    ip_section.add_tag('network.dynamic.ip', ip)

        if urls:
            url_section = ResultSection("URLs", parent=root_section)
            for url in urls:
                url_section.add_line(url)
                url_section.add_tag('network.dynamic.uri', url)
        if email_addresses:
            email_section = ResultSection("Email Addresses", parent=root_section)
            for eml in email_addresses:
                email_section.add_line(eml)
                email_section.add_tag('network.email.address', eml)

        # Map between suricata key names and AL tag types
        tls_mappings = {
            "subject": 'cert.subject',
            "issuerdn": 'cert.issuer',
            "version": 'cert.version',
            "notbefore": 'cert.valid.start',
            "notafter": 'cert.valid.end',
            "fingerprint": 'cert.thumbprint',
            "sni": 'network.tls.sni'
        }

        if tls_dict:
            tls_section = ResultSection("TLS Information", parent=root_section,
                                        body_format=BODY_FORMAT.JSON)
            kv_body = {}
            for tls_type, tls_values in tls_dict.items():
                if tls_type == "fingerprint":
                    # make sure the cert fingerprint/thumbprint matches other values,
                    # like from PEFile
                    tls_values = [v.replace(":", "").lower() for v in tls_values]

                if tls_type in tls_mappings:
                    kv_body[tls_type] = tls_values

                    tag_type = tls_mappings[tls_type]
                    if tag_type is not None:
                        for tls_value in tls_values:
                            tls_section.add_tag(tag_type, tls_value)

                elif tls_type == "ja3":
                    kv_body.setdefault('ja3_hash', [])
                    kv_body.setdefault('ja3_string', [])

                    for ja3_entry in tls_values:
                        ja3_hash = ja3_entry.get("hash")
                        ja3_string = ja3_entry.get("string")
                        if ja3_hash:
                            kv_body['ja3_hash'].append(ja3_hash)
                            tls_section.add_tag('network.tls.ja3_hash', ja3_hash)
                        if ja3_string:
                            kv_body['ja3_string'].append(ja3_string)
                            tls_section.add_tag('network.tls.ja3_string', ja3_string)

                else:
                    kv_body[tls_type] = tls_values
                    # stick a message in the logs about a new TLS type found in suricata logs
                    self.log.info(f"Found new TLS type {tls_type} with values {tls_values}")
            tls_section.set_body(json.dumps(kv_body))

        # Create the result sections if there are any hits
        if len(alerts) > 0:
            for signature_id, signature_details in signatures.items():
                signature = signature_details['signature']
                attributes = signature_details['attributes']
                section = ResultSection(f'{signature_id}: {signature}')
                heur_id = 3
                if any(x in signature for x in self.config.get("sure_score")):
                    heur_id = 1
                elif any(x in signature for x in self.config.get("vhigh_score")):
                    heur_id = 2

                section.set_heuristic(heur_id)
                if signature_details['al_signature']:
                    section.add_tag("file.rule.suricata", signature_details['al_signature'])
                for flow in alerts[signature_id][:10]:
                    section.add_line(flow)
                if len(alerts[signature_id]) > 10:
                    section.add_line(f'And {len(alerts[signature_id]) - 10} more flows')

                # Add a tag for the signature id and the message
                section.add_tag('network.signature.signature_id', str(signature_id))
                section.add_tag('network.signature.message', signature)
                [section.add_tag('network.static.uri', attr['uri']) for attr in attributes if attr.get('uri')]
                # Tag malware_family
                for malware_family in signature_details['malware_family']:
                    section.add_tag('attribution.family', malware_family)

                result.add_section(section)
                self.ontology.add_result_part(
                    Signature,
                    data=dict(
                        name=signature_details['al_signature'],
                        type="SURICATA", malware_family=signature_details['malware_family'] or None,
                        attributes=attributes))

            # Add the original Suricata output as a supplementary file in the result
            request.add_supplementary(os.path.join(self.working_directory, 'eve.json'), 'SuricataEventLog.json', 'json')

        # Add the stats.log to the result, which can be used to determine service success
        if os.path.exists(os.path.join(self.working_directory, 'stats.log')):
            request.add_supplementary(os.path.join(self.working_directory, 'stats.log'), 'stats.log', 'log')

        request.result = result
