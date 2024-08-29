import json
import os
import subprocess
import sys
import time
from io import StringIO

import regex
import suricatasc
import yaml
from assemblyline.common.exceptions import RecoverableError
from assemblyline.common.forge import get_classification
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import DOMAIN_ONLY_REGEX
from assemblyline.odm.models.ontology.results import Signature
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import MaxExtractedExceeded
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from tenacity import RetryError, retry, retry_if_result, wait_exponential, stop_after_delay

from suricata_.helper import parse_suricata_output

SURICATA_BIN = "/usr/local/bin/suricata"
Classification = get_classification()


class Suricata(ServiceBase):
    """This class is the main class for the Suricata service."""

    def __init__(self, config=None):
        super().__init__(config)

        self.home_net = self.config.get("home_net", "any")
        self.rules_config = yaml.safe_dump({"rule-files": []})
        self.run_dir = "/usr/local/var/run/suricata"
        self.suricata_socket = None
        self.suricata_sc = None
        self.suricata_process = None
        self.suricata_yaml = "/usr/local/etc/suricata/suricata.yaml"
        self.suricata_log = "/usr/local/var/log/suricata/suricata.log"
        self.uses_proxy_in_sandbox = self.config.get("uses_proxy_in_sandbox", False)
        self.suricata_conf = self.config.get("suricata_conf", {})

    @staticmethod
    def run_command(command):
        """This function runs a command and returns the process object"""
        try:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                stdout, stderr = process.communicate()

                if process.returncode != 0:
                    print(f"Error: {stderr.decode().strip()}")
                else:
                    print(f"Output: {stdout.decode().strip()}")

                return process

        except Exception as broad_exception:
            print(f"An exception occurred: {broad_exception}")
            return None

    @staticmethod
    def strip_frame_headers(filepath):
        """Use an external tool to strip frame headers"""
        new_filepath = os.path.join(os.path.dirname(filepath), "striped.pcap")
        command = ["/usr/local/bin/stripe", "-r", filepath, "-w", new_filepath]

        Suricata.run_command(command)

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
            for ruleset in ret.get("message"):
                self.log.info(f"Ruleset {ruleset['id']}: {ruleset['rules_loaded']} rules loaded")
                if ruleset["rules_failed"] and ruleset["rules_loaded"] == 0:
                    self.log.error(f"Ruleset {ruleset['id']}: {ruleset['rules_failed']} rules failed to load")
                elif ruleset["rules_failed"]:
                    self.log.warning(
                        f"Ruleset {ruleset['id']}: {ruleset['rules_failed']} rules failed to load."
                        "This can be due to duplication of rules among muliple rulesets being loaded."
                    )

                    # Get the list of rules that failed and log them
                    ret = self.suricata_sc.send_command("ruleset-failed-rules")
                    if ret:
                        for rule in ret.get("message", []):
                            self.log.warning(f"Rule failed to load: {rule['rule']}")

    def get_suricata_version(self):
        return safe_str(subprocess.check_output(["suricata", "-V"]).strip().replace(b"This is Suricata version ", b""))

    def get_tool_version(self):
        """
        Return the version of suricata used for processing
        :return:
        """
        return f"{self.get_suricata_version()}.r{self.rules_hash}"

    # When we're shutting down, kill the Suricata child process as well
    def stop(self):
        self.kill_suricata()

    # Kill the process if it isn't ending
    def kill_suricata(self):
        if self.suricata_process:
            try:
                self.log.info(f"Trying to kill Suricata ({str(self.suricata_process.pid)})")
                self.suricata_process.kill()
            except Exception as broad_exception:
                self.log.exception(
                    f"Failed to kill Suricata ({str(self.suricata_process.pid)}): {str(broad_exception)}"
                )

    # Reapply our service configuration to the Suricata yaml configuration
    def replace_suricata_config(self):
        source_path = os.path.join(os.getcwd(), "suricata_", "conf", "suricata.yaml")
        dest_path = self.suricata_yaml
        # home_net = re.sub(r"([/\[\]])", r"\\\1", self.home_net)
        home_net = self.home_net
        with open(source_path) as s_path:
            conf = yaml.safe_load(
                s_path.read().replace("__HOME_NET__", home_net).replace("__RULE_FILES__", self.rules_config)
            )
            # Update the configuration based on service configuration
            conf.update(self.suricata_conf)
            with open(dest_path, "w") as d_path:
                d_path.write("%YAML 1.1\n---\n")
                d_path.write(yaml.dump(conf))

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
            except RetryError as retry_error:
                raise RecoverableError(retry_error) from retry_error

    # Try connecting to the Suricata socket
    def suricata_running(self):
        if self.suricata_sc is None:
            return False
        try:
            self.suricata_sc.connect()
        except suricatasc.SuricataException as suricata_exception:
            if "Transport endpoint is already connected" in str(suricata_exception):
                return True
            self.log.info(f"Suricata not started yet: {str(suricata_exception)}")
            return False
        return True

    # Retry with exponential backoff until we can actually connect to the Suricata socket
    @retry(
        retry=retry_if_result(lambda x: x is False),
        wait=wait_exponential(multiplier=1, max=10),
        stop=stop_after_delay(120),
    )
    def suricata_running_retry(self):
        return self.suricata_running()

    # Launch Suricata using a UID socket
    def launch_or_load_suricata(self):
        self.suricata_socket = os.path.join(self.run_dir, "suricata.socket")

        if not os.path.exists(self.suricata_socket):
            command = [
                SURICATA_BIN,
                "-vvvv",  # Useful for debugging
                "-c",
                self.suricata_yaml,
                f"--unix-socket={self.suricata_socket}",
                "--pidfile",
                f"{self.run_dir}/suricata.pid",
                "--set",
                f"logging.outputs.1.file.filename={self.suricata_log}",
                "-D",
            ]

            self.log.info(f"Launching Suricata: {' '.join(command)}")

            self.suricata_process = self.run_command(command)

        self.suricata_sc = suricatasc.SuricataSC(self.suricata_socket)

        if not self.suricata_running_retry():
            raise Exception("Suricata could not be started.")

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
        ret = self.suricata_sc.send_command(
            "pcap-file",
            {"filename": stripped_filepath, "output-dir": self.working_directory},
        )

        if not ret or ret["return"] != "OK":
            self.log.exception(f"Failed to submit PCAP for processing: {ret['message']}")

        # Wait for the socket finish processing our PCAP
        while True:
            time.sleep(1)
            try:
                ret = self.suricata_sc.send_command("pcap-current")
                if ret and ret["message"] == "None":
                    break
            except ConnectionResetError as connection_reset_error:
                raise RecoverableError(connection_reset_error) from connection_reset_error

        # Bring back stdout and stderr
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        # NOTE: for now we will ignore content of mystdout and mystderr but we have them just in case...

        (
            alerts,
            signatures,
            domains,
            ips,
            urls,
            email_addresses,
            tls_dict,
            extracted_files,
            reverse_lookup,
        ) = parse_suricata_output(
            self.working_directory, request.temp_submission_data, self.uses_proxy_in_sandbox, self.ontology
        ).values()

        file_extracted_section = ResultSection("File(s) extracted by Suricata")
        # Parse the json results of the service
        if request.get_param("extract_files"):
            for file in extracted_files:
                sha256, filename, extracted_file_path = file.values()
                self.log.info(f"extracted file {filename}")
                try:
                    if request.add_extracted(
                        extracted_file_path,
                        filename,
                        "Extracted by Suricata",
                        safelist_interface=self.api_interface,
                    ):
                        file_extracted_section.add_line(filename)
                        if filename != sha256:
                            file_extracted_section.add_tag("file.name.extracted", filename)
                except FileNotFoundError as file_not_found_error:
                    # An intermittent issue, just try again
                    raise RecoverableError(file_not_found_error) from file_not_found_error
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
                if not regex.match(DOMAIN_ONLY_REGEX, domain):
                    ips.append(domain)
                    continue
                domain_section.add_line(domain)
                domain_section.add_tag("network.dynamic.domain", domain)
        if ips:
            ip_section = ResultSection("IP Addresses", parent=root_section)
            for ip_addr in ips:
                # Make sure it's not a local IP
                if not (
                    ip_addr.startswith("127.")
                    or ip_addr.startswith("192.168.")
                    or ip_addr.startswith("10.")
                    or (ip_addr.startswith("172.") and 16 <= int(ip_addr.split(".")[1]) <= 31)
                    # Link-local IPv6 addresses
                    or ip_addr.startswith("fe80:0000:0000:0000:")
                    # All-routers link-local multicast
                    or ip_addr == "ff02:0000:0000:0000:0000:0000:0000:0002"
                ):
                    ip_section.add_line(ip_addr)
                    ip_section.add_tag("network.dynamic.ip", ip_addr)

        if urls:
            url_section = ResultSection("URLs", parent=root_section)
            for url in urls:
                if url.startswith("https"):
                    url = url.replace(":443", "", 1)
                url_section.add_line(url)
                url_section.add_tag("network.dynamic.uri", url)
        if email_addresses:
            email_section = ResultSection("Email Addresses", parent=root_section)
            for eml in email_addresses:
                email_section.add_line(eml)
                email_section.add_tag("network.email.address", eml)

        # Map between suricata key names and AL tag types
        tls_mappings = {
            "subject": "cert.subject",
            "issuerdn": "cert.issuer",
            "version": "cert.version",
            "notbefore": "cert.valid.start",
            "notafter": "cert.valid.end",
            "fingerprint": "cert.thumbprint",
            "sni": "network.tls.sni",
        }

        if tls_dict:
            tls_section = ResultSection("TLS Information", parent=root_section, body_format=BODY_FORMAT.JSON)
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
                    kv_body.setdefault("ja3_hash", [])
                    kv_body.setdefault("ja3_string", [])
                    for ja3_entry in tls_values:
                        ja3_hash = ja3_entry.get("hash")
                        ja3_string = ja3_entry.get("string")
                        if ja3_hash:
                            kv_body["ja3_hash"].append(ja3_hash)
                            tls_section.add_tag("network.tls.ja3_hash", ja3_hash)
                        if ja3_string:
                            kv_body["ja3_string"].append(ja3_string)
                            tls_section.add_tag("network.tls.ja3_string", ja3_string)

                elif tls_type == "ja3s":
                    kv_body.setdefault("ja3s_hash", [])
                    kv_body.setdefault("ja3s_string", [])
                    for ja3s_entry in tls_values:
                        ja3s_hash = ja3s_entry.get("hash")
                        ja3s_string = ja3s_entry.get("string")
                        if ja3s_hash:
                            kv_body["ja3s_hash"].append(ja3s_hash)
                            tls_section.add_tag("network.tls.ja3s_hash", ja3s_hash)
                        if ja3s_string:
                            kv_body["ja3s_string"].append(ja3s_string)
                            tls_section.add_tag("network.tls.ja3s_string", ja3_string)

                elif tls_type == "ja4":
                    kv_body.setdefault("ja4_hash", [])
                    for ja4_entry in tls_values:
                        ja4_hash = ja4_entry
                        if ja4_hash:
                            kv_body["ja4_hash"].append(ja4_hash)
                            tls_section.add_tag("network.tls.ja4_hash", ja4_hash)

                else:
                    kv_body[tls_type] = tls_values
                    # stick a message in the logs about a new TLS type found in suricata logs
                    self.log.info(f"Found new TLS type {tls_type} with values {tls_values}")
            tls_section.set_body(json.dumps(kv_body))

        # Create the result sections if there are any hits
        if len(alerts) > 0:
            for signature_key, signature_details in signatures.items():
                _, signature_id = signature_key.split(":", 1)
                signature_meta = self.signatures_meta[signature_key]
                signature = signature_details["signature"]
                attributes = signature_details["attributes"]
                classification = signature_meta["classification"]
                source = signature_meta["source"]
                section = ResultSection(
                    f"[{source}] {signature_id}: {signature}",
                    classification=Classification.max_classification(
                        classification,
                        request.task.min_classification,
                    ),
                )
                heur_id = 3
                if any(x in signature for x in self.config.get("sure_score")):
                    heur_id = 1
                elif any(x in signature for x in self.config.get("vhigh_score")):
                    heur_id = 2

                section.set_heuristic(heur_id)
                if signature_details:
                    section.add_tag("file.rule.suricata", f"{source}.{signature}")
                for timestamp, src_ip, src_port, dest_ip, dest_port in alerts[signature_key][:10]:
                    section.add_line(f"{timestamp} {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                if len(alerts[signature_key]) > 10:
                    section.add_line(f"And {len(alerts[signature_key]) - 10} more flows")

                # Tag IPs/Domains/URIs associated to signature
                for flow in alerts[signature_key]:
                    dest_ip = flow[3]
                    section.add_tag("network.dynamic.ip", dest_ip)
                    if dest_ip in reverse_lookup.keys():
                        section.add_tag("network.dynamic.domain", reverse_lookup[dest_ip])
                    uri_tags = [
                        uri
                        for uri in urls
                        if dest_ip in uri or reverse_lookup.get(dest_ip) and reverse_lookup[dest_ip] in uri
                    ]
                    for uri_tag in uri_tags:
                        section.add_tag("network.dynamic.uri", uri_tag)

                # Add a tag for the signature id and the message
                section.add_tag("network.signature.signature_id", str(signature_id))
                section.add_tag("network.signature.message", signature)
                for attr in attributes:
                    if attr.get("uri"):
                        section.add_tag("network.static.uri", attr["uri"])
                # Tag malware_family
                for malware_family in signature_details["malware_family"]:
                    section.add_tag("attribution.family", malware_family)

                result.add_section(section)
                self.ontology.add_result_part(
                    Signature,
                    data={
                        "name": f"{signature_meta['source']}.{signature}",
                        "type": "SURICATA",
                        "malware_families": signature_details["malware_family"] or None,
                        "attributes": attributes,
                        "signature_id": signature_id,
                        "classification": classification,
                    },
                )

        # Add the original Suricata output as a supplementary file in the result
        request.add_supplementary(
            os.path.join(self.working_directory, "eve.json"),
            "SuricataEventLog.json",
            "json",
        )

        # Add the stats.log to the result, which can be used to determine service success
        if os.path.exists(os.path.join(self.working_directory, "stats.log")):
            request.add_supplementary(os.path.join(self.working_directory, "stats.log"), "stats.log", "log")

        request.result = result
