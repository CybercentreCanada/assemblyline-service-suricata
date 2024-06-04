import json
import os
from copy import deepcopy
from socket import getservbyport
from typing import Any, Dict

import dateutil.parser as dateparser
import regex
from assemblyline.odm.base import DOMAIN_ONLY_REGEX, IP_ONLY_REGEX
from assemblyline.odm.models.ontology.results import NetworkConnection
from assemblyline_service_utilities.common.network_helper import convert_url_to_https
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.task import PARENT_RELATION


def parse_suricata_output(
    working_directory: str,
    temp_submission_data: Dict[str, Any] = None,
    uses_proxy_in_sandbox: bool = False,
    ontology: OntologyHelper = OntologyHelper(None, None),
):
    if temp_submission_data is None:
        temp_submission_data = {}
    alerts = {}
    signatures = {}
    domains = []
    ips = []
    urls = []
    email_addresses = []
    tls_dict = {}
    extracted_files = {}
    temp_submission_data.setdefault("url_headers", {})
    ancestry = temp_submission_data.setdefault("ancestry", [])

    from_proxied_sandbox = (
        any(a[-1]["parent_relation"] ==
            PARENT_RELATION.DYNAMIC for a in ancestry) and uses_proxy_in_sandbox
    )

    reverse_lookup = {}
    oid_lookup = {}
    event_types = {
        "dns": [],
        "http": [],
        "netflow": [],
        "smtp": [],
        "tls": [],
        "fileinfo": [],
        "alert": [],
    }

    def attach_network_connection(data: dict):
        # Check for any fields that may be null and remove them from the data before applying validation
        for k in list(data.keys()):
            if data.get(k) is None:
                data.pop(k)

        oid = NetworkConnection.get_oid(data)
        data["objectid"]["ontology_id"] = oid
        # Don't overwrite important netflows
        if not ontology._result_parts.get(oid):
            ontology.add_result_part(NetworkConnection, data)

        # Add ObjectID to lookup for signatures/alerts
        if flow_id:
            oid_lookup.setdefault(flow_id, []).append(data["objectid"])

    # Parse the json results of the service and organize them into certain categories
    with open(os.path.join(working_directory, "eve.json"), encoding="utf-8") as file:
        for line in file:
            record = json.loads(line)
            if record["event_type"] in event_types:
                event_types[record["event_type"]].append(record)

    ordered_records = []
    for record in event_types.values():
        ordered_records.extend(record)
    # Populate reverse lookup map
    for record in event_types["dns"]:
        domain = record["dns"]["rrname"]
        for lookup_type, resolved_ips in record["dns"].get("grouped", {}).items():
            reverse_lookup.update({ip: domain for ip in resolved_ips})

    for record in ordered_records:
        timestamp = dateparser.parse(record["timestamp"]).isoformat(" ")
        src_ip = record.get("src_ip")
        src_port = record.get("src_port")
        dest_ip = record.get("dest_ip")
        dest_port = record.get("dest_port")
        proto = record.get("proto", "TCP").lower()
        app_proto = record.get("app_proto", None)
        direction = "outbound"
        flow_id = record.get("flow_id")

        ext_hostname = reverse_lookup.get(dest_ip)
        if not ext_hostname:
            # Potentially dealing with an inbound response back to host
            ext_hostname = reverse_lookup.get(src_ip, src_ip)
            direction = "inbound"

        network_data = {
            "objectid": {
                "tag": ext_hostname + f"{f':{dest_port}' if dest_port else ''}",
                "time_observed": timestamp,
            },
            "source_ip": src_ip,
            "source_port": src_port,
            "destination_ip": dest_ip,
            "destination_port": dest_port,
            "transport_layer_protocol": proto,
            "connection_type": app_proto,
            "direction": direction,
        }

        if src_ip is not None and src_ip not in ips:
            ips.append(src_ip)
        if dest_ip is not None and dest_ip not in ips:
            ips.append(dest_ip)

        if record["event_type"] == "http":
            if "hostname" not in record["http"] or "url" not in record["http"]:
                continue

            domain = record["http"]["hostname"]
            if domain not in domains and domain not in ips:
                domains.append(domain)

            protocol = "https" if record["http"].get(
                "http_port") == 443 else "http"
            url_meta = record["http"]["url"]
            if url_meta.startswith("/"):
                # Assume this is a path
                url = f"{protocol}://" + domain + record["http"]["url"]
            elif url_meta.startswith("http"):
                # Assume this is a URL with the protocol
                url = url_meta
            else:
                # Assume this ia a URL without the protocol, default to http
                url = f"{protocol}://" + url_meta

            url = convert_url_to_https(record["http"].get(
                "http_method", "GET"), url) if from_proxied_sandbox else url
            if url not in urls:
                urls.append(url)
            network_data["connection_type"] = "http"
            http_details = record["http"]
            network_data["http_details"] = {
                "request_uri": url,
                "request_headers": {
                    h["name"].replace("-", "_").lower(): h["value"] for h in http_details["request_headers"]
                },
                "request_method": http_details["http_method"].upper(),
                "response_headers": {
                    h["name"].replace("-", "_").lower(): h["value"] for h in http_details["response_headers"]
                },
            }
            temp_submission_data["url_headers"].update(
                {url: {h["name"]: h["value"]
                       for h in http_details["request_headers"]}}
            )
            if http_details.get("status"):
                network_data["http_details"].update(
                    {"response_status_code": http_details["status"]})
            attach_network_connection(network_data)

        elif record["event_type"] == "dns":
            if "rrname" not in record["dns"]:
                continue
            domain = record["dns"]["rrname"]
            if regex.match(DOMAIN_ONLY_REGEX, domain) and domain not in domains and domain not in ips:
                domains.append(domain)
            network_data["connection_type"] = "dns"
            for lookup_type, resolved_ips in record["dns"].get("grouped", {}).items():
                if lookup_type in ["A", "AAAA"]:
                    data = deepcopy(network_data)
                    data["dns_details"] = {
                        "domain": domain,
                        "resolved_ips": resolved_ips,
                        "lookup_type": lookup_type,
                    }
                    attach_network_connection(data)
                elif lookup_type == "PTR":
                    # Reverse lookup occurred
                    if domain.endswith("in-addr.arpa"):
                        # Extract the actual IP and it's resolution
                        domain = domain.rstrip(".in-addr.arpa")[::-1]
                    reverse_lookup[domain] = resolved_ips[0]
        # elif record["event_type"] == "netflow":
        #     attach_network_connection(network_data)
        elif record["event_type"] == "alert":
            if "signature_id" not in record["alert"] or "signature" not in record["alert"]:
                continue
            signature_id = record["alert"]["signature_id"]
            gid = record["alert"]["gid"]
            signature = record["alert"]["signature"]
            signature_key = f"{gid}:{signature_id}"
            if signature_key not in alerts:
                alerts[signature_key] = []
            if signature_key not in signatures:
                try:
                    proto = getservbyport(dest_port) if dest_port else "http"
                except OSError:
                    proto = "http"
                signatures[signature_key] = {
                    "signature": signature,
                    "malware_family": record["alert"].get("metadata", {}).get("malware_family", []),
                    "attributes": [],
                }

            if any(record.get(event_type) for event_type in ["http", "dns", "flow"]) and flow_id:
                attributes = []
                for source in oid_lookup.get(flow_id, []):
                    attribute = {"source": source}
                    if not regex.match(IP_ONLY_REGEX, ext_hostname):
                        attribute["domain"] = ext_hostname
                    if record.get("http") and record["http"].get("hostname"):
                        # Only alerts containing HTTP details can provide URI-relevant information
                        hostname = reverse_lookup.get(
                            record["http"]["hostname"],
                            record["http"]["hostname"],
                        )
                        if record["http"]["url"].startswith(hostname):
                            url = f"{app_proto}://{record['http']['url']}"
                        else:
                            url = f"{app_proto}://{hostname+record['http']['url']}"
                        url = (
                            convert_url_to_https(
                                record["http"].get("http_method", "GET"), url)
                            if from_proxied_sandbox
                            else url
                        )
                        attribute.update({"uri": url})
                    elif record.get("dns"):
                        # Only attach network results that are directly related to the alert
                        network_part: NetworkConnection = ontology._result_parts.get(
                            source['ontology_id'])
                        if not any(query["rrname"] == network_part.dns_details.domain
                                   for query in record["dns"]["query"]):
                            continue
                    attributes.append(attribute)

                if attributes:
                    signatures[signature_key]["attributes"] = (
                        signatures[signature_key].get(
                            "attributes", []) + attributes
                    )

            alerts[signature_key].append(
                (timestamp, src_ip, src_port, dest_ip, dest_port))

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
            sha256_full = record["fileinfo"]["sha256"]
            if sha256_full not in extracted_files:
                sha256 = f"{sha256_full[:12]}.data"
                extracted_files[sha256_full] = {
                    "sha256": sha256,
                    "filename": os.path.basename(record["fileinfo"].get("filename", sha256)) or sha256,
                    "extracted_file_path": os.path.join(
                        working_directory,
                        "filestore",
                        sha256_full[:2].lower(),
                        sha256_full,
                    ),
                }
    return {
        "alerts": alerts,
        "signatures": signatures,
        "domains": domains,
        "ips": ips,
        "urls": urls,
        "email_addresses": email_addresses,
        "tls": tls_dict,
        "extracted_files": extracted_files.values(),
        "reverse_lookup": reverse_lookup,
    }
