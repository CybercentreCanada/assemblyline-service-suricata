import json
import os
from copy import deepcopy
from socket import getservbyport
from typing import Any, Dict

import dateutil.parser as dateparser
import regex
from assemblyline.common.identify import Identify
from assemblyline.odm.base import DOMAIN_ONLY_REGEX, IP_ONLY_REGEX
from assemblyline.odm.models.ontology.results import NetworkConnection
from assemblyline_service_utilities.common.network_helper import convert_url_to_https
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from assemblyline_v4_service.common.task import PARENT_RELATION

IDENTIFY = Identify(use_cache="PRIVILEGED" in os.environ)


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
    alert_logs = []

    from_proxied_sandbox = (
        any(a[-1]["parent_relation"] == PARENT_RELATION.DYNAMIC for a in ancestry) and uses_proxy_in_sandbox
    )

    reverse_lookup = dict()
    oid_lookup = {}
    event_types = {
        "fileinfo": [],
        "dns": [],
        "http": [],
        "flow": [],
        "netflow": [],
        "smtp": [],
        "tls": [],
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
        if record["dns"].get("rrtype") == "SRV":
            # These kinds of records have to be parsed differently
            for answer in record["dns"].get("additionals", []):
                reverse_lookup[answer["rdata"]] = answer["rrname"]
        else:
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
                "tag": f"{dest_ip if dest_ip else ext_hostname}" + f"{f':{dest_port}' if dest_port else ''}",
                "time_observed": timestamp,
            },
            "source_ip": src_ip,
            "source_port": src_port,
            "destination_ip": dest_ip,
            "destination_port": dest_port,
            "transport_layer_protocol": proto,
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

            protocol = "https" if record["http"].get("http_port") == 443 else "http"
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

            url = convert_url_to_https(record["http"].get("http_method", "GET"), url) if from_proxied_sandbox else url
            if url not in urls:
                urls.append(url)
            network_data["connection_type"] = "http"
            http_details = record["http"]
            network_data["http_details"] = {
                "request_uri": url,
                "request_headers": {
                    h["name"].replace("-", "_").lower(): h["value"] for h in http_details.get("request_headers", [])
                    if "value" in h
                },
                "request_method": http_details.get("http_method", "").upper(),
                "response_headers": {
                    h["name"].replace("-", "_").lower(): h["value"] for h in http_details.get("response_headers", []) if "value" in h
                },
            }
            temp_submission_data["url_headers"].update(
                {url: {h["name"]: h["value"] for h in http_details.get("request_headers", []) if "value" in h}}
            )
            if http_details.get("status"):
                network_data["http_details"].update({"response_status_code": http_details.get("status")})
            attach_network_connection(network_data)

        elif record["event_type"] == "dns":
            if record["dns"]["type"] == "query":
                # Ignore event records about DNS queries
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
        elif record["event_type"] == "flow":
            attach_network_connection(network_data)
        elif record["event_type"] == "alert":
            alert_logs.append(record)
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
                sources = oid_lookup.get(flow_id, [])
                for source in sources:
                    attribute = {"source": source}
                    network_part: NetworkConnection | None = ontology._result_parts.get(source["ontology_id"])
                    if not regex.match(IP_ONLY_REGEX, ext_hostname):
                        attribute["domain"] = ext_hostname

                    if not network_part:
                        # No network attribute to link to alert
                        continue
                    elif app_proto == "http" and not network_part.http_details:
                        # Alert pertains to an HTTP event
                        continue
                    elif record.get("http") and record["http"].get("hostname") and network_part.http_details:
                        # Only alerts containing HTTP details can provide URI-relevant information
                        http_record = record["http"]
                        network_part_http_details = network_part.http_details

                        if "content_range" in http_record and http_record["content_range"][
                            "raw"
                        ] != network_part_http_details.response_headers.get("content_range"):
                            # Content range doesn't match
                            continue
                        elif "http_user_agent" in http_record and http_record[
                            "http_user_agent"
                        ] != network_part_http_details.request_headers.get("user_agent"):
                            # User agent doesn't match
                            continue
                        elif "http_content_type" in http_record and http_record[
                            "http_content_type"
                        ] != network_part_http_details.response_headers.get("content_type"):
                            # Content type doesn't match
                            continue
                        elif (
                            "status" in http_record
                            and http_record["status"] != network_part_http_details.response_status_code
                        ):
                            # Status code doesn't match
                            continue

                        if not (http_record["http_method"] == network_part_http_details.request_method):
                            # Request method or status code doesn't match
                            continue

                        hostname = reverse_lookup.get(
                            http_record["hostname"],
                            http_record["hostname"],
                        )
                        if http_record["url"].startswith(hostname):
                            url = f"{app_proto}://{record['http']['url']}"
                        else:
                            url = f"{app_proto}://{hostname+record['http']['url']}"
                        url = (
                            convert_url_to_https(http_record.get("http_method", "GET"), url)
                            if from_proxied_sandbox
                            else url
                        )
                        attribute.update({"uri": url})
                    elif record.get("dns"):
                        if not network_part.dns_details:
                            # Only attach network results that are directly related to the alert
                            continue

                        if not any(
                            query["rrname"] == network_part.dns_details.domain
                            for query in record["dns"].get("queries", []) + record["dns"].get("query", [])
                        ):
                            # This particular record isn't relevant to the alert
                            continue
                    elif record.get("smtp"):
                        if not network_part.smtp_details:
                            # Only attach network results that are directly related to the alert
                            continue

                        if (
                            f"<{network_part.smtp_details.mail_from}>" != record["smtp"]["mail_from"]
                            and not all(
                                [eml[1:-1] in network_part.smtp_details.mail_to for eml in record["smtp"]["rcpt_to"]]
                            )
                            and network_part.smtp_details.attachments != record["email"]["attachment"]
                        ):
                            # This particular record isn't relevant to the alert
                            continue

                    attributes.append(attribute)

                for attr in attributes:
                    # Ensure there are no duplicate attributes being merged
                    if attr not in signatures[signature_key]["attributes"]:
                        signatures[signature_key]["attributes"].append(attr)

            alerts[signature_key].append((timestamp, src_ip, src_port, dest_ip, dest_port))

        elif record["event_type"] == "smtp":
            # extract email metadata
            if "email" not in record:
                continue
            if not isinstance(record["smtp"], dict):
                continue

            mail_from = record["smtp"].get("mail_from")
            if mail_from is not None:
                mail_from = mail_from[1:-1]
                if mail_from not in email_addresses:
                    email_addresses.append(mail_from)

            mail_to = []
            for email_addr in record["smtp"].get("rcpt_to", []):
                email_addr = email_addr[1:-1]
                mail_to.append(email_addr)
                if email_addr not in email_addresses:
                    email_addresses.append(email_addr)
            network_data["connection_type"] = "smtp"
            attachments = []
            for filename in record["email"].get("attachment", []):
                if filename in extracted_files[flow_id]:
                    attachments.append(extracted_files[flow_id][filename])
            network_data["smtp_details"] = dict(mail_to=mail_to, mail_from=mail_from, attachments=attachments)
            attach_network_connection(network_data)

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
            filename = record["fileinfo"]["filename"]
            sha256_full = record["fileinfo"]["sha256"]
            # We'll assume the filename is unique to the flow
            extracted_files.setdefault(flow_id, {})
            if filename not in extracted_files.get(flow_id):
                extracted_files[flow_id][filename] = IDENTIFY.fileinfo(
                    os.path.join(
                        working_directory,
                        "filestore",
                        sha256_full[:2].lower(),
                        sha256_full,
                    )
                )
                # Include extracted_file_path
                extracted_files[flow_id][filename].update(
                    {
                        "extracted_file_path": os.path.join(
                            working_directory,
                            "filestore",
                            sha256_full[:2].lower(),
                            sha256_full,
                        ),
                        "names": [filename],
                    }
                )

    # De-duplicate extracted files:
    extracted_files_dedup = []
    for flow_files in extracted_files.values():
        for file in flow_files.values():
            extracted_file = {
                "sha256": file["sha256"],
                "name": file["names"][0],
                "extracted_file_path": file["extracted_file_path"],
            }
            if extracted_file not in extracted_files_dedup:
                extracted_files_dedup.append(extracted_file)

    if alert_logs:
        # Append logging to ontology in 'other' key
        ontology.add_other_part("alerts", json.dumps(alert_logs))

    return {
        "alerts": alerts,
        "signatures": signatures,
        "domains": domains,
        "ips": ips,
        "urls": urls,
        "email_addresses": email_addresses,
        "tls": tls_dict,
        "extracted_files": extracted_files_dedup,
        "reverse_lookup": reverse_lookup,
    }
