import json
import os
import shutil
import subprocess
import time
import uuid

from retrying import retry
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TAG_USAGE
from assemblyline.al.service.base import ServiceBase, UpdaterFrequency, UpdaterType

suricatasc = None
dateparser = None


class Suricata(ServiceBase):
    SERVICE_ACCEPTS = 'network/tcpdump'
    SERVICE_CATEGORY = 'Networking'
    SERVICE_ENABLED = True
    SERVICE_STAGE = "CORE"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id: 2021d906006158b7d4afbfadaf24f809e1573b56 $')
    SERVICE_TIMEOUT = 60
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 1024

    SERVICE_DEFAULT_CONFIG = {
        "SURICATA_BIN": "/usr/local/bin/suricata",
        "SURICATA_CONFIG": "/etc/suricata/suricata.yaml",
        "SURE_SCORE": "MALWARE TROJAN CURRENT_EVENTS CnC Checkin",
        "VHIGH_SCORE": "EXPLOIT SCAN Adware PUP",
        "RULES_URL": "http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz",
        "HOME_NET": "any"
    }

    def __init__(self, cfg=None):
        super(Suricata, self).__init__(cfg)
        self.suricata_socket = None
        self.suricata_sc = None
        self.suricata_process = None
        self.last_rule_update = None
        self.rules_url = cfg.get("RULES_URL", self.SERVICE_DEFAULT_CONFIG["RULES_URL"])
        self.home_net = cfg.get("HOME_NET", self.SERVICE_DEFAULT_CONFIG["HOME_NET"])
        self.oinkmaster_update_file = '/etc/suricata/oinkmaster'

    def update_suricata(self, **_):
        subprocess.call(["/usr/sbin/oinkmaster",  "-Q", "-u", self.rules_url, "-o", "/etc/suricata/rules"])
        subprocess.call(["touch", self.oinkmaster_update_file])

    def start(self):
        self._register_update_callback(self.update_suricata, execute_now=True, utype=UpdaterType.BOX,
                                       freq=UpdaterFrequency.QUARTER_DAY)
        self.replace_suricata_config()
        self.start_suricata_if_necessary()

    # The rules are updated once per day, so each day we have a new tool version
    def get_tool_version(self):
        return os.path.getmtime(self.oinkmaster_update_file)

    # When we're shutting down, kill the Suricata child process as well
    def stop(self):
        self.kill_suricata()

    def kill_suricata(self):
        if self.suricata_process:
            try:
                self.log.info("Trying to kill Suricata (%s)" % (str(self.suricata_process.pid)))
                self.suricata_process.kill()
            except Exception as e:
                self.log.exception("Failed to kill Suricata (%s): %s" % (str(self.suricata_process.pid), e.message))

    def replace_suricata_config(self):
        shutil.copyfile(os.path.join(self.source_directory, 'conf', 'suricata.yaml'),
                        os.path.join(self.working_directory, 'suricata.yaml'))

        command = [
            '/bin/sed',
            '-i', '-e',
            's/__HOME_NET__/' + self.home_net.replace('/', '\/').replace('[', '\[').replace(']', '\]') + '/g',
            os.path.join(self.working_directory, 'suricata.yaml')
        ]
        p = subprocess.Popen(command)
        p.communicate()

        os.rename(os.path.join(self.working_directory, 'suricata.yaml'), '/etc/suricata/suricata.yaml')

    def reload_rules_if_necessary(self):
        if self.last_rule_update < self.get_tool_version():
            self.reload_rules()

            # Send the reload_rules command to the socket

    def reload_rules(self):
        ret = self.suricata_sc.send_command("reload-rules")

        if not ret and ret["return"] != "OK":
            self.log.exception("Failed to reload Suricata rules")

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
        self.suricata_socket = str(uuid.uuid4()) + '.socket'

        command = [
            self.cfg.get('SURICATA_BIN'),
            "-c", self.cfg.get('SURICATA_CONFIG'),
            '--unix-socket=' + self.suricata_socket
        ]

        self.log.info('Launching Suricata: %s' % (' '.join(command)))

        self.suricata_process = subprocess.Popen(command)

        self.suricata_sc = suricatasc.SuricataSC(os.path.join('/var/run/suricata', self.suricata_socket))

        # Schedule a job to delete the scoket when it isn't needed any longer
        self._register_cleanup_op(
            {
                'type': 'shell',
                'args': ["rm", os.path.join("/var/run/suricata/", self.suricata_socket)]
            }
        )

        if not self.suricata_running_retry():
            raise Exception('Suricata could not be started.')
        self.last_rule_update = time.time()

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global suricatasc, dateparser
        import suricatasc
        import dateutil.parser as dateparser

    def execute(self, request):
        filepath = request.download()
        result = Result()

        # restart Suricata if we need to
        self.start_suricata_if_necessary()

        # Update our rules if they're stale,
        self.reload_rules_if_necessary()

        # Pass the pcap file to Suricata via the socket
        ret = self.suricata_sc.send_command("pcap-file", {
            "filename": filepath,
            "output-dir": self.working_directory
        })

        if not ret or ret["return"] != "OK":
            self.log.exception("Failed to submit PCAP for processing: %s" % ret['message'])

        # Wait for the socket to be finished processing
        while True:
            time.sleep(1)
            ret = self.suricata_sc.send_command("pcap-current")

            if ret and ret["message"] == "None":
                break

        alerts = {}
        signatures = {}

        # Parse the json results of the service
        for line in open(os.path.join(self.working_directory, 'eve.json')):
            alert = json.loads(line)

            timestamp = dateparser.parse(alert['timestamp']).isoformat(' ')
            signature_id = alert['alert']['signature_id']
            signature = alert['alert']['signature']
            src_ip = alert['src_ip']
            src_port = alert['src_port']
            dest_ip = alert['dest_ip']
            dest_port = alert['dest_port']

            if signature_id not in alerts:
                alerts[signature_id] = []
            if signature_id not in signatures:
                signatures[signature_id] = signature

            alerts[signature_id].append("%s %s:%s -> %s:%s" % (timestamp, src_ip, src_port, dest_ip, dest_port))

        # Create the result sections if there are any hits
        if len(alerts) > 0:
            for signature_id, signature in signatures.iteritems():
                score = SCORE.NULL
                tag_weight = TAG_WEIGHT.NULL

                if any(x in signature for x in self.cfg.get("SURE_SCORE").split()):
                    score = SCORE.SURE
                    tag_weight = TAG_WEIGHT.SURE

                if any(x in signature for x in self.cfg.get("VHIGH_SCORE").split()):
                    score = SCORE.VHIGH
                    tag_weight = TAG_WEIGHT.VHIGH

                section = ResultSection(score, '%s: %s' % (signature_id, signature))
                for flow in alerts[signature_id][:10]:
                    section.add_line(flow)
                if len(alerts[signature_id]) > 10:
                    section.add_line('And %s more flows' % (len(alerts[signature_id]) - 10))
                result.add_section(section)

                # add a tag for the signature id and the message
                result.add_tag(TAG_TYPE.SURICATA_SIGNATURE_ID, str(signature_id), tag_weight,
                               usage=TAG_USAGE.IDENTIFICATION)
                result.add_tag(TAG_TYPE.SURICATA_SIGNATURE_MESSAGE, signature, tag_weight,
                               usage=TAG_USAGE.IDENTIFICATION)

            # Add the original Suricata output as a supplementary file in the result
            request.add_supplementary(os.path.join(self.working_directory, 'eve.json'), 'json', 'SuricataEventLog.json')

        request.result = result
