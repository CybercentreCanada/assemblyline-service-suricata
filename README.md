# Suricata Service

This service scans network capture files with signature and extract files from network capture.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

The Suricata configuration file is available in suricata\_.conf.suricata.yaml.

The ruleset(s) configured by default for use with this service are:

- [Emerging Threats Open](https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz)
- [Snortv3 Community](https://www.snort.org/downloads/community/snort3-community-rules.tar.gz)
- [URLhaus](https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz)

Organizations can add their own rulesets to this service.

## Test if working

Inside the container run:

```bash
python -m assemblyline_v4_service.dev.run_service_once suricata_.suricata_.Suricata /tmp/testing.pcap
```
