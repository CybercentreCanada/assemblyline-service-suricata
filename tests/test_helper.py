import os
import pytest

from suricata_.helper import parse_suricata_output


@pytest.mark.parametrize("sample_dir", ["files/alert_http", "files/alert_flow", "files/alert_dns"])
def test_alert_signature_correlation(sample_dir):
    sample_dir = os.path.join(os.path.dirname(__file__), sample_dir)
    result = parse_suricata_output(sample_dir)
    for s in result["signatures"].values():
        # In most cases, an alert event should correspond to a other single event (ie. http, dns, netflow)
        assert len(s["attributes"]) == 1
