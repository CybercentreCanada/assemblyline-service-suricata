#!/usr/bin/env python

"""
This is a script to automatically create/update JA3 signatures from https://github.com/trisulnsm/ja3prints

At this point, it doesn't make any effort to score anything that may be malware related.

"""
import json

import requests
from assemblyline.al.common import forge


def main():

    # Get the latest ja3 tags
    ja3_db_req = requests.get("https://raw.githubusercontent.com/trisulnsm/ja3prints/master/ja3fingerprint.json")

    sigdict = {}
    # Make some tagcheck sigs out of them
    for ja3_line in ja3_db_req.content.splitlines():
        if not ja3_line.startswith("#") and len(ja3_line.strip()) > 0:
            try:
                ja3 = json.loads(ja3_line.strip())
            except:
                print "Error decoding line %s" % ja3_line

            ja3h = ja3["ja3_hash"].lower()

            sigdict["ja3_%s" % ja3h] = {
                "classification": "U",
                "status": "DEPLOYED",
                "score": 0,
                "threat_actor": None,
                "implant_family": None,
                "comment": ja3["desc"],
                "values": ["TLS_JA3_HASH:%s" % ja3h],
                "callback": None,
            }
        # pprint.pprint(sigdict)

    print "Got %d JA3 tagcheck sigs to add/update" % len(sigdict)

    # Now get the sigs out of the datastore and add/update them
    ds = forge.get_datastore()

    current_sigs = ds.get_blob('tagcheck_signatures')

    for signame, sigvalue in sigdict.iteritems():
        if signame in current_sigs:
            print "Found %s in current sig, updating it" % signame
        else:
            print "Adding new tagcheck sig %s" % signame

        current_sigs[signame] = sigvalue

    print "Saving tagcheck signatures back to datastore..."
    ds.save_blob('tagcheck_signatures', current_sigs)
    print "... done"


if __name__ == "__main__":
    main()