#!/usr/bin/python
#
# default-view.py
# Purpose: Satellite 6 - changes client content-view to 'Default Organization View'
# Author: Fred Caldeira <frederico.caldeira@scotiabank.com>
# Modified: Mohammad Salman Ali L2 unix 
# Added FQDN 
# Version 1.1

import sys
import json
import base64
# Socket is used by gethostname()
import socket

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print "Please install the python-requests module."
    sys.exit(-1)

# URL to Satellite 6 server
URL = "https://rhsat.bns"
# URL for the API deployed Satellite 6 server
SAT_API = "%s/api/v2/hosts/" % URL
KATELLO_API = "%s/katello/api/" % URL
POST_HEADERS = {'content-type': 'application/json'}
# Ignore SSL for now
SSL_VERIFY = False
HOSTN = socket.gethostname()
FQDN = socket.getfqdn()
RUN = '0'
print 'Hostname =',HOSTN
print 'FQDN=', FQDN
def cdec(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc)
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def post_json(urllocation, json_data):
    """
    Performs a POST and passes the data to the URL location
    """
    result = requests.put(
       urllocation,
       data=json_data,
       auth=(cdec('scotiacdn', '5cjW6dzT'), cdec('scotiacdn', 'xtPU19LCz5aepJo=')),
       verify=SSL_VERIFY,
       headers=POST_HEADERS)
    return str(result)

MyLOC=SAT_API + HOSTN
MyLOC1=SAT_API + FQDN

aux = json.dumps({"host":{"content_facet_attributes":{"content_view_id": 146}}})
print ("Changing the view.")

RUN = post_json(MyLOC, aux)
if RUN == '<Response [200]>':
   print 'running with hostname', HOSTN, 
   print '\nSuccessful', RUN
elif RUN != '<Response [200]>':
   FRUN = post_json(MyLOC1, aux)
   print 'running with FQDN', FQDN
   if FRUN == '<Response [200]>':
      print 'Successful', FRUN
