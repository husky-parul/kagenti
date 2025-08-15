

import base64, json, os
import json, os, sys

def get_token():

    tok=os.environ['TOKEN']
    hdr=json.loads(base64.urlsafe_b64decode(tok.split('.')[0]+'=='))
    print("kid:", hdr.get('kid'))
    print("alg:", hdr.get('alg'))