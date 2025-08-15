

import base64, json, os
import json, os, sys

def get_token():

    tok=os.environ['TOKEN']
    print(tok)
    hdr=json.loads(base64.urlsafe_b64decode(tok.split('.')[0]+'=='))
    print("kid:", hdr.get('kid'))
    print("alg:", hdr.get('alg'))

def verify():
    pass

if __name__ == "__main__":
    get_token()