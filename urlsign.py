from datetime import datetime
import base64
import time
import urllib
from pytz import UTC
import sys
import json

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


with open('client_secrets.json', 'r') as f:
    j = json.loads(f.read())
    PRIVATE_KEY = j['private_key']
    CLIENT_EMAIL = j['client_email']


def unix_time(dt):
    """
    Convert a datetime to seconds since 1/1/1970
    """
    if dt is None:
        return None
    epoch = datetime.utcfromtimestamp(0)
    if dt.tzinfo is not None:
        epoch = epoch.replace(tzinfo=UTC)
    delta = dt - epoch
    return int(delta.total_seconds())

GCS_API_ACCESS_ENDPOINT = 'https://storage.googleapis.com'


def sign_gcs_url(gcs_filename, method='GET', content_type=None, content_md5=None, expiration=None):
    expiration = str(unix_time(expiration)) if expiration is not None else None

    urlsafe_filename = urllib.quote(gcs_filename)

    signature_string = '\n'.join([
        method,
        content_md5 or '',
        content_type or '',
        expiration or '',
        urlsafe_filename])

    key64 = PRIVATE_KEY
    key_der = base64.b64decode(key64)
    pem_key = RSA.importKey(key_der)

    signer = PKCS1_v1_5.new(pem_key)
    signature_hash = SHA256.new(signature_string)
    signature_bytes = signer.sign(signature_hash)
    signature = base64.b64encode(signature_bytes)

    query_params = {
        'GoogleAccessId': CLIENT_EMAIL,
        'Signature': signature
    }
    if expiration is not None:
        query_params['Expires'] = expiration

    return '{endpoint}{resource}?{querystring}'.format(endpoint=GCS_API_ACCESS_ENDPOINT, resource=urlsafe_filename,
        querystring=urllib.urlencode(query_params))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: {} <gcs_filename>'.format(sys.argv[0]))
    else:
        print(sign_gcs_url(sys.argv[1]))
