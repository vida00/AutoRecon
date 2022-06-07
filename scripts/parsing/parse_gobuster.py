#!/usr/bin/python3

import subprocess
import sys
import socket
import uuid
import requests
import json
from dotenv import load_dotenv
import os
from time import strftime

homedir = str(os.getenv('HOME'))
load_dotenv(homedir+'/recon/config.env')

target = sys.argv[1]
domain = sys.argv[2]
ip = sys.argv[3]
url_with_protocol = sys.argv[4]
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-webenum/_doc?refresh'
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'gobuster'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner
output = scanner+'-'+rand_name+'.txt'
dict_web = {}

def get_infos(targ):
    output_httpx = subprocess.check_output('docker run --rm --name '+container_name+' -v '+homedir+'/recon/wordlists:/wordlists:ro kali-tool:2.0 gobuster dir -u "'+domain+'" -w /wordlists/small.txt -q || true', shell=True)
    return output_httpx.decode('utf-8').rstrip('\n').replace(' ', '').replace('\r', '').split('\n')

def input_data():

        dict_web = get_infos(url_with_protocol)
        for uri in dict_web:

            url_path = uri.split('(')[0]
            data = {
                '@timestamp': hora,
                'server.address': domain,
                'server.domain': domain,
                'server.ip': ip,
                'server.port': sys.argv[5],
                'network.protocol': sys.argv[6],
                'url.path': url_path,
                'http.response.status_code': uri.split(':')[1].split(')')[0],
                'url.original': url_with_protocol,
                'url.full': url_with_protocol+url_path,
                'vulnerability.scanner.vendor': scanner
            }
            
            req = requests.post(url, headers=header, auth=auth, data=json.dumps(data), verify=False)
            print(req.text)

def main():
    input_data()

main()
