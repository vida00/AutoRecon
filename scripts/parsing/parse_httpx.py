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
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-webenum/_doc?refresh'
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'httpx'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner
output = scanner+'-'+rand_name+'.txt'
dict_web = {}

def get_infos(targ):
    output_httpx = subprocess.check_output('docker run --rm --name '+container_name+' kali-tool:2.0 echo "'+targ+'" | httpx --silent || true', shell=True)
    return output_httpx

def input_data():

        httpx = get_infos(domain).decode('utf-8').rstrip('\n')
        if httpx:

            dict_web['network.protocol'] = httpx.split(':')[0]

            try:
                dict_web['server.port'] = httpx.split(':')[2].split('/')[0]
            except:
                if(dict_web['network.protocol'] == 'http'):
                    dict_web['server.port'] = '80'
                else:
                    dict_web['server.port'] = '443'
            
            path = len(httpx.split('/'))
            if(path == 3):
                dict_web['url.path'] = '/'
                dict_web['url.original'] = httpx
            else:
                i = 3
                dict_web['url.path'] = ''

                dict_web['url.original'] = dict_web['network.protocol']+'://'+httpx.split('/')[2]
                while i < path:
                    dict_web['url.path'] = dict_web['url.path']+'/'+httpx.split('/')[i]
                    i += 1

            data = {
                '@timestamp': hora,
                'server.address': domain,
                'server.domain': domain,
                'server.ip': ip,
                'server.port': dict_web['server.port'],
                'network.protocol': dict_web['network.protocol'],
                'url.path': dict_web['url.path'],
                'http.response.status_code': '200',
                'url.original': dict_web['url.original'],
                'url.full': dict_web['url.original']+dict_web['url.path'],
                'vulnerability.scanner.vendor': scanner
            }
            
            req = requests.post(url, headers=header, auth=auth, data=json.dumps(data), verify=False)
            print(req.text)

def main():
    input_data()

main()
