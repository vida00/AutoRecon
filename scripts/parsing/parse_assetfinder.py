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
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-subdomain/_doc?refresh'
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'assetfinder'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner
output = scanner+'-'+rand_name+'.txt'

def get_block(ip):
    try:
        command = subprocess.check_output('docker run --rm --name '+container_name+' kali-tool:2.0 rdap '+ip+' --json || true', shell=True)
        json_data = json.loads(command)
        block = json_data['handle']
        return block
    except:
        return ''

def get_domain(domain):
    nameserver = ''
    try:
        return_data = requests.get('https://rdap.registro.br/domain/'+domain)
        json_data = json.loads(return_data)
        for ns in json_data['nameservers']:
            nameserver = nameserver+ns['ldhName']+','
        return nameserver[:-1]
    except:
        return ''

def assetfinder():
    subprocess.check_output('docker run --rm --name '+container_name+' kali-tool:2.0 assetfinder -subs-only '+domain+' > '+homedir+'/recon/data/'+target+'/temp/'+output+' || true', shell=True)

def input_data():
    with open(homedir+'/recon/data/'+target+'/temp/'+output) as file:
        for i in file:
            host = i.rstrip('\n')

            try:
                ip = socket.gethostbyname(host)
            except:
                ip = '0.0.0.0'

            data = {
                '@timestamp': hora,
                'server.address': host,
                'server.domain': host,
                'server.ip': ip,
                'server.ipblock': get_block(ip),
                'server.nameserver': get_domain(host),
                'vulnerability.scanner.vendor': scanner
            }

            req = requests.post(url, headers=header, auth=auth, data=json.dumps(data), verify=False)
            print(req.text)

def main():
    assetfinder()
    input_data()

main()
