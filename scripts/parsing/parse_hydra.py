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
ip = sys.argv[2]
port = sys.argv[3]
service = sys.argv[4]
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-infravuln/_doc?refresh'
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'hydra'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner
output = scanner+'-'+rand_name+'.json'
dict_infra = {}


def get_infos(ip, port, service):
    subprocess.check_output('docker run --rm --name '+container_name+' -v '+homedir+'/recon/data/'+target+'/temp:/data -v '+homedir+'/recon/wordlists:/wordlists:ro kali-tool:2.0 hydra -I -L /wordlists/user.txt -P /wordlists/passwords.txt -e nsr -o /data/'+output+' -b json -t 1 '+ip+' '+service+' -s '+port+' || true', shell=True)

def input_data():
    get_infos(ip, port, service)

    with open(homedir+'/recon/data/'+target+'/temp/'+output) as file:
        jsondata = json.load(file)
        for i in jsondata['results']:
            data = {
                '@timestamp': hora,
                'server.address': i['host'],
                'server.ip': ip,
                'server.port': i['port'],
                'network.protocol': i['service'],
                'service.name' : '',
                'vulnerability.description': 'Broken username/password '+i['login']+':'+i['password'],
                'vulnerability.name': 'Broken username/password',
                'vulnerability.severity': 'High',
                'vulnerability.scanner.vendor':scanner
            }

            r = requests.post(url, headers=header, auth=auth, data=json.dumps(data), verify=False)
            print (r.text)

def main():
    print('AQQUI:::: '+str(os.getenv('HOST')))
    input_data()

main()
