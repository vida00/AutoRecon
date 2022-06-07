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

hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'nuclei'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner
output = scanner+'-'+rand_name+'.json'
dict_web = {}
dict_infra = {}

def get_infos(targ):
    subprocess.check_output('docker run --rm --name '+container_name+' -v '+homedir+'/recon/data/'+target+'/temp:/data kali-tool:2.0 nuclei -u '+targ+' -t /root/nuclei-templates/ -o /data/'+output+' -json || true', shell=True)

def input_data():
    get_infos(domain)
    with open(homedir+'/recon/data/'+target+'/temp/'+output) as file:

        for line in file:

            jsonline = line.rstrip('\n')
            jsondata = json.loads(jsonline)

            if 'http' in jsondata['matched-at'] or 'https' in jsondata['matched-at']:
                url = str(os.getenv('HOST'))+target+'-webvuln/_doc?refresh'
                dict_web['vulnerability.name'] = jsondata['info']['name']
                dict_web['vulnerability.severity'] = jsondata['info']['severity']
                try:
                    dict_web['vulnerability.description']= jsondata['info']['description']
                except:
                    dict_web['vulnerability.description'] = jsondata['info']['name']
                dict_web['url.original'] = jsondata['host']
                try:
                    dict_web['vulnerability.description'] = dict_web['vulnerability.description']+' '+jsondata['matcher-name']
                except:
                    pass
                dict_web['url.full'] = jsondata['matched-at']
                try:
                    dict_web['server.ip'] = jsondata['ip']
                except:
                    dict_web['server.ip'] = '0.0.0.0'
                dict_web['reference'] = jsondata['info']['reference']
                dict_web['network.protocol'] = jsondata['host'].split(':')[0]
                dict_web['server.address'] = sys.argv[3]
                dict_web['server.domain'] = dict_web['server.address']
                dict_web['server.port'] = sys.argv[4]
                dict_web['url.path'] = sys.argv[5]
                dict_web['http.response.status_code'] = '200'

                data = {
                    '@timestamp':hora,
                    'server.address':dict_web['server.address'],
                    'server.domain':dict_web['server.domain'],
                    'server.ip':dict_web['server.ip'],
                    'server.port':dict_web['server.port'],
                    'network.protocol':dict_web['network.protocol'],
                    'service.name' : '',
                    'url.path':dict_web['url.path'],
                    'http.response.status_code':dict_web['http.response.status_code'],
                    'vulnerability.description':dict_web['vulnerability.description'],
                    'vulnerability.name':dict_web['vulnerability.name'],
                    'vulnerability.severity':dict_web['vulnerability.severity'],
                    'url.original':dict_web['url.original'],
                    'url.full':dict_web['url.full'],
                    'vulnerability.scanner.vendor':scanner
                }

            else:
                url = str(os.getenv('HOST'))+target+'-infravuln/_doc?refresh'
                dict_infra['server.address'] = sys.argv[3]
                dict_infra['vulnerability.name'] = jsondata['info']['name']
                dict_infra['vulnerability.severity'] = jsondata['info']['severity']
                try:
                    dict_infra['vulnerability.description'] = jsondata['info']['description']
                except:
                    dict_infra['vulnerability.description']= jsondata['info']['name']
                try:
                    dict_infra['vulnerability.description'] = dict_infra['vulnerability.description']+' '+jsondata['matcher-name']
                except:
                    pass
                try:
                    dict_infra['server.ip'] = jsondata['ip']
                except:
                    dict_infra['server.ip'] = '0.0.0.0'
                try:
                    dict_infra['server.port'] = jsondata['matched-at'].split(':')[1]
                except:
                    dict_infra['server.port'] = sys.argv[4]
                dict_infra['network.protocol'] = ''
                if(dict_infra['server.port'] == '22'):
                    dict_infra['network.protocol'] = 'ssh'
                if(dict_infra['server.port'] == '21'):
                    dict_infra['network.protocol'] = 'ftp'
                if(dict_infra['server.port'] == '23'):
                    dict_infra['network.protocol'] = 'telnet'
                if(dict_infra['server.port'] == '3389'):
                    dict_infra['network.protocol'] = 'rdp'
                data = {
                    '@timestamp':hora,
                    'server.address':dict_infra['server.address'],
                    'server.ip':dict_infra['server.ip'],
                    'server.port':dict_infra['server.port'],
                    'network.protocol':dict_infra['network.protocol'],
                    'service.name' : '',
                    'vulnerability.description':dict_infra['vulnerability.description'],
                    'vulnerability.name':dict_infra['vulnerability.name'],
                    'vulnerability.severity':dict_infra['vulnerability.severity'],
                    'vulnerability.scanner.vendor':scanner
                }

        req = requests.post(url, headers=header, auth=auth, data=json.dumps(data), verify=False)
        print (req.text)

def main():
    input_data()

main()
