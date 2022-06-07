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
import xml.etree.ElementTree as ET

homedir = str(os.getenv('HOME'))
load_dotenv(homedir+'/recon/config.env')

target = sys.argv[1]
domain = sys.argv[2]
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-webvuln/_doc?refresh'
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'nikto'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner
output = scanner+'-'+rand_name+'.xml'
dict = {}

def get_infos(targ):
    output_httpx = subprocess.check_output('docker run --rm --name '+container_name+' -v '+homedir+'/recon/data/'+target+'/temp:/data kali-tool:2.0 nikto -host '+targ+' -output /data/'+output+' || true', shell=True)

def input_data():

        get_infos(domain)

        tree = ET.parse(homedir+'/recon/data/'+target+'/temp/'+output)
        root = tree.getroot()

        for i in root.iter('scandetails'):
            dict['server.ip'] = i.attrib['targetip']
            dict['server.address'] = i.attrib['targethostname']
            dict['server.domain'] = i.attrib['targethostname']
            dict['server.port'] = i.attrib['targetport']
            dict['network.protocol'] = i.attrib['sitename'].split(':')[0]
            dict['service.name'] = i.attrib['sitename'].split(':')[0]
            dict['url.original'] = domain
            for scan in i:
                if(scan.tag == 'item'):
                    for item in scan:
                        if(item.tag == 'description'):
                            dict['vulnerability.description'] = item.text.replace('\n ','').replace(' \n','')
                            dict['vulnerability.name'] = item.text.replace('\n ','').replace(' \n','')
                            dict['vulnerability.severity'] = ''
                        if(item.tag == 'uri'):
                            dict['url.path'] = item.text.replace('\n ','').replace(' \n','')
                        if(item.tag == 'namelink'):
                            dict['url.full'] = item.text.replace('\n ','').replace(' \n','')

                    data = {
                        '@timestamp': hora,
                        'server.address': dict['server.address'],
                        'server.domain': dict['server.domain'],
                        'server.ip': dict['server.ip'],
                        'server.port': dict['server.port'],
                        'network.protocol': dict['network.protocol'],
                        'url.path': dict['url.path'],
                        'http.response.status_code': '200',
                        'vulnerability.description': dict['vulnerability.description'],
                        'vulnerability.name': dict['vulnerability.name'],
                        'vulnerability.severity': dict['vulnerability.severity'],
                        'url.original': dict['url.original'],
                        'url.full': dict['url.full'],
                    }
                    print(data)
                    #req = requests.post(url, headers=header, auth=auth, data=json.dumps(data), verify=False)
                    #print(req.text)

def main():
    input_data()

main()
