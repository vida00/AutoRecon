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
ip = sys.argv[2]
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-portscan/_doc?refresh'
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'nmap'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner
output = scanner+'-'+rand_name+'.xml'

def get_block(ip):
    try:
        command = subprocess.check_output('docker run --rm --name '+container_name+' kali-tool:2.0 rdap '+ip+' --json || true', shell=True)
        json_data = json.loads(command)
        block = json_data['handle']
        return block
    except:
        return ''

def nmap():
    subprocess.check_output('docker run --rm --name '+container_name+' -v '+homedir+'/recon/data/'+target+'/temp:/data kali-tool:2.0 nmap -sSV -Pn '+ip+' -oX /data/'+output+' || true', shell=True)

def input_data():
    tree = ET.parse(homedir+'/recon/data/'+target+'/temp/'+output)
    root = tree.getroot()

    dict = {}

    for i in root.iter('nmaprun'):
        for nmaprun in i:
            if nmaprun.tag == 'host':
                for host in nmaprun:
                    if host.tag == 'address':
                        dict['network.type'] = host.attrib['addrtype']
                    if host.tag == 'ports':
                        for port in host:
                            if port.tag == 'port':
                                dict['server.port'] = port.attrib['portid']
                                dict['network.transport'] = port.attrib['protocol']
                                for info in port:
                                    if info.tag == 'state':
                                        dict['server.state'] = info.attrib['state']
                                    if info.tag == 'service':
                                        try: dict['network.protocol'] = info.attrib['name']
                                        except: dict['network.protocol'] = ''

                                        try: dict['service.name'] = info.attrib['product']
                                        except: dict['service.name'] = ''

                                        try: dict['application.version.number'] = info.attrib['version']
                                        except: dict['application.version.number'] = ''

                                        data = {
                                            "@timestamp": hora,
                                            "server.address": ip,
                                            "network.protocol": dict['network.protocol'],
                                            "server.ip": ip,
                                            "server.port": dict['server.port'],
                                            "server.ipblock": get_block(ip),
                                            "service.name": dict['service.name'],
                                            "service.state": dict['server.state'],
                                            "application.version.number": dict['application.version.number'],
                                            "network.transport": dict['network.transport'],
                                            "network.type": dict['network.type'],
                                            "vulnerability.scanner.vendor": scanner
                                        }

                                        req = requests.post(url, headers=header, auth=auth, data=json.dumps(data), verify=False)
                                        print(req.text)

def main():
    nmap()
    input_data()

main()
