#!/usr/bin/env python3

import os
import sys
import requests
import json
from dotenv import load_dotenv
import os

homedir = str(os.getenv('HOME'))
load_dotenv(homedir+'/recon/config.env')

target = sys.argv[1]
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-portscan/_search'

query_consult = {"size": 1000}
get_doc = requests.get(url, headers=header, auth=auth, data=json.dumps(query_consult), verify=False)
response = json.loads(get_doc.text)

list_ip = []
list_serv = []
dic_ip = {}
servicos = ['ftp','ssh','pop3','telnet','imap','mysql']

parallel_log = homedir+'/recon/data/'+target+'/temp/hydra_parallel.log'

def hydra():
	for x in response['hits']['hits']:
		if(x['_source']['server.ip'] not in list_ip):
			list_ip.append(x['_source']['server.ip'])
	for i in list_ip:
		list_serv = []
		for x in response['hits']['hits']:
			if(x['_source']['server.ip'] == i):
				if(x['_source']['server.port'] not in list_serv):
					list_serv.append(x['_source']['server.port'])	
					if(x['_source']['network.protocol'] in servicos):
						with open (parallel_log,'a') as file:
            						file.write('python3 '+homedir+'/recon/scripts/parsing/parse_hydra.py '+target+' '+i+' '+x['_source']['server.port']+' '+x['_source']['network.protocol']+'\n')

def main():
    os.system('rm -rf '+parallel_log)

    hydra()
    print("[+] Initialized hydra scanning")
    os.system('cat '+parallel_log+' | parallel -u')

if __name__ == '__main__':
    main()
