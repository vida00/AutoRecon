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
url = str(os.getenv('HOST'))+target+'-subdomain/_search'

query_consult = {"size": 1000}
get_doc = requests.get(url, headers=header, auth=auth, data=json.dumps(query_consult), verify=False)
response = json.loads(get_doc.text)

ip_list = []

def get_ip():
	for x in response['hits']['hits']:
		if(str(x['_source']['server.ip']) not in ip_list):
			ip_list.append(str(x['_source']['server.ip']))

def main():
	get_ip()

	parallel_log = homedir+'/recon/data/'+target+'/temp/nmap_parallel.log'

	os.system('rm -f '+parallel_log)
	for ip in ip_list:
		with open(parallel_log, 'a') as file:
			file.write('python3 '+homedir+'/recon/scripts/parsing/parse_nmap.py '+target+' '+ip+'\n')

	print('[+] Initialized nmap scanning')
	os.system('cat '+parallel_log+' | parallel -u')

if __name__ == '__main__':
	main()
