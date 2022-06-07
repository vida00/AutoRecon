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
url = str(os.getenv('HOST'))+target+'-webenum/_search'

query_consult = {"size": 1000}
get_doc = requests.get(url, headers=header, auth=auth, data=json.dumps(query_consult), verify=False)
response = json.loads(get_doc.text)

domain_list = []

def get_ip():
	for x in response['hits']['hits']:
		if(str(x['_source']['url.original']) not in domain_list):
			domain_list.append(str(x['_source']['url.original']))

def main():
	get_ip()

	parallel_log = homedir+'/recon/data/'+target+'/temp/nikto_parallel.log'

	os.system('rm -f '+parallel_log)
	for domain in domain_list:
		with open(parallel_log, 'a') as file:
			file.write('python3 '+homedir+'/recon/scripts/parsing/parse_nikto.py '+target+' '+domain+'\n')

	print('[+] Initialized nikto scanning')
	os.system('cat '+parallel_log+' | parallel -u')

if __name__ == '__main__':
	main()
