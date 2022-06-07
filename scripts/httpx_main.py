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

query_consult = {"size": 10000}
get_doc = requests.get(url, headers=header, auth=auth, data=json.dumps(query_consult), verify=False)
response = json.loads(get_doc.text)

dict_args = {}

def get_subdomain():
    for x in response['hits']['hits']:
        if str(x['_source']['server.domain']) not in dict_args and str(x['_source']['server.ip']) != '':
            dict_args[str(x['_source']['server.domain'])] = str(x['_source']['server.ip'])

def main():

    get_subdomain()

    parallel_log = homedir+'/recon/data/'+target+'/temp/httpx_parallel.log'

    os.system('rm -f '+parallel_log)

    with open(parallel_log, 'a') as file:
        for arg in dict_args:
            file.write('python3 '+homedir+'/recon/scripts/parsing/parse_httpx.py '+target+' '+arg+' '+dict_args[arg]+'\n')

    print('[+] Initialized httpx scanning')
    os.system('cat '+parallel_log+' | parallel -u')

if __name__ == '__main__':
	main()