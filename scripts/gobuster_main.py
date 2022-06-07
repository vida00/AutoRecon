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

query_consult = {"size": 10000}
get_doc = requests.get(url, headers=header, auth=auth, data=json.dumps(query_consult), verify=False)
response = json.loads(get_doc.text)

dict_args = {}

def get_subdomain():
    for x in response['hits']['hits']:
        if str(x['_source']['server.domain']) not in dict_args and str(x['_source']['server.ip']) != '':
            dict_args[x['_source']['url.original']] = [x['_source']['server.domain'],x['_source']['server.ip'],x['_source']['server.port'],x['_source']['network.protocol']]

def main():

    get_subdomain()

    parallel_log = homedir+'/recon/data/'+target+'/temp/gobuster_parallel.log'

    os.system('rm -f '+parallel_log)

    with open(parallel_log, 'a') as file:
        for arg in dict_args:
            file.write('python3 '+homedir+'/recon/scripts/parsing/parse_gobuster.py '+target+' '+dict_args[arg][0]+' '+dict_args[arg][1]+' '+arg+' '+str(dict_args[arg][2])+' '+dict_args[arg][3]+'\n')

    print('[+] Initialized gobuster scanning')
    os.system('cat '+parallel_log+' | parallel -u')

if __name__ == '__main__':
	main()