#!/usr/bin/python3

import sys
import json
from dotenv import load_dotenv
import requests
import os

homedir = str(os.getenv('HOME'))
load_dotenv(homedir+'/recon/config.env')

target = sys.argv[1]
header = { 'Accept': 'application/json', 'Content-Type': 'application/json' }
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
url = str(os.getenv('HOST'))+target+'-webvuln/_search'
scanner = 'assetfinder'

query_consult = {"size": 1000}

get_doc = requests.get(url, headers=header, auth=auth, data=json.dumps(query_consult), verify=False)

parse_output = json.loads(get_doc.text)

#list_subdomains = []

for i in parse_output['hits']['hits']:
	print(i['_source']['url.original'])

#print(list_subdomains)
