#!/usr/bin/env python3

import sys
import socket
import sys
import requests
import subprocess
import os
import uuid
import json
from dotenv import load_dotenv

homedir = str(os.getenv('HOME'))
load_dotenv(homedir+'/recon/config.env')

target = sys.argv[1]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
auth = (str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
lista_ips = []
lista_index = ['subdomain','portscan','webenum','webvuln','infravuln']
json_parse = ''
dic_ip = {}
list_vulns = []
list_sistemas = []

def consulta_bases(index):
	data = {"size":10000}
	url = str(os.getenv('HOST'))+target+'-'+index+'/_search'
	get_doc = requests.get(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
	parse_scan = json.loads(get_doc.text)
	return(parse_scan)

if len(sys.argv) != 3:
	for i in lista_index:
		ind = consulta_bases(i)

		if ind not in list_sistemas:
			try:
				for x in ind['hits']['hits']:
					list_sistemas.append(x['_source']['url.original'])
			except:
				pass

	os.system('clear')
	print(list_sistemas)
	exit()
else:
	sistema = sys.argv[2]

def consulta_diretorios(sistema):
	with open (homedir+'/recon/data/'+target+'/result.txt','a') as file:
		file.write('\n[*] Directories\n')

	list_sis = []
	for index in lista_index:
		json_parse = consulta_bases(index)
		for x in json_parse['hits']['hits']:
			try:
				if(x['_source']['url.original'] == sistema):
					if(x['_source']['url.full'] not in list_sis):
						list_sis.append(x['_source']['url.full'])
						with open (homedir+'/recon/data/'+target+'/result.txt','a') as file:
							file.write(x['_source']['url.full']+'\n')
			except:
				pass

def consulta_ip(ip):
	with open (homedir+'/recon/data/'+target+'/result.txt','a') as file:
		file.write('\n[*] Ports\n')
	dic_ip[ip] = []
	for index in lista_index:
		json_parse = consulta_bases(index)
		try:
			for x in json_parse['hits']['hits']:
				if(x['_source']['server.ip'] == ip):
					if(x['_source']['server.port'] not in dic_ip[ip]):
						dic_ip[ip].append(x['_source']['server.port'])
						with open (homedir+'/recon/data/'+target+'/result.txt','a') as file:
								file.write(str(ip)+' '+str(x['_source']['server.port'])+'\n')
		except:
			pass
	consulta_diretorios(sistema)
def consulta_vuln():
	list_vulns = []
	ip = ''
	with open (homedir+'/recon/data/'+target+'/result.txt','a') as file:
		file.write('[*] Vulnerabilities\n')
	for index in lista_index:
		json_parse = consulta_bases(index)
		for x in json_parse['hits']['hits']:
			try:
				for x in json_parse['hits']['hits']:
					if(x['_source']['url.original'] == sistema):
						if(x['_source']['server.ip'] != '0.0.0.0'):
							ip = x['_source']['server.ip']
						if(x['_source']['vulnerability.name'] not in list_vulns):
							list_vulns.append(x['_source']['vulnerability.name'])
							with open (homedir+'/recon/data/'+target+'/result.txt','a') as file:
								file.write(x['_source']['url.full']+' - '+x['_source']['vulnerability.name']+'\n')
			except:
				pass

	consulta_ip(ip)

def main():
	os.system('rm -rf '+homedir+'/recon/data/'+target+'/result.txt')
	consulta_vuln()
	with open(homedir+'/recon/data/'+target+'/result.txt', 'r') as file:
		os.system('clear')
		data = file.read()
		print(data)

if __name__ == '__main__':
	main()
