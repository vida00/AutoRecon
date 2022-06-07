import sys
import socket
import requests
import subprocess
import os
import uuid
import json
import telegram
from time import strftime
from dotenv import load_dotenv

homedir = str(os.getenv('HOME'))
load_dotenv(homedir+'/recon/config.env')

target = sys.argv[1]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}

url = str(os.getenv('HOST'))+target+'-subdomain/_search'
url_temp = str(os.getenv('HOST'))+target+'-subdomain-temp/_search'
url_post = str(os.getenv('HOST'))+target+'-subdomain/_doc?refresh'
url_web = str(os.getenv('HOST'))+target+'-webvuln/_search'
url_systems = str(os.getenv('HOST'))+target+'-webenum/_search'

auth=(str(os.getenv('USERNAME')), str(os.getenv('PASSWORD')))
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'monitoring_subdomains'
rand_name = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+rand_name+'-'+scanner

dic_subdomain = {}
list_subs = []
list_new_subdomains = []
list_ips = []
dic_serv = {}
dic_new_subs = {}
dict_systems = {}

def sendMessage(message):
    bot = telegram.Bot(token=str(os.getenv('BOT_TOKEN')))
    bot.send_message(text=message, chat_id=str(os.getenv('CHAT_ID')))

def monitoring_nuclei(dic_new_subs):
    data = {"size":10000}
    get_doc = requests.get(url_systems, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(str(x['_source']['url.original']) not in dict_systems):
            dict_systems[x['_source']['url.original']] = [x['_source']['server.domain'],x['_source']['server.port'],x['_source']['url.path']]

    os.system('rm -rf '+homedir+'/recon/data/'+target+'/temp/nuclei_parallel.log')

    for sis in dict_systems:
        if(sis.split(':')[1].split('/')[2] in dic_new_subs):
            with open (homedir+'/recon/data/'+target+'/temp/nuclei_parallel.log','a') as file:
                file.write('python3 '+homedir+'/recon/scripts/parsing/parse_nuclei.py '+target+' '+sis+' '+dict_systems[sis][0]+' '+dict_systems[sis][1]+' '+dict_systems[sis][2]+'\n')
    print("\n[+] Initialized Nuclei")
    os.system('cat '+homedir+'/recon/data/'+target+'/temp/nuclei_parallel.log | parallel -u')

    get_doc = requests.get(url_web, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(x['_source']['server.domain'] in dic_new_subs):
            message = (x['_source']['url.full'],x['_source']['vulnerability.name'],x['_source']['vulnerability.severity'])
            sendMessage(message)

def monitoring_httpx(dic_new_subs):
    os.system('rm -rf '+homedir+'/recon/data/'+target+'/temp/httpx_parallel.log')
    with open (homedir+'/recon/data/'+target+'/temp/httpx_parallel.log','a') as file:
        for sub in dic_new_subs:
            file.write('python3 '+homedir+'/recon/scripts/parsing/parse_httpx.py '+target+' '+sub+' '+dic_new_subs[sub]+'\n')
    print("\n[+] Initilized httpx")
    os.system('cat '+homedir+'/recon/data/'+target+'/temp/httpx_parallel.log | parallel -u')
    monitoring_nuclei(dic_new_subs)

def nmap_monitoring(list_ips):
	os.system('rm -rf '+homedir+'/recon/data/'+target+'/temp/nmap_parallel.log')
	for ip in list_ips:
		dic_serv[ip] = []
		with open (homedir+'/recon/data/'+target+'/temp/nmap_parallel.log','a') as file:
			file.write('python3 '+homedir+'/recon/scripts/parsing/parse_nmap.py '+target+' '+ip+'\n')
	print("\n[+] Initialized nmap")
	message = "[+] Initialized nmap"
	sendMessage(message)
	os.system('cat '+homedir+'/recon/data/'+target+'/temp/nmap_parallel.log | parallel -u')
	url_nmap = str(os.getenv('HOST'))+target+'-portscan/_search'
	data = {"size":10000}
	get_doc = requests.get(url_nmap, headers=headers, auth=auth, data=json.dumps(data), verify=False)
	parse_scan = json.loads(get_doc.text)
	for x in parse_scan['hits']['hits']:
		if(x['_source']['server.ip'] in list_ips):
			if(x['_source']['server.port'] not in dic_serv[x['_source']['server.ip']]):
				print('HERE:',x['_source']['server.port'])
				dic_serv[x['_source']['server.ip']].append(x['_source']['server.port'])

	for ip in dic_serv:
		message = ip,' port: ',dic_serv[ip]
		sendMessage(message)
    

def get_subdomains_existing():
	data = {"size":10000}
	get_doc = requests.get(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
	parse_scan = json.loads(get_doc.text)
	for x in parse_scan['hits']['hits']:
		if(str(x['_source']['server.domain']) not in list_subs):
			list_subs.append(str(x['_source']['server.domain']))

def get_new_subdomains():
    data = {"size":10000}
    get_doc = requests.get(url_temp, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(str(x['_source']['server.domain']) not in list_subs and x['_source']['server.domain'] not in list_new_subdomains):
            list_new_subdomains.append(x['_source']['server.domain'])

def get_block(ip):
    try:
        command = subprocess.check_output('docker run --rm --name '+container_name+' kali-tool:2.0 rdap '+ip+' --json || true', shell=True)
        json_data = json.loads(command)
        block = json_data['handle']
        return block
    except:
        return ''

def get_domain(domain):
    nameserver = ''
    try:
        return_data = requests.get('https://rdap.registro.br/domain/'+domain)
        json_data = json.loads(return_data)
        for ns in json_data['nameservers']:
            nameserver = nameserver+ns['ldhName']+','
        return nameserver[:-1]
    except:
        return ''

def init():
    os.system('sh '+homedir+'/recon/indexes/monitoring/delete_subdomain_index_temp.sh '+target+' > /dev/null 2>&1')
    os.system('sh '+homedir+'/recon/indexes/monitoring/create_subdomain_index_temp.sh '+target+' > /dev/null 2>&1')
    os.system('sh '+homedir+'/recon/scripts/monitoring/monitoring_subdomain.sh '+target)

def parse():
    for line in list_new_subdomains:
        dic_subdomain['server.address'] = line.rstrip('\n')
        dic_subdomain['server.domain'] = line.rstrip('\n')
        try:
            dic_subdomain['server.ip'] = socket.gethostbyname(line.rstrip('\n'))
        except:
            dic_subdomain['server.ip'] = '0.0.0.0'
        dic_subdomain['vulnerability.scanner.vendor'] = scanner
        dic_subdomain['server.ipblock'] = get_block(dic_subdomain['server.ip'])
        dic_subdomain['server.nameserver'] = get_domain(dic_subdomain['server.domain'])
        data = {
                 '@timestamp':hora,
                 'server.address':dic_subdomain['server.address'],
                 'server.domain':dic_subdomain['server.domain'],
                 'server.ip':dic_subdomain['server.ip'],
                 'server.ipblock':dic_subdomain['server.ipblock'],
                 'server.nameserver':dic_subdomain['server.nameserver'],
                 'vulnerability.scanner.vendor':dic_subdomain['vulnerability.scanner.vendor']
        }

        r = requests.post(url_post, headers=headers, auth=auth, data=json.dumps(data), verify=False)
        print (r.text)
        message = "[+] New Subdomain finded - "+dic_subdomain['server.domain']+' - '+dic_subdomain['server.ip']
        sendMessage(message)
        if(dic_subdomain['server.ip'] not in list_ips):
            list_ips.append(dic_subdomain['server.ip'])
        try:
            dic_new_subs[dic_subdomain['server.domain']] = dic_subdomain['server.ip']
        except:
            pass

        nmap_monitoring(list_ips)
        monitoring_httpx(dic_new_subs)

def main():
	init()
	get_subdomains_existing()
	get_new_subdomains()
	parse()

if __name__== '__main__':
    main()
