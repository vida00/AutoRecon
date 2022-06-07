#!/bin/sh

client=$1

rm -rf ~/recon/data/$client/temp/*

echo "[*] Monitoring Subdomains"
for domain in $(cat ~/recon/data/$client/domains.txt);do
	python3 ~/recon/scripts/monitoring/subdomain_monitoring_main.py $client $domain
done
