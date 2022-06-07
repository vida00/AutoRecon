#!/bin/sh

client=$1

rm -rf ~/recon/data/$client/temp/*

echo "[*] Initialized SubDomain Enumeration\n"
for domain in $(cat ~/recon/data/$client/domains.txt);do
	python3 ~/recon/scripts/subdomain_main.py $client $domain
done

echo "[*] Initialized System Enumeration"
python3 ~/recon/scripts/httpx_main.py $client

echo "[*] Initialized Web Directory Enumeration"
python3 ~/recon/scripts/gobuster_main.py $client

echo "[*] Initialized URLs Enumeration"
python3 ~/recon/scripts/wayback_main.py $client

echo "[*] Initialized Port Scanning"
python3 ~/recon/scripts/nmap_main.py $client

echo "[*] Initialized Web Vulnerability Scanner"
python3 ~/recon/scripts/nikto_main.py $client
python3 ~/recon/scripts/nuclei_main.py $client

echo "[*] Initialized Brute Force at Services"
python3 ~/recon/scripts/hydra_main.py $client

echo "====== FINISH ======"
