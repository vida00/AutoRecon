import os
import sys


def main():
    homedir = str(os.getenv('HOME'))

    target = sys.argv[1]
    domain = sys.argv[2]

    parallel_log = homedir+'/recon/data/'+target+'/temp/subdomain_monitoring_parallel.log'

    os.system('rm -f '+parallel_log)
    with open(parallel_log, 'a') as file:
        file.write('python3 '+homedir+'/recon/scripts/monitoring/parsing/parse_assetfinder_temp.py '+target+' '+domain+'\n')
        file.write('python3 '+homedir+'/recon/scripts/monitoring/parsing/parse_sublist3r_temp.py '+target+' '+domain+'\n')
        file.write('python3 '+homedir+'/recon/scripts/monitoring/parsing/parse_subfinder_temp.py '+target+' '+domain+'\n')

    print('[+] Initialize subdomain enumeration')
    os.system('cat '+parallel_log+' | parallel -u')

if __name__ == '__main__':
    main()
