import os
import sys


def main():
    homedir = str(os.getenv('HOME'))

    target = sys.argv[1]
    domain = sys.argv[2]

    parallel_log = homedir+'/recon/data/'+target+'/temp/subdomain_parallel.log'

    os.system('rm -f '+parallel_log)
    with open(parallel_log, 'a') as file:
        file.write('python3 '+homedir+'/recon/scripts/parsing/parse_assetfinder.py '+target+' '+domain+'\n')
        file.write('python3 '+homedir+'/recon/scripts/parsing/parse_sublist3r.py '+target+' '+domain+'\n')
        file.write('python3 '+homedir+'/recon/scripts/parsing/parse_subfinder.py '+target+' '+domain+'\n')

    print('[+] Initialized subdomain enumeration')
    os.system('cat '+parallel_log+' | parallel -u')

if __name__ == '__main__':
    main()
