#Call external library in "core" directory 
from core.SecuritytrailsApi import Securitytrails
from core.DnsdumpsterApi import Dnsdumpster
from core.CensysApi import Censys
from core.ShodanApi import Shodan

from datetime import datetime
from argparse import ArgumentParser

import json
import sys

#API Configuration, might be this config shoud be move in environment variables
SECURITYTRAILS_API_KEY = "REDACTED"
CENSYS_API_ID = "REDACTED"
CENSYS_API_SECRET = "REDACTED"
SHODAN_API_KEY = "REDACTED"

dnsEnum = {
  "time" : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
  "data" : {
	  "securitytrails_com" : [],
	  "dnsdumpster_com" : [],
	  "censys_io" : [],
	  "shodan_io" : []
  }
}

def dnsdumpster(domain):
	print("\033[1;32m[+] Gathering info from dnsdumpster.com\033[1;m" )
	res = Dnsdumpster(True).search(domain)
	for entry in res['dns_records']['host']:
		dnsEnum["data"]["dnsdumpster_com"].append(entry)
        
def securitytrails(domain):
	print("\033[1;32m[+] Gathering info from securitytrails.com\033[1;m" )
	s = Securitytrails(api_key=SECURITYTRAILS_API_KEY)
	response = json.loads(s.get_subdomain(domain))
	for entry in response["subdomains"]:
		data = {
			"domain" : entry+"."+domain
		}
		dnsEnum["data"]["securitytrails_com"].append(data)
	
def censys(domain):
	print("\033[1;32m[+] Gathering info from censys.io\033[1;m" )
	cens = Censys(censysApiId=CENSYS_API_ID,censysApiSecret=CENSYS_API_SECRET)
	cert = cens.get_certificates(domain)
	subdomains = cens.get_subdomains(domain, cert)
	unique_subdomains = list(set(subdomains))
	for sub_domain in unique_subdomains:
		data = {
			"domain" : sub_domain
		}
		dnsEnum["data"]["censys_io"].append(data)
		
def shodan(domain):
	print("\033[1;32m[+] Gathering info from shodan.io\033[1;m" )
	shodan = Shodan(api_key=SHODAN_API_KEY, host=domain)
	res = shodan.get_shodan_data()
	for entry in res["matches"]:
		data = {
			"domain" : ' '.join(entry["hostnames"])
		}
		dnsEnum["data"]["shodan_io"].append(data)

def write_to_file(output, path):
	print("\033[1;32m[+] Writing to file in "+path+" \033[1;m" )
	with open(path, 'w') as outfile:  
		json.dump(output, outfile)
	
def main(target, output, show):
	dnsdumpster(target)
	securitytrails(target)
	censys(target)
	shodan(target)
	write_to_file(dnsEnum, output)
	if show == "yes":
		print(json.dumps(dnsEnum))
	
if __name__ == "__main__":
	parser = ArgumentParser(description="")
	parser.add_argument("--target", help='Add target host. i.e: spots.co.id')
	parser.add_argument("--output", help="Add path location to write the output. i.e: /tmp/out.json")
	parser.add_argument("--show", help="(optional) set yes to print console output. i.e: yes")
	if len(sys.argv) < 4:
		parser.print_help()
		sys.exit(1)
		
	main(**vars(parser.parse_args()))
		
	
	
	

