from __future__ import print_function

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
    )

import argparse
import re
import sys
import censys.certificates

class Censys():  
	def __init__(self, censysApiId, censysApiSecret):
		self.censysApiId = censysApiId
		self.censysApiSecret = censysApiSecret
	  
	def get_certificates(self, domain):
		if not self.censysApiId or not self.censysApiSecret:
			logging.info("\033[1;31m[!] API KEY or Secret for Censys not provided.\033[1;m" \
						 "\nYou'll have to provide them in the script") 
			sys.exit()
		logging.info("[+] Extracting certificates for {} using Censys".format(domain))
		c = censys.certificates.CensysCertificates(self.censysApiId, self.censysApiSecret)
		search_results = c.paged_search(domain)
		certificates = search_results['results']
		if len(certificates) == 0:
			print("\033[1;31m[!] No matching certificates found!\033[1;m")
			sys.exit()
		return certificates

	def get_subdomains(self, domain, certificates):
		logging.info("[+] Extracting sub-domains for {} from certificates".format(domain))
		subdomains = []
		for certificate in certificates:
			parsed_result = re.findall(r'(?<=CN=).*', certificate[u'parsed.subject_dn'])
			if len(parsed_result) > 0 and domain in parsed_result[0]: subdomains.append(parsed_result[0])
		return subdomains

	

