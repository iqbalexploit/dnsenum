import requests
import logging
import json

logging.basicConfig()
logger = logging.getLogger('securitytrails')


class Securitytrails():
    def __init__(self, api_key, base_url='https://api.securitytrails.com/v1/', prettyPrint=False):
        self.session = requests.session()
        self.session.headers.update({'APIKEY': api_key})
        self.base_url = base_url
        self.api_key = api_key
        self.prettyPrint = prettyPrint

        if self.api_key is None:
            raise Exception("No API Key present")

        self.ping = self.session.get(base_url + "ping")

        if self.ping.status_code != 200:
            logger.error(
                "Error connecting to Security Trails, error message: {}".format(
                    self.ping.text))

    def parse_output(self, input):
        # If prettyPrint set to False
        if self.prettyPrint == False:
            return json.dumps(input)
        # If prettyPrint set to True
        elif self.prettyPrint == True:
            print json.dumps(input, indent=4)

    def get_subdomain(self, domain):
        endpoint = '{}/domain/{}/subdomains'.format(self.base_url, domain)
        # Make connection to the subdomain endpoint
        r = self.session.get(endpoint)
        output = r.json()
        # If the request is successful
        if r.status_code == 200:
            return self.parse_output(r.json())
        # Request failed returning false and logging an error
        else:
            logger.warning(
                "get_subdomain:Error with query to Security Trails, error message: {}".format(
                    output['message']))
            return False
