import requests

class Shodan():
	def __init__(self, api_key, host):
		self.api_key = api_key
		self.host = host
		
	def get_shodan_data(self):
		url = "https://api.shodan.io/shodan/host/search?key="+self.api_key+"&query=hostname:"+self.host
		res = requests.get(url)
		return res.json()
		
