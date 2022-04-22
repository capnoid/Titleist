from selenium.webdriver import Firefox
import datetime
import requests
import json
import os

def error(msg):
	print(f'[!] ERROR: {msg}')
	exit()

class MalCrawl:
	def __init__(self, preferences):
		# initialize and configure based on preferences
		self.browser = Firefox()
		self.links = self.initialize(preferences)

	def initialize(self, config):
		if 'links' in config.keys():
			links = config['links']
		else:
			links = [str(input(f'[!] No link Provided! Please Enter URL to visit:\n'))]
		if 'dimensions' in config:
			self.set_window_size(config['dimensions']['W'], config['dimensions']['H'])
		return links

	def run(self):
		for page in self.links:
			print(f'[+] Visiting {page}')
			self.visit_page(page)


class DataLoader:
	def __init__(self, location_opts):
		self.raw_dns_data = self.setup(location_opts)
		self.data = self.parse_log()

	def setup(self, config):
		log_data = ""
		if 'port' in config.keys():
			PORT = int(config['port'])
		else:
			PORT = 8000
		if 'remote' in config.keys():
			date_label = datetime.datetime.now().strftime('%m%d%y')
			LOG = os.path.join(f'squatters{date_label}.txt')
			RMT = config['remote']
			URL = f'http://{RMT}:{PORT}/{LOG}'
			req = requests.get(URL)
			if req.status_code == 200:
				print(f'[+] Loaded DNS Records from {URL}')
			else:
				error(f'Unable to Get Data from {URL}')
			log_data = req.text.split('\n')
		elif 'local' in config.key():
			print(f'[+] Loading DNS Records from locally saved data')
			if not os.path.isfile(config['local']):
				error(f'Unable to find Data at {config["local"]}')
			log_data = open(config['local'],'r').read().split('\n')
		return log_data


	def parse_log(self):
		log = {}
		for ln in self.raw_dns_data:
			try:
				fields = ln.split(' ')
				date_day = fields[0].replace('[','')
				date_time = fields[1].replace(']','')
				dom_registered = fields[2]
				registrant = fields[-1].replace('[','').replace(']','')
				log[date_day+' '+date_time] = {'domain':dom_registered,
											   'registrant': registrant}
			except IndexError:
				pass
		print(f'[-] {len(log.keys())} Entries Parsed')
		return log

if __name__ == '__main__':
	# Load Data from Remote Machines 
	#interesting_site_data = DataLoader({'remote': 'CHANGE_ME'})
	#squatter_data = DataLoader({'remote':'CHANGE_ME'})