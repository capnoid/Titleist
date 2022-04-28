from selenium.webdriver import Firefox
import datetime
import requests
import json
import sys
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
		if 'files' in config.keys():
				LOG = config['files']
				# Multiple logs to parse
				log_data = []
		else:
			LOG = f"squatters{datetime.datetime.now().strftime('%m%d%y')}.txt"

		if len(LOG) > 1:
			for logfile in LOG:
				log_data.append(self.get_remote_log(config['remote'],PORT,logfile))
		else:
			# Pull a remote log
			if 'remote' in config.keys():
				log_data = self.get_remote_log(config['remote'], PORT, LOG)
			elif 'local' in config.key():
				log_data = self.get_local_log(config)
			return log_data


	def get_remote_log(self,rmt,port,log):
		URL = f'http://{rmt}:{port}/{log}'
		req = requests.get(URL)
		if req.status_code == 200:
			print(f'[+] Loaded DNS Records from {URL}')
		else:
			error(f'Unable to Get Data from {URL}')
		return req.text.split('\n')

	def get_local_log(self, config):
		print(f'[+] Loading DNS Records from locally saved data')
		if not os.path.isfile(config['local']):
			error(f'Unable to find Data at {config["local"]}')
		return open(config['local'],'r').read().split('\n')

	def parse_log(self):
		log = {}
		if type(self.raw_dns_data) != None:
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
	interesting_site_data = DataLoader({'remote': '192.168.1.155', 
										'files': ['squatters042022.txt','squatters042122.txt','squatters042222.txt','squatters042322.txt']})

	#squatter_data = DataLoader({'remote':'CHANGE_ME'})