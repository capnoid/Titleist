from colorama import init, Fore
from parser import levenshtein
import multiprocessing
import pandas as pd
import dns.resolver
import numpy as np
import certstream
import datetime
import logging
import requests
import random
import json
import time
import os

# create a log file 
date_label = datetime.datetime.now().strftime('%m%d%y')
LOG = os.path.join(os.getcwd(),f'squatters{date_label}.txt')
if not os.path.isfile(LOG):
    open(LOG,'w').write('SPOT_A_SQUAT\n')

fB = Fore.LIGHTBLUE_EX
fR = Fore.RED
fW = Fore.WHITE
fM = Fore.MAGENTA
fC = Fore.CYAN
fG = Fore.GREEN
fY = Fore.YELLOW
OFF = ''

top1m = pd.read_csv('top-1m.csv')
TOP_DOMAINS = list(top1m[:]['DOMAIN'])

def get_arecord_ip(host):
    ans = b''
    try:
        ans = str(dns.resolver.resolve(host, 'A')[0])
    except:
        pass
    return ans

def test_domain(dom_registered, dom_real, t):
    score = levenshtein(dom_real, dom_registered)
    try:
        ip = get_arecord_ip(name)
    except:
        ip = ''
        pass
    if 3 >= score >= 0:
        name = dom_registered.replace('*.','')
        log_msg = f'{t}{fB} {dom_registered} {fW}was registered {fW}[similar to {dom_real}? IP:{ip}]'
        print(log_msg)
        open('squatters_01.txt','a').write(u"[{}] {} (SAN: {} [similar to {dom_real}? IP:{ip})\n".format(t, dom_registered, m))
        # Maybe also show the Location data?
        return True
    else:
        return False

def print_callback(message, context):
	logging.debug("Message -> {}".format(message))
	if message['message_type'] == "heartbeat":
		return

	if message['message_type'] == "certificate_update":
		all_domains = message['data']['leaf_cert']['all_domains']

		if len(all_domains) == 0:
			domain = "NULL"
		else:
			domain = all_domains[0]
			tsfmt = datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')
			msg = " , ".join(message['data']['leaf_cert']['all_domains'][1:])
			try:
				IP =get_arecord_ip(domain.replace("*.", ""))
			except:
				IP = ''
				pass
       		
			sus = False
			threads = multiprocessing.Pool(8)
			for real_domain in TOP_DOMAINS[0:750]:
				event = threads.apply_async(test_domain, (domain,f'{real_domain}', tsfmt))
				if event.get(4):
					sus = True
					break
			if not sus:
				IP = get_arecord_ip(domain.replace("*.",""))
				if domain.split('.')[-1] in ['ru', 'cn','hk']:
					C = fR
				elif domain.split('.')[-1] in ['gg', 'work','ml']:
					C = '\033[1m'+fM
				elif 'autodiscover' in domain.split('.'):
					C = fC
				else:
					C = fG
				print(f'{tsfmt}{C} {domain} {fW}was registered at {IP}\033[0m')

if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
    