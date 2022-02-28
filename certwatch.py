import pandas as pd
import certstream
import datetime
import logging
import json
import sys

MALICIOUS = list(set(list(open('bad_hosts.txt','r').read().split('\n'))))
popups = pd.read_csv('popups.csv')
top1m = pd.read_csv('top-1m.csv')
TOP_DOMAINS = list(top1m[:]['DOMAIN'])
DOMAINS = list(popups[:]['Domain'])

fB = '\033[1m'
fR = '\033[31m'
fM = '\033[34m'
fC = '\033[36m'
fY = '\033[33m'
fI = '\033[3m'
OFF = '\033[0m'


def get_arecord_ip(host):
    return str(dns.resolver.resolve(host, 'A')[0])

def reverse_lookup(address):
    return str(dns.reversename.from_address(address))


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
            msg = ", ".join(message['data']['leaf_cert']['all_domains'][1:])
            try:
                ip = get_arecord_ip(domain)
            except:
                ip = 'unknown'
                pass
            if domain.split('.')[-1] in ['ua',' ru']:
                sys.stdout.write(fB+fY+u"[{}] {} (SAN: {}, IP: {})\n".format(tsfmt, domain, msg,ip)+OFF)
                sys.stdout.flush()
            elif 'mil' in domain.split('.'):
                print(f'{fB}{fI}{fR}[{tsfmt}] {domain} (SAN: {msg}, IP: {ip}){OFF}')
            elif domain.split('.')[-1] in ['pl','hk','nk']:
                print(f'{fB}{fM}[{tsfmt}] {domain} (SAN: {msg}, IP: {ip}){OFF}')
            elif domain.split('.')[-1] in ['cn','gov',]:
                print(f'{fB}{fI}{fC}[{tsfmt}] {domain} (SAN: {msg}, IP: {ip}){OFF}')
logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
