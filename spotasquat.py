from colorama import init, Fore
import pandas as pd
import dns.resolver
import numpy as np
import certstream
import datetime
import logging

# Initializes Colorama
init(autoreset=True)

# pull from http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
top1m = pd.read_csv('top-1m.csv')
TOP_DOMAINS = list(top1m[:]['DOMAIN'])

fB = Fore.LIGHTBLUE_EX
fR = Fore.RED
fW = Fore.WHITE
fM = Fore.MAGENTA
fC = Fore.CYAN
fG = Fore.GREEN
fY = Fore.YELLOW
OFF = ''


def get_arecord_ip(host):
    return str(dns.resolver.resolve(host, 'A')[0])


def levenshtein(seq1, seq2):
    size_x = len(seq1) + 1
    size_y = len(seq2) + 1
    matrix = np.zeros ((size_x, size_y))
    for x in range(size_x):
        matrix [x, 0] = x
    for y in range(size_y):
        matrix [0, y] = y

    for x in range(1, size_x):
        for y in range(1, size_y):
            if seq1[x-1] == seq2[y-1]:
                matrix [x,y] = min(
                    matrix[x-1, y] + 1,
                    matrix[x-1, y-1],
                    matrix[x, y-1] + 1
                )
            else:
                matrix [x,y] = min(
                    matrix[x-1,y] + 1,
                    matrix[x-1,y-1] + 1,
                    matrix[x,y-1] + 1
                )
    return matrix[size_x - 1, size_y - 1]


def reverse_lookup(address):
    return str(dns.reversename.from_address(address))


def spot_a_squat(ts, domain, msg):
    for legit in TOP_DOMAINS:
        score = levenshtein(domain, legit)
        if 2 >= score > 0:
            print(f'{ts} {fR} {domain} {fW} {msg} [similar to {legit}?]')


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
            spot_a_squat(tsfmt, domain, msg)
            # Check if the domain looks like a misspelling of a common domain/target domain
            score = levenshtein(domain, 'discord.com')
            if 2 >= score > 0:
                print(f'{tsfmt} {fR} {domain} {fW} was registered [similar to discord?]')


if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
