import dns.resolver
import certstream
import datetime
import logging
import sys
import os
logfile = 'NEW_DOMAINS.txt'

def get_arecord_ip(host):
    return str(dns.resolver.resolve(host, 'A')[0])

def print_callback(message, context):
    if not os.path.isfile(logfile):
        open(logfile,'w').write()
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
            if domain.split('.')[-1] == 'ru':
                try:
                    ip = get_arecord_ip(domain)
                except:
                    ip = 'unknown'
                    pass
                logline = u"[{}] {} (SAN: {}, IP: {})\n".format(tsfmt, domain, msg,ip)
                sys.stdout.write(logline)
                sys.stdout.flush()
                open(logfile, 'a').write(logline)


def main():
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')


if __name__ == '__main__':
    main()
