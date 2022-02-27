import logging
import sys
import datetime
import certstream


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
            if domain.split('.')[-1] == 'ru':
                sys.stdout.write(u"[{}] {} (SAN: {})\n".format(tsfmt, domain, msg))
                sys.stdout.flush()


def main():
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')


if __name__ == '__main__':
    main()