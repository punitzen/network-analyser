import argparse
import datetime
import os
import sys
import time
from datetime import timezone

FREQ = 0.1
CYCLETIME = 1/FREQ


def run_network_analyser(file_name, server_ip):
    print(" [+] Running Network Analyser")

    os.system(
        "tshark -T fields -e frame.time -e data.data -w {} -F pcap -c 3000".format(file_name))

    time.sleep(3)

    os.system("python network_analyser.py --pcap {} --packet 1 --data_frame src,dst,sport,dport --stats num,graph --suspicion true --payload get,post --cmd true".format(file_name))


def main(file_name, server_ip):
    t0 = time.perf_counter()
    time_counter = t0
    while 1:
        now = time.perf_counter()
        elapsed_time = now - t0
        target_time = time_counter + CYCLETIME

        if elapsed_time < target_time:
            time.sleep(target_time - elapsed_time)

        milliseconds_since_epoch = datetime.datetime.now(timezone.utc)
        print('\n', milliseconds_since_epoch)
        run_network_analyser(file_name, server_ip)
        time_counter += CYCLETIME


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Analyser Scheduler')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--server_ip', help='server ip', required=False)

    args = parser.parse_args()

    file_name = args.pcap
    server_ip = args.server_ip

    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(0)

    main(file_name, server_ip)
