import os
import time
import datetime
from datetime import timezone

FREQ = 0.1
CYCLETIME = 1/FREQ

def run_network_analyser():
    print(" [+] Running Network Analyser")
    
    os.system(
        "tshark -T fields -e frame.time -e data.data -w sniffed_network.pcap -F pcap -c 3000")

    time.sleep(3)

    os.system("python network_analyzer.py --pcap sniffed_network.pcap --packet 1 --data_frame src,dst,sport,dport --stats num,graph --suspicion true --payload get,post")

def main():
    t0 = time.perf_counter()
    time_counter = t0
    while 1:
        now = time.perf_counter()
        elapsed_time = now - t0
        target_time = time_counter + CYCLETIME

        if elapsed_time < target_time:
            time.sleep(target_time - elapsed_time)

        milliseconds_since_epoch = datetime.datetime.now(timezone.utc)
        print('\n',milliseconds_since_epoch)
        run_network_analyser()
        time_counter += CYCLETIME


if __name__ == "__main__":
    main()