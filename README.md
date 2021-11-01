## Network Analyser using python and wireshark
python script to analyse `PCAP` files, able to extract information about specific IP addresses, guess suspicious IP addresses, able to extract and identify malicious payload and give statistics about top IP addresses, detect reverse shell, used `scapy` to parse pcap file and `pandas` to create data frames for statistics, scheduler script to run the script on constant intervals

### Usage
```python
~$ python .\network_analyser.py --help

usage: network_analyser.py [-h] --pcap <pcap file name> [--client <client IP:port>] 
                           [--server <server IP:port>] [--packet <packet number>] 
                           [--data_frame <src,dst,sport,dport>] [--stats <num,graph>]
                           [--suspicion <true>] [--payload <get,post>] 

Network Analyser

optional arguments:
  -h, --help                         show this help message and exit
  --pcap <pcap file name>            pcap file to parse
  --client <client IP:port>          clients IP and port
  --server <server IP:port>          server IP and port
  --packet <1>                       Packet Number
  --data_frame <src,dst,sport,dport> All IP Addresses and Ports
  --stats <num,graph>                Shows Statistics for given pcap file numerical or graphical
  --suspicion <true>                 Investigate for Suspicious IPs
  --payload <get,post>               Payload Investigation for specific protocols, detect reverse shell
```

### Example
#### Analyser
```python 
python network_analyser.py --pcap <pcap_file_name> --packet 1 --data_frame src,dst,sport,dport --stats num,graph --suspicion true --payload get,post 
```
#### Scheduler
```python 
python scheduler.py --pcap <pcap_file_name> --server_ip <server IP>
```

#### References 
[vnetman's blog](https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html) |
[Ronald Eddings Article](https://medium.com/hackervalleystudio/learning-packet-analysis-with-data-science-5356a3340d4e)
