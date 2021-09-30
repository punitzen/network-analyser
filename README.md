## Network Analyser using python and wireshark
python script to analyse `PCAP` files, able to extract information about specific IP addresses, guess suspicious IP addresses, able to extract and identify malicious payload and give statistics about top IP addresses, used `scapy` to parse pcap file and `pandas` to create data frames for statistics

### Usage
```python
~$ python .\network_analyser.py --help

usage: network_analyser.py [-h] --pcap <pcap file name> [--client CLIENT] [--server SERVER] [--packet PACKET]
                           [--data_frame DATA_FRAME] [--stats STATS] [--suspicion SUSPICION] 
                           [--payload PAYLOAD] [--ping_flood PING_FLOOD]

Network Analyser

optional arguments:
  -h, --help               show this help message and exit
  --pcap <pcap file name>  pcap file to parse
  --client CLIENT          clients IP and port
  --server SERVER          server IP and port
  --packet PACKET          Packet Number
  --data_frame DATA_FRAME  All IP Addresses and Ports, eg. --data_frame src,dst
  --stats STATS            Shows Statistics for given pcap file numerical or graphical, eg. --stats num,graph
  --suspicion SUSPICION    Investigate for Suspicious IPs
  --payload PAYLOAD        Payload Investigation for specific protocols, eg. --payload get,post
  --ping_flood PING_FLOOD  Detect ping flood attack, add server ip, eg. --ping_flood server_IP
```
### Example
#### Analyser
```python 
python network_analyser.py --pcap pcap_file_name --packet 1 --data_frame src,dst,sport,dport --stats num,graph --suspicion true --payload get,post --ping_flood server_IP
```
#### Scheduler
```python 
python scheduler.py --pcap pcap_file_name 
```

#### References 
[vnetman's blog](https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html) |
[Ronald Eddings Article](https://medium.com/hackervalleystudio/learning-packet-analysis-with-data-science-5356a3340d4e)
