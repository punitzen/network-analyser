## Network Analyzer using python and wireshark
python script to analyse `PCAP` files, able to extract information about specific IP addresses, guess suspicious IP addresses, able to extract and identify malicious payload and give statistics about top IP addresses, used `scapy` to parse pcap file and `pandas` to create data frames for statistics

### Usage
```python
~$ python .\network_analyzer.py --help

usage: network_analyzer.py [-h] --pcap <pcap file name> [--client CLIENT] [--server SERVER] [--packet PACKET] 
                           [--data_frame DATA_FRAME] [--stats STATS] [--suspicion SUSPICION] 
                           [--payload PAYLOAD]

Network Analyzer

optional arguments:
  -h, --help              show this help message and exit
  --pcap <pcap file name> pcap file to parse
  --client CLIENT         clients IP and port
  --server SERVER         server IP and port
  --packet PACKET         Packet Number
  --data_frame DATA_FRAME All IP Addresses and Ports, eg. --data_frame src,dst
  --stats STATS           Shows Statistics for given pcap file numerical or graphical, eg. num,graph
  --suspicion SUSPICION   Investigate for Suspicious IPs
  --payload PAYLOAD       Payload Investigation for specific protocols, eg. get,post
```
### example
```python 
~$ python network_analyzer.py --pcap pcap_file_name --packet 1 --data_frame src,dst,sport,dport --stats num,graph --suspicion true --payload get,post
```

### References 
[vnetman's blog](https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html)

[Ronald Eddings Article](https://medium.com/hackervalleystudio/learning-packet-analysis-with-data-science-5356a3340d4e)
