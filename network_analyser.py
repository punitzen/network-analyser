import argparse
import binascii
import os
import string
import sys

import matplotlib.pyplot as plt
import pandas as pd
from prettytable import PrettyTable
from scapy.all import *
from scapy.layers import http
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader
from termcolor import colored

tcp_payloads = ["nc -e /bin/sh", "bash -i >& /dev/tcp", "perl -e 'use Socket;$i=", "python -c 'import socket,os,pty;s=socket.socket", "ruby -rsocket -e'f=TCPSocket.open",
                "echo 'package main;import'os/exec';import", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i", "f (function_exists('pcntl_fork')) {// Fork and have the parent process exit $pid = pcntl_fork();"]

command_injection_list = ["cd", "ls", "id",
                          "dir", "sysinfo", "nc", "netstat", "pwd"]


def process_pcap(file_name, client, server):
    print(colored('\n[+] Opening', 'green'), '{}...'.format(file_name))

    if client or server is not None:
        (client_ip, client_port) = client.split(':')
        (server_ip, server_port) = server.split(':')

    count = 0
    interesting_packet_count = 0

    pcap_data = RawPcapReader(file_name)

    for pkt_data in pcap_data:
        count += 1
        if client or server is not None:
            ether_pkt = Ether(pkt_data)
            if 'type' not in ether_pkt.fields:
                continue
            if ether_pkt.type != 0x0800:
                continue

            ip_pkt = ether_pkt[IP]

            if ip_pkt.proto != 6:
                continue
            if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
                continue
            if (ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
                continue
            tcp_pkt = ip_pkt[TCP]

            if (tcp_pkt.sport != int(server_port)) and \
                    (tcp_pkt.sport != int(client_port)):
                continue

            if (tcp_pkt.dport != int(server_port)) and \
                    (tcp_pkt.dport != int(client_port)):
                continue

            interesting_packet_count += 1

    print(colored('[+]', 'yellow'), '{} contains'.format(file_name), colored('{} packets'.format(count),
                                                                             'yellow'), '(' + colored('{}'.format(interesting_packet_count), 'yellow') + ' interesting)')


def analysis_pcap(file_name, packet):
    pcap = rdpcap(file_name)
    print(colored("\n[+] Some Forensics...", 'green'))
    print(colored("[+]", 'blue'), "File Type", colored(type(pcap), 'blue'))
    print("[+] Lenght of Packets", colored(len(pcap), 'green'))
    print(colored("[+]", 'green'), "Raw", colored(pcap, 'green'))

    if packet is None:
        print("[+] Taken Default Packet Count...")
        # default packet
        ethernet_frame = pcap[0]
    else:
        ethernet_frame = pcap[int(packet)]

    ip_packet = ethernet_frame.payload
    segment = ip_packet.payload

    if packet is not None:
        if(segment.summary()[-1:] == "S"):
            print("[+] Packet number {} is Syn Packet".format(packet))
        elif(segment.summary()[-2:] == "SA"):
            print("[+] Packet number {} is Syn-Ack Packet".format(packet))
        elif(segment.summary()[-1:] == "A"):
            print("[+] Packet number {} is Ack Packet".format(packet))

    print(colored("[+]", 'blue'), "Packet Summary " + ip_packet.summary())

    summary = input("Detailed Summary? Y/N ")

    if(summary == "Y" or summary == "y"):
        print(colored("[+]", 'green'), "Detailed Summary...")
        ethernet_frame.show()
    else:
        return


def dataframe_pcap(file_name, frames):
    cols = frames.split(',')
    pcap = rdpcap(file_name)

    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    dataframe_fields = ip_fields + \
        ['time'] + tcp_fields + ['payload', 'payload_raw', 'payload_hex']
    global df
    df = pd.DataFrame(columns=dataframe_fields)

    print(colored('\n[+] ', 'green') +
          'Proccessing for each packets in ' + colored(file_name, 'yellow') + '...')

    i = 1

    for packet in pcap[IP]:
        field_values = []
        for field in ip_fields:
            if field == 'options':
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])

        if i == 1:
            print(colored('[+] ', 'green') +
                  'Proccessing for each fields in ' + colored(file_name, 'yellow') + '...')
            print("[+] ", end="")
        i = i + 1

        if i % 200 == 0:
            print(".", end="")

        field_values.append(packet.time)

        layer_type = type(packet[IP].payload)

        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)

        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(
            packet[layer_type].payload.original))
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)

    df = df.reset_index()
    df = df.drop(columns="index")
    print('\n')

    show_ips = input("[+] Show all unique IP Addresses Associated?.... Y/N ")

    if show_ips == 'Y' or show_ips == 'y':
        data_frame = []

        for ip in df['src']:
            data_frame.append(ip)

        for ip in df['dst']:
            data_frame.append(ip)

        unique_data_frame = list(set(data_frame))
        unique_data_frame.sort

        table = PrettyTable(['Sno.', 'IP'])
        i = 1

        for ip in unique_data_frame:
            table.add_row([i, ip])
            i = i + 1

        print(colored("[+]", 'yellow'),
              "Printing all unique IP Addresses found...")
        print(colored(table, 'yellow'))

    show_all = input(
        "[+] Show IP Addresses Associated with all packets?.... Y/N ")
    if show_all == "Y" or show_all == "y":
        print(df[cols])


def statistics():
    print(colored("\n[+]", 'yellow') + " Top Source Address")
    print(colored(df['src'].describe(), 'yellow'))

    print(colored("\n[+]", 'green') + " Top Destination Address")
    print(colored(df['dst'].describe(), 'green'))

    frequent_address = df['src'].describe()['top']

    print(colored("\n[+]", 'yellow') + " Who is Top Address Speaking to:\n",
          colored(df[df['src'] == frequent_address]['dst'].unique(), 'yellow'))

    print(colored("\n[+]", 'green') + " Who is the top address speaking to (Destination Ports)\n",
          colored(df[df['src'] == frequent_address]['dport'].unique(), 'green'))

    print(colored("\n[+]", 'yellow') + " Who is the top address speaking to (Source Ports)\n",
          colored(df[df['src'] == frequent_address]['sport'].unique(), 'yellow'))


def graphical_stats():
    source_addresses = df.groupby("src")['payload'].sum()
    source_addresses.plot(
        kind='barh', title="Addresses Sending Payloads", figsize=(8, 5))
    print(colored("\n[+]", 'green') +
          " Showing Source IPs sending payloads...")
    plt.show()

    source_payloads = df.groupby("sport")['payload'].sum()
    source_payloads.plot(
        kind='barh', title="Source Ports (Bytes Sent)", figsize=(8, 5))
    print(colored("\n[+]", 'yellow') +
          " Showing Source ports sending payloads...")
    plt.show()

    destination_payloads = df.groupby("dport")['payload'].sum()
    destination_payloads.plot(
        kind='barh', title="Destination Ports (Bytes Received)", figsize=(8, 5))
    print(colored("\n[+]", 'green') +
          " Showing Destination ports recieving payloads...")
    plt.show()


def ip_suspicion():
    print("\n[+] Investigating for Suspicious IP...")

    frequent_address = df['dst'].describe()['top']
    frequent_address_df = df[df['dst'] == frequent_address]

    frequent_address_groupby = frequent_address_df[[
        'src', 'dst', 'payload']].groupby("dst")['payload'].sum()

    print(colored("[+]", 'green') +
          " Showing Most Frequent Address Speaking To (Bytes)...")
    frequent_address_groupby.plot(
        kind='barh', title="Most Frequent Address is Speaking To (Bytes)", figsize=(8, 5))
    plt.show()

    suspicious_ip = frequent_address_groupby.sort_values(
        ascending=False).index[0]
    print(colored("[+]", 'yellow'), "Suspicious IP reaching out most to:",
          colored(suspicious_ip, 'yellow'))

    global suspicious_df
    suspicious_df = frequent_address_df[frequent_address_df['dst']
                                        == suspicious_ip]


def payload_investigation(file_name, payload):
    packets = rdpcap(file_name)

    protocols = payload.split(",")

    for protocol in protocols:
        protocol = protocol.upper()
        suspicious_ip = {}
        raw_payloads = {}
        for packet in packets:
            if not packet.haslayer('HTTPRequest'):
                continue
            http_layer = packet.getlayer('HTTPRequest').fields
            ip_layer = packet.getlayer('IP').fields

            if packet.getlayer('Raw') is not None:
                raw_payloads[str(packet.getlayer('Raw'))] = ip_layer['src']

            if protocol == 'POST':
                if http_layer['Method'] == b'POST':
                    suspicious_ip[ip_layer['src']] = http_layer['Path']
            elif protocol == 'GET':
                if http_layer['Method'] == b'GET':
                    suspicious_ip[ip_layer['src']] = http_layer['Path']

        if len(suspicious_ip) != 0:
            print(
                "\n[+] Found IPs making {} Request, You might wanna take a look at it!".format(protocol))

            if protocol == 'POST':
                print(colored("[+] Might be a Payload...", 'yellow'))

            for sus_ip in suspicious_ip:
                print(colored("[+]", 'yellow'), "Request from IP: " + colored(
                    sus_ip, 'yellow') + " to Server Path", colored(suspicious_ip[sus_ip], 'yellow'))

    for payload in tcp_payloads:
        for cur_payload in raw_payloads.keys():
            if payload in cur_payload:
                print(colored("\n[+] High Alert!", 'red'),
                      "Reverse Shell Detected from IP: ", end="")
                print(colored(raw_payloads[cur_payload], 'yellow'))
                print(colored("\n[+]", 'red'),
                      "Raw Payload extracted from the request:")
                print(colored(cur_payload, 'red') + '\n')


def command_injection(file_name):
    packets = rdpcap(file_name)

    raw_payload = {}

    for packet in packets:
        if packet.haslayer('TCP'):
            ip_layer = packet.getlayer('IP').fields
            if packet.getlayer('Raw') is not None:
                raw_payload[ip_layer['src']] = packet.getlayer('Raw')

    for cmd_inj in command_injection_list:
        for ip in raw_payload.keys():
            if cmd_inj in str(raw_payload[ip]):
                print(colored(
                    "\n[+]", 'red'), "Command Injection Detected from IP:", colored(ip, 'yellow'))
                print(colored(
                    "[+]", 'red'), "Command Extracted from Raw Payload:", colored(raw_payload[ip], 'red'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Network Analyser')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--client', metavar='<client IP:port>',
                        help='clients IP and port', required=False)
    parser.add_argument('--server', metavar='<server IP:port>',
                        help='server IP and port', required=False)
    parser.add_argument('--packet', metavar='<1>',
                        help='Packet Number', required=False)
    parser.add_argument(
        '--data_frame', metavar='<src,dst,sport,dport>', help='All IP Addresses and Ports', required=False)
    parser.add_argument(
        '--stats', metavar='<num,graph>', help='Shows Statistics for given pcap file numerical or graphical', required=False)
    parser.add_argument(
        '--suspicion', metavar='<true>', help='Investigate for Suspicious IPs', required=False)
    parser.add_argument(
        '--payload', metavar='<get,post>', help='Payload Investigation for specific protocols, detect reverse shell', required=False)
    parser.add_argument(
        '--cmd', metavar='<command injection>', help='Check raw payloads for Command Injection', required=False)

    args = parser.parse_args()

    file_name = args.pcap
    client = args.client
    server = args.server
    packet = args.packet
    frames = args.data_frame
    stats = args.stats
    suspicion = args.suspicion
    payload = args.payload
    cmd = args.cmd

    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(0)

    if (client is not None and server is None) or (client is None and server is not None):
        print("\nPlease include both --client and --server\n")
        sys.exit(0)

    if frames is None:
        if stats is not None:
            print('\nTo include --stats, include --data_frame tag\n')
            sys.exit(0)
        elif suspicion is not None:
            print('\nTo include --investigate, include --data_frame tag\n')
            sys.exit(0)

    process_pcap(file_name, client, server)
    analysis_pcap(file_name, packet)

    if frames is not None:
        dataframe_pcap(file_name, frames)

    if stats is not None:
        if stats == 'num':
            statistics()
        elif stats == 'graph':
            graphical_stats()
        elif stats == 'num,graph':
            statistics()
            graphical_stats()

    if suspicion is not None:
        ip_suspicion()

    if payload is not None:
        payload_investigation(file_name, payload)

    if cmd is not None:
        command_injection(file_name)
