#!/usr/bin/env python
from scapy.all import DNS, DNSQR, IP, sr1, TCP, dnsqtypes, DNSRR, Ether
from scapy.layers.inet import *
from scapy.layers.dns import *
import subprocess
import argparse
import requests
import base64
import socket
import json
import time
import os


def trace(max_hops, dst_port, target):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    sock.bind(('ens3',0))
    sock.setblocking(0)
    hop_list = []
    for _ in range(1,4):
        timeToLive = 1
        while timeToLive <= max_hops :
            print("\n==================start===================")
            raw_tcp_pkt = Ether()/IP(dst=target, ttl=timeToLive)/TCP(dport=dst_port, sport=12345, flags='S')
            raw_tcp_pkt.show()
            st = time.time()
            sock.send(bytes(raw_tcp_pkt))
            timer = 0
            flag = False
            while True:
                try:
                    pkt = sock.recv(1480)
                    eth_pkt = Ether(pkt)
                    if ICMP in eth_pkt:
                        et = time.time()
                        ipSrc = eth_pkt[IP].src
                        packetTime = str(round((et-st)*1000, 2)) + 'ms'
                        hop_list = print_hop_details(timeToLive, ipSrc, packetTime, flag, hop_list)
                        timeToLive += 1
                        print("Time to live after:", timeToLive)
                        break
                    elif TCP in eth_pkt and eth_pkt[TCP].dport == 12345 and eth_pkt[TCP].flags == "SA":
                        et = time.time()
                        ipSrc = eth_pkt[IP].src
                        packetTime = str(round((et-st)*1000, 2)) + 'ms'
                        hop_list = print_hop_details(timeToLive, ipSrc, packetTime, flag,hop_list)
                        timeToLive = max_hops+1
                        print("Time to live after:", timeToLive)
                        break
                    timer = timer + 0.01
                    if timer > 1:
                        ipSrc=''
                        packetTime = 0
                        flag = True
                        hop_list = print_hop_details(timeToLive, ipSrc, packetTime, flag, hop_list)
                        timeToLive += 1
                        print("Time to live after:", timeToLive)
                        break        
                except Exception as e:
                    pass
        timeToLive = 0
    for i in hop_list:
        for j in i:
            print(j, end =" ")
        print()
    return

def print_hop_details(hop_number, hostIp, pTime, flag, hop_list):
    
    if flag:
        if len(hop_list) >= hop_number:
            hop_list[hop_number-1].append("*")
        else:
            single_hop_details = []
            single_hop_details.append(hop_number)
            single_hop_details.append("*")
            hop_list.append(single_hop_details)
    else:
        if len(hop_list) >= hop_number:
            # for eachHop in hop_list:
            #     if eachHop[0] == hop_number:
            eachHop = hop_list[hop_number-1]
            for index, element in enumerate(eachHop):
                if len(element) >= 7:
                    if element == hostIp and index >= int((len(eachHop)-1)/2):
                        eachHop.append(pTime)
                    elif element == hostIp:
                        eachHop.append(hostIp)
                        eachHop.append(pTime)
        else:
            single_hop_details = []
            single_hop_details.append(hop_number)
            single_hop_details.append(hostIp)
            single_hop_details.append(pTime)
            hop_list.append(single_hop_details)
    return hop_list

# Main function
def main():
    parser = argparse.ArgumentParser(description='DoH-capable DNS forwarder')
    
    parser.add_argument('-m', metavar='MAX_HOPS',
                    help='Max hops to probe', 
                    type=int, default= 30)
    
    parser.add_argument('-p', metavar= 'DST_PORT', 
                    help='File containing domains to block', 
                    type=int, default=80)
    
    parser.add_argument('-t', metavar= 'TARGET',
                    help='Target domain or IP', 
                    type=str, default= '8.8.8.8', required=True)

    args = parser.parse_args()
    
    trace(args.m, args.f, args.t)

# calling the main function
if __name__=='__main__':
    main()