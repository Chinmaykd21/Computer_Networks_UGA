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
            raw_tcp_pkt = Ether()/IP(dst=target, ttl=timeToLive)/TCP(dport=dst_port, sport=12345, flags='S')
            # raw_tcp_pkt.show()
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
                        # print("ICMP: Time to live after:", timeToLive)
                        break
                    elif TCP in eth_pkt and eth_pkt[TCP].dport == 12345 and eth_pkt[TCP].flags == "SA":
                        et = time.time()
                        ipSrc = eth_pkt[IP].src
                        packetTime = str(round((et-st)*1000, 2)) + 'ms'
                        hop_list = print_hop_details(timeToLive, ipSrc, packetTime, flag,hop_list)
                        timeToLive = max_hops+1
                        # print("TCP: Time to live after:", timeToLive)
                        break
                    timer = timer + 0.01
                    if timer > 1:
                        ipSrc=''
                        packetTime = 0
                        flag = True
                        hop_list = print_hop_details(timeToLive, ipSrc, packetTime, flag, hop_list)
                        timeToLive += 1
                        # print("TIMER: Time to live after:", timeToLive)
                        break        
                except Exception as e:
                    pass
        timeToLive = 0
    # This function will get the appropriate host name or host Ip depending upon whether entered target by user is domain name or ip address.
    hostName, targetIp = getHostName(target)
    # To print the output
    print("traceroute to %s (%s), %d hops max, TCP SYN to port %d" % (hostName, targetIp, max_hops,dst_port))
    for i in hop_list:
        for j in i:
            print(j, end =" ")
        print()

def getHostName(target):
    try:
        hostName = socket.gethostbyaddr(target)[0]
        targetIp = socket.gethostbyaddr(target)[2]
        targetIp = targetIp[0].lstrip("['").rstrip("']")
    except Exception as e:
        print(e)
    return hostName, targetIp

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
            eachHop = hop_list[hop_number-1]
            for index, element in enumerate(eachHop):
                if len(str(element)) >= 7:
                    if element == hostIp and index >= int((len(eachHop)-1)/2):
                        eachHop.append(pTime)
                        break
                    elif element == hostIp:
                        eachHop.append(hostIp)
                        eachHop.append(pTime)
                        break
                    elif index == (len(eachHop)-2):
                        eachHop.append(hostIp)
                        eachHop.append(pTime)
                        break
        else:
            single_hop_details = []
            single_hop_details.append(hop_number)
            single_hop_details.append(hostIp)
            single_hop_details.append(pTime)
            hop_list.append(single_hop_details)
    
    return hop_list

def verifyIpAdd(target):
    try:
        # This line will check the legality of the resolver's IP address entered by the user
        socket.inet_aton(target)
    except socket.error:
        print("Entered Ip address or target is not valid. Exiting the program:", target)
        exit(0)

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
                    type=str, required=True)

    args = parser.parse_args()

    # This function will check if the dst mentioned is correct or not
    verifyIpAdd(args.t)
    
    # This function will process the incoming request from the user
    trace(args.m, args.p, args.t)

# calling the main function
if __name__=='__main__':
    main()