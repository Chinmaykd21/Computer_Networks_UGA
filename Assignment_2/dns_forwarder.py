#!/usr/bin/env python
from scapy.all import DNS, DNSQR, IP, sr1, UDP, dnsqtypes, DNSRR
import subprocess
import argparse
import socket
import json
import os

# Function to arbitrary message from client and using that message we will forward it to the appropriate forwarder and then using this we will send the response to the client.
def recvMsg(dst_ip, deny_list_file, log_file):
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = 53

    print()
    print("DNS forwarder started on %s" % SERVER_IP)
    print()
    print("Listening for the DNS request from the client...")

    # DGRAM = datagram packet, means it can accept UDP packages
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((SERVER_IP, SERVER_PORT))
    except:
        print("Failed to bind the socket to %s server at port %d" %(SERVER_IP, SERVER_PORT))
        exit
    while 1:
        # UDP_PAYLOAD = entire udp message minus UDP_header
        client_payload, client_addr = sock.recvfrom(1024)
        print()
        print('DNS package has arrived from %s:%s' % client_addr)
        print()
        dns = DNS(client_payload)
        
        # To get the query type, e.g.,'A' = IPv4, 'AAAA' = IPv6
        queryType = dnsqtypes[dns[DNSQR].qtype]
        domainName = dns[DNSQR].qname.decode().rstrip(".")

        # send the domainName, deny_list_file, log_file to the checkDomain function.
        domain, flag = checkDomain(domainName, deny_list_file)
        
        # Store the returned result with the following format domainname querytype ALLOW/DENY in the log file
        storeLogs(domain, queryType, flag, log_file)

        # The domainName, flag will be forwarded to the dns_forwarder function, where the domain name will be forwarded to the dns_resolver
        if flag == "ALLOW":
            # This code fails when packets are sent through browser
            # ip_pkt = IP(dst = dst_ip)/UDP(dport=53)/dns
            # response = sr1(ip_pkt)
            # sock.sendto(bytes(response['DNS']), client_addr)

            # This is a workaround for the above issue
            out_sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            out_sckt.sendto(bytes(dns),(dst_ip,53))
            dns_response, resolver_addr = out_sckt.recvfrom(1024)
            sock.sendto(dns_response, client_addr)
            out_sckt.close()
            print("Check the client for the response from the resolver!")
            print()
            print("<------------------------End of the request------------------------>")
        elif flag == "DENY":
            # This flag indicate that this is the answer packet
            dns.qr = 1
            # This flag indicate the status of packet,i.e, the NXDomain packet
            dns.rcode = 3
            sock.sendto(bytes(dns), client_addr)
            print("Check the client for the response from the resolver!")
            print()
            print("<------------------------End of the request------------------------>")
    sock.close()

# this function will check if the domain name is blocked or not, and record the result in the log file
def checkDomain(domainName, deny_list_file):
    # Split the directory path and the deny_list file name in two variables
    pathToDir, fileName = os.path.split(deny_list_file)
    # First check if the path entered by the user is correct or not.
    if os.path.exists(os.path.abspath(pathToDir)):
        pathToFile = os.path.join(os.path.abspath(pathToDir), fileName)
        # Open the file and read the content line by line
        with open(pathToFile, "r") as readFile:
            print("Reading the denied domain name list from the file:", fileName)
            print()
            readLines = readFile.readlines()
            # Here we will check if the domain name sent from the client is present in the deny_list file or not.
            for line in readLines:
                # If the domain name is found in deny list then send an NX message to the client stating that the domain name is blocked
                fileDomain = line.rstrip(".").strip()
                if fileDomain == domainName:
                    print("%s domain name is present in the deny_list file, cannot forward %s domain name to the resolver" % (domainName, domainName))
                    print()
                    return (domainName, "DENY")
            print("%s domain name is NOT present in the deny_list file, forwarding %s domain name to the resolver" % (domainName, domainName))
            print()
            return (domainName, "ALLOW")
    else:
        print("The path enetered is not a valid path:", pathToDir)
        print()
        print("Reading from the example deny domain list created by the programmer from directory:", os.getcwd())
        print()
        # Reading from the current working directory
        with open("Deny_Domain.txt", "r") as readFile:
            print("Reading the denied domain name list from the file:Deny_Domain.txt")
            print()
            readLines = readFile.readlines()
            # Here we will check if the domain name sent from the client is present in the deny_list file or not.
            for line in readLines:
                # If the domain name is found in deny list then send an NX message to the client stating that the domain name is blocked
                fileDomain = line.strip().rstrip(".")
                if fileDomain == domainName:
                    print("%s domain name is present in the deny_list file, %s domain name is blocked" % (domainName, domainName))
                    print()
                    return (domainName, "DENY")
            print("%s domain name is NOT present in the deny_list file, forwarding %s domain name to the resolver" % (domainName, domainName))
            print()            
            return (domainName, "ALLOW")

# This function will store the logs in the log file mentioned by the user
def storeLogs(domain, queryType, flag, log_file):
    # Split the directory path and the deny_list file name in two variables
    pathToDir, fileName = os.path.split(log_file)
    # First check if the path entered by the user is correct or not.
    if os.path.exists(os.path.abspath(pathToDir)):
        pathToFile = os.path.join(os.path.abspath(pathToDir), fileName)
        # Open the file and read the content line by line
        with open(pathToFile, "a") as writeFile:
            log = str(domain) + " " +  str(queryType) + " " + str(flag) + "\n"
            writeFile.write(log)
        print("Check the logs at %s in file %s" % (os.path.abspath(pathToDir), log_file))
        print()
    else:
        with open(fileName, "a") as writeFile:
            log = str(domain) + " " +  str(queryType) + " " + str(flag) + "\n"
            writeFile.write(log)
        print("Check the logs at %s in file %s" % (os.getcwd(), log_file))
        print()

# Main function
def main():
    parser = argparse.ArgumentParser(description='DoH-capable DNS forwarder')
    
    parser.add_argument('-d', metavar='DST_IP',
                    help='Destination DNS server IP', 
                    type=str, default= '8.8.8.8')
    
    parser.add_argument('-f', metavar= 'DENY_LIST', 
                    help='File containing domains to block', 
                    type=str, required= True)
    
    parser.add_argument('-l', metavar= 'LOG_FILE',
                    help='Append-only log file', 
                    type=str, default= None)
    
    # parser.add_argument('--doh', help='Use default upstream DoH server',
    #                 type= str)
                    
    # parser.add_argument('--doh_server', metavar='DOH_SERVER',
    #                 help='Use this upstream DoH server',
    #                 type=str)
                        
    args = parser.parse_args()
    
    # Receieving the domain name from the dig command on the local server - This will start the server on 127.0.0.1:53 and keep on listening for the incoming traffics
    recvMsg(args.d, args.f, args.l)

# calling the main function
if __name__=='__main__':
    main()