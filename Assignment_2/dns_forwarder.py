#!/usr/bin/env python
from scapy.all import DNS, DNSQR, IP, sr1, UDP, dnsqtypes, DNSRR
import subprocess
import argparse
import requests
import base64
import socket
import json
import os

# Function to arbitrary message from client and using that message we will forward it to the appropriate forwarder and then using this we will send the response to the client.
def recvMsg(dst_ip, deny_list_file, log_file, defaultDoH, doh_server=None):
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = 53

    print("\n<--------------------------------------Start of the DNS request------------------------------------------->\n")
    print("Listening on %s for the request from the client...\n" % SERVER_IP)

    # DGRAM = datagram packet, means it can accept UDP packages
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((SERVER_IP, SERVER_PORT))
    except Exception as e:
        print("Failed to bind the socket to %s server at port %d.\n" %(SERVER_IP, SERVER_PORT))
        print("""There might be two reason for this:\n 
        1. The file dns_forwarder.py does not have permission to run the code. 
        (in this case please give proper permissions to the file or run the code with sudo)\n 
        2. This socket might be running on some other terminal on this system.\n 
        The server will be stopped, please restart the server after solving the potential issues.\n""")
        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")
        exit(0)

    while 1:
        # UDP_PAYLOAD = entire udp message minus UDP_header
        client_payload, client_addr = sock.recvfrom(1024)
        print('DNS package has arrived from %s:%s\n' % client_addr)
        try:
        # Converting the byte packet to DNS format using scapy
            dns = DNS(client_payload)
            if not dns.qd:
                print("Please send valid DNS packets.\n")
                exit(0)
        except Exception as e:
            print("Error while converting the packet recieved from client\n")
            print(e)

        # To get the query type, e.g.,'A' = IPv4, 'AAAA' = IPv6
        queryType = dnsqtypes[dns[DNSQR].qtype]

        # To get the domain name
        domainName = dns[DNSQR].qname.decode()

        if domainName == ".":
        # send the domainName, deny_list_file, log_file to the checkDomain function.
            domain, flag = checkDomain(domainName, deny_list_file)
        else:
            domainName = domainName.rstrip(".")
            domain, flag = checkDomain(domainName, deny_list_file)

        # Store the returned result with the following format domainname querytype ALLOW/DENY in the log file
        storeLogs(domain, queryType, flag, log_file)

        if flag == "ALLOW":
        # If the defaultDoH is True then use DoH method to send the DNS request over https otherwise use normal DNS resolver
            if defaultDoH == True and doh_server == None:
                # defaultDoH server
                doh_server = "dns.google"
                print("Default DoH server:%s\n" % doh_server)
                # Encode the dns packet in base_64 encoding before sending it via DoH
                base64_dns = base64.urlsafe_b64encode(bytes(client_payload)).rstrip(b"=")
                append_string = str(base64_dns, 'UTF-8')
                print("DNS query with url safe base64 encoding:\n%s\n" % append_string)
                # use this string to attach to the request.get method
                query_string = "https://" + doh_server + "/dns-query?dns=" + append_string
                # Using the request module query DNS over https
                try:
                    https_response = requests.get(query_string)
                    # if the status code of the reponse is 200 then send the response to the client, otherwise send NXDomain packet to the client
                    if https_response.status_code == 200:
                    # Sending the https_response.content(which is byte object) to the client and it will print the reponse properly
                        sock.sendto(https_response.content, client_addr)
                        print("Status code:%d\n" % https_response.status_code)
                        print("Response sent to the client.\n")
                        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")
                    else:
                        print("Response recieved from the doh_server does not have status code 200. Sending NXDomain packet to client\n")
                        print("Status code:%d\n" % https_response.status_code)
                        dns.qr = 1
                        # This flag indicate the status of packet,i.e, the NXDomain packet
                        dns.rcode = 3
                        sock.sendto(bytes(dns), client_addr)
                        print("Check the client for the response from the resolver!\n")
                        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")

                except requests.RequestException as e:
                    print("There might be some error while getting response from DoH server. Sending NXDomain packet to client.\n")
                    print("<--------------------------------------End of the DNS request-------------------------------------------->\n")

            elif defaultDoH == True and doh_server != None:
                print("Using doh_server %s entered by the user\n" % doh_server)
                
                # Encode the dns packet in base_64 encoding before sending it via DoH
                base64_dns = base64.urlsafe_b64encode(bytes(client_payload)).rstrip(b"=")
                append_string = str(base64_dns, 'UTF-8')
                
                print("DNS query with base64 encoding:\n%s\n" % append_string)
                
                # use this string to attach to the request.get method
                query_string = "https://" + doh_server + "/dns-query?dns=" + append_string
                
                # Using the request module query DNS over https
                try:
                    https_response = requests.get(query_string)
                    if https_response.status_code == 200:
                        print("Status code:%d\n" % https_response.status_code)
                        # Converting the https_response object to the DNS packet and then send it to checkID function
                        new_response = checkID(dns, DNS(https_response.content))

                        # Sending the https_response(which is byte object) to the client and it will print the reponse properly
                        sock.sendto(new_response, client_addr)
                        print("Check the client for the response from the resolver!\n")
                        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")
                    else:
                        print("Response recieved from the doh_server does not have status code 200. Sending NXDomain packet to client\n")
                        print("Status code:%d\n" % https_response.status_code)
                        dns.qr = 1
                        # This flag indicate the status of packet,i.e, the NXDomain packet
                        dns.rcode = 3
                        sock.sendto(bytes(dns), client_addr)
                        print("Check the client for the response from the resolver!\n")
                        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")

                except requests.RequestException as e:
                    print("There might be some error while getting response from DoH server. Sending NXDomain packet to client.\n")
                    print("<--------------------------------------End of the DNS request-------------------------------------------->\n")

            elif defaultDoH == False and doh_server != None:
                print("Using doh_server %s entered by the user\n" % doh_server)
                
                # Encode the dns packet in base_64 encoding before sending it via DoH
                base64_dns = base64.urlsafe_b64encode(bytes(client_payload)).rstrip(b"=")
                append_string = str(base64_dns, 'UTF-8')
                
                # use this string to attach to the request.get method
                query_string = "https://" + doh_server + "/dns-query?dns=" + append_string
                
                print("DNS query with base64 encoding:\n%s\n" % append_string)

                # Using the request module query DNS over https
                try:
                    https_response = requests.get(query_string)

                    if https_response.status_code == 200:
                        print("Status code:%d\n" % https_response.status_code)
                        # Converting the https_response object to the DNS packet and then send it to checkID function
                        new_response = checkID(dns, DNS(https_response.content))

                        # Sending the https_response(which is byte object) to the client and it will print the reponse properly
                        sock.sendto(new_response, client_addr)
                        print("Check the client for the response from the resolver!\n")
                        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")
                    else:
                        print("Response recieved from the doh_server does not have status code 200. Sending NXDomain packet to client\n")
                        print("Status code:%d\n" % https_response.status_code)
                        dns.qr = 1
                        # This flag indicate the status of packet,i.e, the NXDomain packet
                        dns.rcode = 3
                        sock.sendto(bytes(dns), client_addr)
                        print("Check the client for the response from the resolver!\n")
                        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")

                except requests.RequestException as e:
                    print("There might be some error while getting response from DoH server. Sending NXDomain packet to client.\n")
                    print("<------------------------End of the DNS request------------------------>\n")
            
            else:
                # Here check the IP address entered, if it is valid then only proceed, otherwise program will exit.
                checkIP(dst_ip)

                # This is a workaround for the above issue
                out_sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                out_sckt.sendto(bytes(dns),(dst_ip,53))
                dns_response, resolver_addr = out_sckt.recvfrom(1024)
                sock.sendto(dns_response, client_addr)
                out_sckt.close()
                print("Check the client for the response from the resolver!\n")
                print("<--------------------------------------End of the DNS request-------------------------------------------->\n")

        elif flag == "DENY":
                # This flag indicate that this is the answer packet
                dns.qr = 1
                # This flag indicate the status of packet,i.e, the NXDomain packet
                dns.rcode = 3
                sock.sendto(bytes(dns), client_addr)
                print("Check the client for the response from the resolver!\n")
                print("<------------------------End of the DNS request------------------------>\n")
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
            readLines = readFile.readlines()
            # Here we will check if the domain name sent from the client is present in the deny_list file or not.
            for line in readLines:
                # if the entered domain packet is "." or " "
                if line == domainName:
                    print("%s domain name is present in the \"%s\" file, %s domain name is blocked.\n" % (domainName, fileName,domainName))
                    return (domainName, "DENY")
                # If the domain name is found in deny list then send an NX message to the client stating that the domain name is blocked
                else:
                    fileDomain = line.strip().rstrip(".")
                    if fileDomain == domainName:
                        print("%s domain name is present in the \"%s\" file, %s domain name is blocked.\n" % (domainName, fileName,domainName))
                        return (domainName, "DENY")
            print("Allowed Queried Domain:%s\n" % domainName)
            return (domainName, "ALLOW")
    else:
        print("The path enetered is not a valid path:\n", pathToDir)
        print("Reading from the \"Deny_Domain.txt\" created by the programmer from directory:\n", os.getcwd())
        # Reading from the current working directory
        with open("Deny_Domain.txt", "r") as readFile:
            readLines = readFile.readlines()
            # Here we will check if the domain name sent from the client is present in the deny_list file or not.
            for line in readLines:
                # if the entered domain packet is "." or " "
                if line == domainName:
                    print("%s domain name is present in the \"%s\" file, %s domain name is blocked.\n" % (domainName, fileName,domainName))
                    return (domainName, "DENY")
                else:
                # If the domain name is found in deny list then send an NX message to the client stating that the domain name is blocked
                    fileDomain = line.strip().rstrip(".")
                    if fileDomain == domainName:
                        print("%s domain name is present in the Deny_Domain.txt file, %s domain name is blocked.\n" % (domainName, domainName))
                        return (domainName, "DENY")
            print("Allowed Queried Domain:%s\n" % domainName)
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
        print("Access the log file \"%s\" at %s\n" % (log_file, os.path.abspath(pathToDir)))
    else:
        with open(fileName, "a") as writeFile:
            log = str(domain) + " " +  str(queryType) + " " + str(flag) + "\n"
            writeFile.write(log)
        print("Access the log file \"%s\" at %s\n" % (log_file, os.path.abspath(pathToDir)))

# Invalid IP address or domain name as a parameter is not accepted, and upon identifying the legality of IP address this function will terminate the server
def checkIP(ip):
    try:
        # This line will check the legality of the resolver's IP address entered by the user
        socket.inet_aton(ip)
    except socket.error:
        print("For -d parameter, either entered IP address is invalid or domain name is entered instead of IP address.\n")
        print("-d parameter only accepts resolver's IP address\n")
        print("Please restart the server program with correct -d\n")
        print("<------------------------End of the DNS request------------------------>\n")
        exit(0)

# This function will check the ID returned by the https_reponse and compare it with DNS packet came from the client
def checkID(clientDNS, dohDNS):
    if clientDNS.id != dohDNS.id:
        print("Responding server sent a response packet with a different ID than the ID of packet sent by client")
        print("Client ID:%d  Response ID:%d" % (clientDNS.id, dohDNS.id))
        print("Changing the reponse packet ID to %d\n" % clientDNS.id)
        dohDNS.id = clientDNS.id
        return bytes(dohDNS)
    return bytes(dohDNS)

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
                    type=str, default= 'log.txt')
    
    parser.add_argument('--doh', help='Use default upstream DoH server',
                    action='store_true')
                    
    parser.add_argument('--doh_server', metavar='DOH_SERVER',
                    help='Use this upstream DoH server',
                    type=str)

    args = parser.parse_args()
    
    # Receieving the domain name from the dig command on the local server - This will start the server on 127.0.0.1:53 and keep on listening for the incoming traffics
    recvMsg(args.d, args.f, args.l, args.doh, args.doh_server)

# calling the main function
if __name__=='__main__':
    main()