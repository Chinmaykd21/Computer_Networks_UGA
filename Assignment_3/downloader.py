#!/usr/bin/env python
import argparse
import subprocess
import socket
import sys

# This function will get the content length from the HTTP response which we get from the GET request

# This function will get the hostname and the remaining part from the object url
def get_host(object_url):
    try:
        object_url = object_url.replace('http://','')
    except:
        object_url = object_url.replace('https://','')
    
    info = object_url.split('/', 1)
    host_name = info[0]
    req_part = info[1]
    return [host_name, req_part]

# def recvMsg(num_chunks, output_dir, file_name, object_url):
def main_downloader():
    num_chunks = 4
    object_url = 'http://cobweb.cs.uga.edu/~perdisci/CSCI6760-F20/test_files/generic_arch_steps375x250.png'
    TARGET_HOST, TARGET_INFO = get_host(object_url)
    SERVER_PORT = 80

    # STREAM = Means it can accept/send TCP packages
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_HOST, SERVER_PORT))

    except Exception as e:
        print("Failed to bind the socket to %s server at port %d.\n" %(TARGET_HOST, SERVER_PORT))
        print("""There might be two reason for this:\n 
        1. You did not run the file downloader.py with sudo.\n 
        2. This socket might be running on some other terminal on this system.\n 
        The server will be stopped, please restart the server after solving the potential issues.\n""")
        print("<--------------------------------------End of the DNS request-------------------------------------------->\n")
        exit(0)

    # Send some data
    request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % TARGET_HOST
    sock.send(request.encode())

    # receive data
    response = sock.recv(4096)
    
    # Getting the content length
    get_colength(response)


# Main function
def main():
    # parser = argparse.ArgumentParser(description='RUN TRACEROUTE MULTIPLE TIMES TOWARDS A GIVEN TARGET HOST.')
    
    # parser.add_argument('-n', metavar='num_chunks',
    #                 help='Number of chunks', 
    #                 type=int, default=1)
    
    # parser.add_argument('-o', metavar= 'output_dir', 
    #                 help='Directory name where the chunks will be stored', 
    #                 type=str, default = 'output_dir')
    
    # parser.add_argument('-f', metavar= 'file_name',
    #                 help='Name of the chunks which will be downloaded', 
    #                 type=str, default = 'file_name')
    
    # parser.add_argument('-u', metavar='object_url',
    #                 help='Object URL', 
    #                 type= str)
                        
    # args = parser.parse_args()
    
    # # calling out the trace function to start the processing
    # trace(args.n, args.o, args.f, args.u)

    main_downloader()

# calling the main function
if __name__=='__main__':
    main()