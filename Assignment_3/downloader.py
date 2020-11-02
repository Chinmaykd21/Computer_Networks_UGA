#!/usr/bin/env python
import argparse
import subprocess
import socket
import sys
import re

# This function will get the content length from the HTTP response which we get from the GET request
def get_colength(response):
    # if the Accept-range is bytes then only return the content length otherwise exit the downloader
    decode_response = response.split(b'\r\n\r\n')[0].decode("utf-8")
    match = re.search(r'Accept-Ranges: bytes', decode_response)
    if match:
        pre_data = decode_response.split('\r\n')
        for i in range(len(pre_data)):
            eachData = pre_data[i].split()
            if eachData[0] == 'Content-Length:':
                content_length = int(eachData[1])
                break
    else:
        print("Since Accept-Ranges does not have bytes value, downloader cannot support ranges to download chunk.")
        exit(0)
    return content_length

# This function will get the hostname and the remaining part from the object url
def get_host(object_url):
    try:
        object_url = object_url.replace('http://','')
    except:
        object_url = object_url.replace('https://','')
    
    info = object_url.split('/', 1)
    host_name = info[0]
    req_part = info[1]
    return (host_name, req_part)

# This function will create a list which contains information about size of chunks
def get_range_list(sizeOfSingleChunk, sizeOfLastChunk, content_length, num_chunks):
    outputRange = [0]
    if sizeOfLastChunk == 0:
        i = 0
        tmp = 0
        while tmp < content_length:
            tmp = outputRange[i] + sizeOfSingleChunk
            outputRange.append(tmp)
            i = i + 1
    else:
        i = 0
        tmp = 0
        while ((tmp < content_length) and (i < num_chunks - 1)):
            tmp = outputRange[i] + sizeOfSingleChunk
            outputRange.append(tmp)
            i = i + 1
        outputRange.append(outputRange[i] + sizeOfLastChunk)

    print(outputRange)
    
    return outputRange

# This function will create ranged GET http/1.1 request
def make_sock_conn(TARGET_HOST, TARGET_INFO, startRange, endRange):
    SERVER_PORT = 80
    print(startRange)
    print(endRange)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_HOST, SERVER_PORT))

    except Exception as e:
        print("Failed to bind the socket to %s server at port %d.\n" %(TARGET_HOST, SERVER_PORT))
        exit(0)

    # Send GET request to get the content-length
    request = "GET /%s HTTP/1.1\r\nHost:%s\r\nRange: bytes=%d-%d\r\n\r\n" % (TARGET_INFO ,TARGET_HOST, startRange, endRange)
    sock.send(bytes(request, 'utf-8'))
    opResponse = []
    while True:
        response = sock.recv(65536)
        if not response:
            print("Got all the data")
            break
        else:
            opResponse.append(response)
            print("Appending the data to opResponse list")
    print("The end")
    sock.close()


# def recvMsg(num_chunks, output_dir, file_name, object_url):
def main_downloader():
    num_chunks = 3
    object_url = 'http://cobweb.cs.uga.edu/~perdisci/CSCI6760-F20/test_files/generic_arch_steps375x250.png'
    TARGET_HOST, TARGET_INFO = get_host(object_url)
    SERVER_PORT = 80

    # STREAM = Means it can accept/send TCP packages
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_HOST, SERVER_PORT))

    except Exception as e:
        print("Failed to bind the socket to %s server at port %d.\n" %(TARGET_HOST, SERVER_PORT))
        exit(0)

    # Send some data
    request = "GET /%s HTTP/1.1\r\nHost:%s\r\n\r\n" % (TARGET_INFO ,TARGET_HOST)
    sock.send(bytes(request, 'utf-8'))

    # receive data
    response = sock.recv(65536)
    # Getting the content length
    content_length = get_colength(response)
    
    # To get the size of the single chunk
    sizeOfSingleChunk = 0
    sizeOfLastChunk = 0
    if (content_length % num_chunks == 0):
        sizeOfSingleChunk = content_length// num_chunks
        sizeOfLastChunk = 0
    else:
        sizeOfSingleChunk = content_length // num_chunks
        sizeOfLastChunk = (content_length % num_chunks) + (content_length // num_chunks)

    # creating the list of bytes range
    outputRange = get_range_list(sizeOfSingleChunk, sizeOfLastChunk, content_length, num_chunks)
    
    # close the socket connection
    sock.close()

    # creating ranged request using makesocket function
    for i in range(num_chunks):
        if i < num_chunks - 1:
            print(i)
            make_sock_conn(TARGET_HOST, TARGET_INFO, outputRange[i], outputRange[i+1] - 1)
        else:
            print(i)
            make_sock_conn(TARGET_HOST, TARGET_INFO, outputRange[i], outputRange[i+1])


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