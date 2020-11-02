#!/usr/bin/env python
from threading import Thread
import subprocess
import threading
import argparse
import fnmatch
import socket
import sys
import re
import os
import math

# This function will check the status code of the HTTP response, and if the reponse is other than 200, 201, 202, 203, 204, 205, 206, 207, 208, 226 these status codes, it will return false.
def get_status_code_main(response):
    response_status_flag = False
    response_status_code = 0
    status_codes = [200, 201, 202, 203, 204, 205, 206, 207, 208, 226]
    # To get the header
    response_header = response.split(b'\r\n\r\n')[0].decode('utf-8')

    # To get the HTTP status line
    split_header = response_header.split('\r\n')

    # To get the status code
    for eachLine in split_header:
        eachData = eachLine.split()
        if eachData[0] == 'HTTP/1.1':
            response_status_code = int(eachData[1])
            break
    
    # Check if response status code is present in the pre-determined status codes.
    if (response_status_code in status_codes):
        response_status_flag = True
        return (response_status_code, response_status_flag)

    return (response_status_flag, response_status_code)

def get_status_code(split_decoded_http_header):
    response_status_flag = False
    response_status_code = 0
    status_codes = [200, 201, 202, 203, 204, 205, 206, 207, 208, 226]

    # To get the status code
    for eachLine in split_decoded_http_header:
        eachData = eachLine.split()
        if eachData[0] == 'HTTP/1.1':
            response_status_code = int(eachData[1])
            break
    
    # Check if response status code is present in the pre-determined status codes.
    if (response_status_code in status_codes):
        response_status_flag = True
        return (response_status_code, response_status_flag)

    return (response_status_flag, response_status_code)

# This function will get the content length from the HTTP response which we get from the GET request
def get_colength(response):
    # if the Accept-range is bytes then only return the content length otherwise exit the downloader
    decode_response = response.split(b'\r\n\r\n')[0].decode("utf-8")
    print("Decoded response header to get content-length", decode_response)
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
        exit()
    return content_length

# This function will get the hostname and the remaining part from the object url
def get_host(object_url):
    try:
        object_url = object_url.replace('http://','')
    except:
        object_url = object_url.replace('https://','')
    
    info = object_url.split('/', 1)
    if len(info) == 2:
        host_name = info[0]
        req_part = info[1]
    else:
        host_name = info[0]
        req_part = ''
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
def make_sock_conn(TARGET_HOST, TARGET_INFO, startRange, endRange, output_dir, file_name, num):
    SERVER_PORT = 80
    opResponse = b''
    http_header = b''
    http_content_length = 0
    response_status_code = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_HOST, SERVER_PORT))
    except Exception as e:
        print("Failed to bind the socket to %s server at port %d.\n" %(TARGET_HOST, SERVER_PORT))
        exit(0)

    request = "GET /%s HTTP/1.1\r\nHost:%s\r\nRange: bytes=%d-%d\r\n\r\n" % (TARGET_INFO ,TARGET_HOST, startRange, endRange)
    print("Request:", request)
    sock.send(bytes(request, 'utf-8'))

    while True:
        try:
            response = sock.recv(65536)
        except Exception as e:
            print(e)
        
        if http_header == b'':
            http_header, http_body = response.split(b'\r\n\r\n',1)
            decode_http_header = http_header.decode('utf-8')
            print(decode_http_header)
            split_decoded_http_header = decode_http_header.split('\r\n')
            # checking the status code with this function
            response_status_flag, response_status_code = get_status_code(split_decoded_http_header)
            if response_status_flag:
                http_content_length = http_content_length + len(http_body)
                opResponse = opResponse + http_body
            else:
                print("The status code of the partial HTTP request is:", response_status_code)
                print("Exiting the downloader...")
                exit()
        else:
            http_content_length = http_content_length + len(response)
            opResponse = opResponse + response
        
        if http_content_length == (endRange - startRange + 1):
            break

    #     if (not response) or (response == -1) or (response == 0): # -1 & 0 are also one of the checks to stop the data
    #     # if len(opResponse) == endRange-startRange: # -1 & 0 are also one of the checks to stop the data
    #         print("Got all the data \n =========================================")
    #         break
    #     else:
    #         print("Appending the data to opResponse list")
    #         opResponse = opResponse + response
    
    # response_body = opResponse.split(b'\r\n\r\n', 1) # To seperate header from body and then send the data for saving
    print("length of chunk ============> " , len(opResponse))
    # save opResponse bytes data to chunks file
    save_chunk(opResponse, output_dir, file_name, num)
    sock.close()

# This function will read all the files from the folder and then it will merge all of them in one single file
def make_single_file(output_dir, file_name, num_chunks):
    limit = 1
    if os.path.exists(os.path.abspath(output_dir)):
        fullOp=b''
        for i in range(num_chunks):
            tmpFile = file_name + '.chunk_' + str(limit)       
            print("Inside")
            with open(os.path.join(output_dir, tmpFile), "rb") as op:
                fullOp = fullOp + op.read()
                print("---------")
                op.close()
            limit = limit + 1

        finalOp = os.path.join(os.path.abspath(output_dir), file_name)
        with open(finalOp, "wb") as opt:
            opt.write(fullOp)

# This function will save the HTTP response to the filenames in following format file_name.chunk_1, file_name.chunk_2, etc.
def save_chunk(opResponse, output_dir, file_name, num):
    # If given path does not exists then create directory at the mentioned path.
    if not os.path.exists(output_dir):
        # create a directory with name given by the variable output_dir
        os.makedirs(output_dir)
    # this will be the output file name
    opName = file_name + '.chunk_' + str(num)
    # This will be the absolute path with the file name
    opFile = os.path.join(os.path.abspath(output_dir), opName)
    # This line will write the data
    try:
        out = open(opFile, 'wb')
        out.write(opResponse)
    except Exception as e:
        print(e)

def recvMsg(num_chunks, output_dir, file_name, object_url):
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

    try:
        # receive data
        response = sock.recv(65536)
    except Exception as e:
        print(e)
        exit()

    # If the response_status_flag is True then only run the below code, otherwise end the program with appropriate print message
    response_status_flag, response_status_code = get_status_code_main(response)
    
    if response_status_flag:
        # Getting the content length
        content_length = get_colength(response)
        
        # To get the size of the single chunk
        sizeOfSingleChunk = 0
        sizeOfLastChunk = 0
        if (content_length % num_chunks == 0):
            sizeOfSingleChunk = math.floor(content_length / num_chunks)
            sizeOfLastChunk = 0
        else:
            sizeOfSingleChunk = math.floor(content_length / num_chunks)
            sizeOfLastChunk = (content_length % num_chunks) + math.floor(content_length / num_chunks)

        # creating the list of bytes range
        outputRange = get_range_list(sizeOfSingleChunk, sizeOfLastChunk, content_length, num_chunks)
        
        # close the socket connection
        sock.close()

        list_thread = []

        # creating ranged request using make_sock_conn function using threading
        for i in range(num_chunks):
            if i < num_chunks - 1:
                print("starting thread")
                thread = Thread(target=make_sock_conn, args=(TARGET_HOST, TARGET_INFO, outputRange[i], outputRange[i+1] - 1, output_dir, file_name, i + 1))
                # make_sock_conn(TARGET_HOST, TARGET_INFO, outputRange[i], outputRange[i+1] - 1, output_dir, file_name, i + 1)
            else:
                print("starting thread")
                thread = Thread(target=make_sock_conn, args=(TARGET_HOST, TARGET_INFO, outputRange[i], outputRange[i+1] - 1, output_dir, file_name, i + 1))
                # make_sock_conn(TARGET_HOST, TARGET_INFO, outputRange[i], outputRange[i+1] - 1, output_dir, file_name, i + 1)
            list_thread.append(thread)
        
        for thread in list_thread:
            thread.start()
            thread.join()

        # This function will merge all the chunks of data to be downloaded.
        make_single_file(output_dir, file_name, num_chunks)
    
    else:
        print("The reponse code received from the GET request is:", response_status_code)
        print("Ending the downloader...")
        exit()

# Main function
def main():
    parser = argparse.ArgumentParser(description='RUN TRACEROUTE MULTIPLE TIMES TOWARDS A GIVEN TARGET HOST.')
    
    parser.add_argument('-n', metavar='num_chunks',
                    help='Number of chunks', 
                    type=int, default=2)
    
    parser.add_argument('-o', metavar= 'output_dir', 
                    help='Directory name where the chunks will be stored', 
                    type=str, default = 'output_dir')
    
    parser.add_argument('-f', metavar= 'file_name',
                    help='Name of the chunks which will be downloaded', 
                    type=str, default = 'opFile')
    
    parser.add_argument('-u', metavar='object_url',
                    help='Object URL', 
                    type= str, default = 'http://cobweb.cs.uga.edu/~perdisci/CSCI6760-F20/test_files/generic_arch_steps375x250.png')
                        
    args = parser.parse_args()
    
    # calling out the trace function to start the processing
    recvMsg(args.n, args.o, args.f, args.u)

# calling the main function
if __name__=='__main__':
    main()