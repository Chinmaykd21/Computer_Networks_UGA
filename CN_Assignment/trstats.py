#!/usr/bin/env python
import argparse
import subprocess
from statistics import mean, median
import json
import os
import plotly.graph_objects as go
import time

# This funtion will be doing the traceroute function in python
def trace(no_runs, delay, max_hops, opFile, dest_ip_addr, testdir):
    output = []
    
    # if reading from the file is executed then we will use this variable, otherwise it will be just empty
    fileOuputList = []

    # if testDir is given then this loop will run
    if testdir != "no":
        # Checking if the directory path mention by the user is correct or not, if it is then next loop will execute. Otherwise program will return immediately
        if os.path.exists(os.path.abspath(testdir)):
            for filename in os.listdir(testdir):
                with open(os.path.join(testdir, filename), "r") as f:
                    fileOuputList.append(f.read())
    
            for i in range(len(fileOuputList)):
                if i == 0:
                    # For the first run of traceroute, since there is no output, we will send output = []
                    output = fileReOutput(str(fileOuputList[i]), output)
                else:
                    # if the traceroute output run is not the first then we will send the old output as it is, which is updated after the first run
                    output = fileReOutput(str(fileOuputList[i]), output)
        else:
            print("Path entered by user does not exists!")
            print("This is the directory path you have entered you entered",testdir)
            return

    # if testDir is not given then this part will run
    else:
        for i in range(no_runs):
            traceString = 'traceroute ' + '-m ' + str(max_hops) + ' ' + dest_ip_addr
            try:
                traceOutput = subprocess.check_output(traceString, shell=True).decode('UTF-8')
            except:
                print("Something is wrong please check the arguments once again!")
                print("This is the command you entered", traceString)
            if i == 0:
                # Command which will run traceroute with the specifications given by the user
                output = fileReOutput(str(traceOutput), output)   
            else:
                output = fileReOutput(str(traceOutput), output)   

            #After each traceroute run wait for number of seconds mentioned by the user
            time.sleep(delay)
    
    # To remove the duplicates from the final output
    tmpOutput = [i for n, i in enumerate(output) if i not in output[n + 1:]] 

    # this function will plot the box plot and store it in a pdf file
    plotBoxPDF(tmpOutput, opFile)

    # To remove tmpMed key from the final output
    for everyDict in tmpOutput:
        everyDict.pop("tmpMed")

    # This line will remove the dictionaries whose every keys contain value 0 or [].
    finalOutput = [i for i in tmpOutput if not (i['avg'] == 0)]

    # Dumping the output to JSON
    dumpOutput(finalOutput, opFile)

def dumpOutput(finalOutput, opFile):
    pathToDir, opFileName = os.path.split(opFile)
    # First check if the path entered by the user is correct or not.
    if os.path.exists(os.path.abspath(pathToDir)):
        pathToOutputDir = os.path.join(os.path.abspath(pathToDir), opFileName)
        # Store the output file name and use it in the with open loop
        fileName = str(pathToOutputDir) + ".json"

    # dump output in the JSON file
        with open(fileName, "w") as outfile:
            print("Program excuted successfully and file is stored at:", fileName)
            json.dump(finalOutput, outfile)
            outfile.close()
    else:
        print("The path enetered is not valid path:", pathToDir)
        print("Creating the output file at:", os.getcwd())
        fileName = opFileName + ".json"

        # dump output in the JSON file
        with open(fileName, "w") as outfile:
            print("Program excuted successfully and file is stored at:", fileName)
            json.dump(finalOutput, outfile)
            outfile.close()

# This function will plot the box plot and store it in a PDF file
def plotBoxPDF(listOfDictonaries, opFile):
    pathToDir, opFileName = os.path.split(opFile)
    # First check if the path entered by the user is correct or not.
    if os.path.exists(os.path.abspath(pathToDir)):
        pathToOutputDir = os.path.join(os.path.abspath(pathToDir), opFileName)
        # Store the output file name and use it in the with open loop
        fileName = str(pathToOutputDir) + ".pdf"

        fig = go.Figure()
        for i in listOfDictonaries:
            y_axis = i['tmpMed']
            hopName = "Hop " + str(i['hop'])
            check_flag = i['avg']
            if check_flag != 0:
                fig.add_trace(go.Box(y = y_axis, name = hopName))
        fig.write_image(fileName)
        print("Program excuted successfully and file is stored at:", fileName)
    
    else:
        print("The path entered is not a valid path:", pathToDir)
        print("Creating the output file at:", os.getcwd())
        fileName = opFileName + ".pdf"
        fig = go.Figure()
        for i in listOfDictonaries:
            y_axis = i['tmpMed']
            hopName = "Hop " + str(i['hop'])
            check_flag = i['avg']
            if check_flag != 0:
                fig.add_trace(go.Box(y = y_axis, name = hopName))
        fig.write_image(fileName)

# This function will rearrange the output in such a way that only the hops related information is used for the further processing part.
def fileReOutput(traceOutput, ogOutput):
    stringTrace = traceOutput.split("\n")
    stringTrace = [removeItem for removeItem in stringTrace if removeItem not in (stringTrace[0])]
    output = startProcessing(stringTrace, ogOutput)
    return output

# using each line of traceroute output, this function will call the function hostIpTime
def startProcessing(listToProcess, ogOutput):
    output = []
    
    for stringElement in listToProcess:
        if stringElement[4:9].strip() != '* * *':
            hostIpTime = getHostIpTime(stringElement)
            hostIp = hostIpTime[0]
            time = hostIpTime[1]
            hops = stringElement[0:2]
        else:
            hops = stringElement[0:2]
            hostIp = []
            time = ['0.000', '0.000', '0.000']
        
        output = storeInfo(hops,hostIp,time, ogOutput)
    
    return output

# This function will return [(host name, its corrosponding IP address), time for each packet for its subsequent hop]
def getHostIpTime(singlehop):
    listOfEverything = singlehop.split(" ")
    listOfIp = []
    hostNames = []
    times = []
    hostIp = []

    # This loop will get IP address like this --> (IP)
    for i in listOfEverything:
        if len(i) > 1 and i != "":
            if (i[0] == '(' and i[-1] == ")"):
                listOfIp.append(i)
                listOfEverything.remove(i)

    # This loop will give me timings
    for i in range(len(listOfEverything)):
        if listOfEverything[i] == "ms":
            times.append(listOfEverything[i-1])

    # to remove spaces and ms from the list
    for i in listOfEverything:
        if i == '' or i == "ms":
            listOfEverything.remove(i)

    # to remove hops and spaces from the list
    for i in listOfEverything:
        if i == "" or len(i) <= 2:
            listOfEverything.remove(i)
    
    for i in listOfEverything:
        if i == "*":
            listOfEverything.remove(i)

    # to remove times from the list to get the host names
    for i in listOfEverything:
        for j in times:
            if i == j:
                listOfEverything.remove(i) 

    # to remove times from the list to get the host names
    for i in listOfEverything:
        for j in times:
            if i == j:
                listOfEverything.remove(i) 

    # to append the list of host names and ipList to make a tuple
    for i, j in zip(listOfEverything, listOfIp):
        hostIp.append((i,j))

    return [hostIp, times]

# This function will return the output
def storeInfo(hops,hostIp, ogTime, ogOutput):
    finalDict = {}
    index = 0
    time = []
    # converting str ogTime to float time
    for i in ogTime:
        time.append(float(i))
    # If this is first hop information then store it in the following way
    if len(ogOutput) == 0:
        finalDict['tmpMed'] = time
        finalDict['avg'] = getAvg(finalDict.get('tmpMed'))
        finalDict['hop'] = int(hops)
        finalDict['hosts'] = hostIp
        finalDict['max'] = getMax(time, finalDict.get('max', 0))
        finalDict['min'] = getMin(time, finalDict.get('min', None))
        finalDict['med'] = getMed(finalDict.get('tmpMed'))
    else:
        # Iterate through every list to find if the key == hops actually exists in the dictionary, if it does then add the new information to the dictonary and calculate the new data and update the dictonary
        for eachDict in ogOutput:
            if eachDict.get('hop') == int(hops):
                index = int(hops)
                break

        # This is to copy the data of the matched hops into the finalDict and make the chanegs into that particular Dictonary
        if index > 0:
            finalDict = ogOutput[index-1]
            finalDict['tmpMed'] = finalDict.get('tmpMed') + time
            finalDict['avg'] = getAvg(finalDict.get('tmpMed'))
            finalDict['hosts'] = removeDuplicates(hostIp,finalDict.get('hosts'))
            finalDict['max'] = getMax(time, finalDict.get('max'))
            finalDict['min'] = getMin(time, finalDict.get('min'))
            finalDict['med'] = getMed(finalDict.get('tmpMed'))
        # otherwise it means that this particular hop has come for the first time so append its information in ogOuput
        else:
            finalDict['tmpMed'] = time
            finalDict['avg'] = getAvg(finalDict.get('tmpMed'))
            finalDict['hop'] = int(hops)
            finalDict['hosts'] = hostIp
            finalDict['max'] = getMax(time, finalDict.get('max', 0))
            finalDict['min'] = getMin(time, finalDict.get('min', None))
            finalDict['med'] = getMed(finalDict.get('tmpMed'))

    ogOutput.append(finalDict)
    return ogOutput

# This is to remove any duplicate set of host if the hop number matched in the storeInfo function.
def removeDuplicates(hostIp, ogHostIp):
    # merge the two lists
    newHostIp = hostIp + ogHostIp
    newIpHost = list(set([i for i in newHostIp]))
    return newIpHost

# To get average of the packet times in each hop
def getAvg(newTimes):
    newAvg = round(mean(newTimes),3)
    return newAvg

# to get maximum time of the packet times in each hop
def getMax(newTimes, oldMax):
    newMax = max(newTimes)
    if newMax > oldMax:
        return round(newMax,3)
    return round(oldMax,3)

# to get minimum time of the packet times in each hop
def getMin(newTimes, oldMin):
    newMin = min(newTimes)
    if oldMin is None:
        return round(newMin,3)
    elif oldMin > newMin:
        return round(newMin,3)
    return round(oldMin,3)

# to get median time of the packet times in each hop
def getMed(listTimes):
    result = round(median(listTimes),3)
    return result

# Main function
def main():
    parser = argparse.ArgumentParser(description='RUN TRACEROUTE MULTIPLE TIMES TOWARDS A GIVEN TARGET HOST.')
    
    parser.add_argument('-n', metavar='NUM_RUNS',
                    help='Number of times the traceroute will run', 
                    type=int, default=1)
    
    parser.add_argument('-d', metavar= 'RUN_DELAY', 
                    help='Number of seconds to wait between two consecutive runs', 
                    type=float, default = 0.001)
    
    parser.add_argument('-m', metavar= 'MAX_HOPS',
                    help='Maximum number of hops in one single traceroute run', 
                    type=int, default = 30)
    
    parser.add_argument('-o', metavar='OUTPUT',
                    help='path and name of output JSON file', 
                    type= str,required=True)
                    
    parser.add_argument('-t', metavar='TARGET',
                    help='A target domain name or IP address',
                    type=str, default='www.yahoo.com')
                    
    parser.add_argument('-test',metavar='TEST_DIR',
                    help='Directory containing num_runs text files, each of which contains\
                        the output of a traceroute run.\
                        If present, this will override all other options and traceroute will\
                        not be invoked. Stats will be computed over the traceroute output\
                        stored in the text files only.', type=str, default='no')
                        
    args = parser.parse_args()
    
    # calling out the trace function to start the processing
    trace(args.n, args.d, args.m, args.o, args.t, args.test)

# calling the main function
if __name__=='__main__':
    main()