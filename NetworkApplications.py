# Coursework of Viltene
# 2021 - 02 - 19
#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import math
import select
import socketserver


def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='bbc.co.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # Wait for the socket to receive a reply
        isPackageReceived = select.select([icmpSocket], [], [], timeout)
        # Give a timeout if the package is not received on time
        if isPackageReceived[0] == []:
            print('Time out')
            return 0, 0, 0
        # Once received, record time of receipt, get the header part from the response
        else:
            packet = icmpSocket.recv(1024)
            timeOfReceipt = time.time()
            sizeOfReceivedPacket = sys.getsizeof(packet)
            header2 = packet[20:28]
            
            # Unpack the packet header for useful information, including the ID
            typeOfPacket, code, checkSum2, iD, seqNum = struct.unpack_from('BBHHH', header2)
            # Check that the ID matches between the request and reply
            if(iD == ID):
                print("id matches ")
            else:
                print("id doesn't match\n")
            # Return time of receipt, size of the received packet and its checksum
            return timeOfReceipt * 1000, sizeOfReceivedPacket, checkSum2

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # Build ICMP header
        header = struct.pack('BBHHH', 8, 0, 0, ID, 0)
        # Checksum ICMP packet using given function
        cs = self.checksum(header)
        # Insert checksum into packet
        header = struct.pack('BBHHH', 8, 0, cs, ID, 0)
        # Send packet using socket
        sentOver = icmpSocket.sendto(header, (destinationAddress, 1))
        # Record time of sending
        timeOfSending = time.time()
        # Return time of sending and checksum of the sent package
        return timeOfSending * 1000, cs

    def doOnePing(self, destinationAddress, timeout):
        # Create an ICMP socket
        protocolName = socket.getprotobyname('icmp')
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocolName)
        # Call sendOnePing function
        id = int(time.time() % 100)
        t1, checksum1 = self.sendOnePing(s, destinationAddress, id)
        # Call receiveOnePing function
        t2, sizeOfPacket, checksum2 = self.receiveOnePing(s, destinationAddress, id, timeout)
        # Close ICMP socket
        s.close()
        # Return total network delay, both checksums and the size of received packet
        # return zeros if the packet didn't make it
        if t2 == 0 and sizeOfPacket == 0:
            return 0, checksum1, 0, 0
        else:
            return t2 - t1, checksum1, checksum2, sizeOfPacket

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # Prepare arguments used for determining additional data in the loop
        maximumDelay = 0
        numberOfPackages = 0
        totalTimeSpent = 0
        totalMassOfPacketsSent = 0
        totalMassOfPacketsReceived = 0
        minimumDelay = args.timeout
        # Look up hostname, resolving it to an IP address
        ip = socket.gethostbyname(args.hostname)
        lastTime = int(time.time()) + 1
        while True:
            try:
                if int(time.time()) == lastTime:
                    # Call doOnePing function, approximately every second
                    timeSpent, csSent, csReceived, sizeOfReceived = self.doOnePing(ip, args.timeout)
                    # Print out the returned delay (and other relevant details) using the printOneResult method
                    self.printOneResult(args.hostname, sizeOfReceived, timeSpent, 0)
                    if sizeOfReceived == 0 and timeSpent == 0:
                        lastTime = lastTime + args.timeout
                    else:
                        lastTime = lastTime + 1
                    #Counting for additional details
                    numberOfPackages = numberOfPackages + 1
                    totalTimeSpent = totalTimeSpent + timeSpent
                    totalMassOfPacketsSent = totalMassOfPacketsSent + csSent
                    totalMassOfPacketsReceived = totalMassOfPacketsReceived + csReceived
                    if timeSpent < minimumDelay:
                        minimumDelay = timeSpent
                    if maximumDelay < timeSpent:
                        maximumDelay = timeSpent
            # When ping is interrupted print a summary
            except KeyboardInterrupt:
                averageDelay = totalTimeSpent / numberOfPackages
                percentageOfLoss = (totalMassOfPacketsSent - totalMassOfPacketsReceived) / totalMassOfPacketsSent * 100
                break
        self.printAdditionalDetails(percentageOfLoss, minimumDelay, averageDelay, maximumDelay)
        

class Traceroute(NetworkApplication):

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # Build ICMP header
        header = struct.pack('BBHHH', 8, 0, 0, ID, 0)
        # Checksum ICMP packet using given function
        cs = self.checksum(header)
        # Insert checksum into packet
        header = struct.pack('BBHHH', 8, 0, cs, ID, 0)
        # Send packet using socket
        sentOver = icmpSocket.sendto(header, (destinationAddress, 1))
        # Record time of sending
        timeOfSending = time.time()
        # Return time of sending and checksum of the sent package
        return timeOfSending * 1000, cs

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # Wait for the socket to receive a reply
        isPackageReceived = select.select([icmpSocket], [], [], timeout)
        # Give a timeout if the package is not received on time
        if isPackageReceived[0] == []:
            print('Time out')
            return 0, 0, 0, 11, 0
        # Once received, record time of receipt, get the header part from the response
        else:
            packet, addr = icmpSocket.recvfrom(1024)
            timeOfReceipt = time.time()
            sizeOfReceivedPacket = sys.getsizeof(packet)
            header2 = packet[20:28]
            
            # Unpack the packet header for useful information, including the ID
            typeOfPacket, code, checkSum2, iD, seqNum = struct.unpack_from('BBHHH', header2)

            # Return time of receipt, size of the received packet, its checksum and type
            return timeOfReceipt * 1000, sizeOfReceivedPacket, checkSum2, typeOfPacket, addr

    def doOnePing(self, destinationAddress, timeout, ttlNum):
        # Create an ICMP socket
        protocolName = socket.getprotobyname('icmp')
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocolName)
        # Set TTL 
        s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttlNum)
        # Call sendOnePing function
        id = int(time.time() % 100)
        t1, checksum1 = self.sendOnePing(s, destinationAddress, id)
        # Call receiveOnePing function
        t2, sizeOfPacket, checksum2, packetType, address = self.receiveOnePing(s, destinationAddress, id, timeout)
        # Close ICMP socket
        s.close()
        # Return total network delay, both checksums and the size of received packet
        # return zeros if the packet didn't make it
        if t2 == 0 and sizeOfPacket == 0:
            return 0, checksum1, 0, 0, 11, 0
        else:
            return t2 - t1, checksum1, checksum2, sizeOfPacket, packetType, address
    
    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        # Create a socket
        ip = socket.gethostbyname(args.hostname)
        numberOfTTL = 1
        totalMassOfPacketsReceived = 0
        totalMassOfPacketsSent = 0
        while True:
            # Do a ping
            timeSpent, checksum1, checksum2, sizeOfReceivedPacket, packetType, addressOfHop = self.doOnePing(ip, args.timeout, numberOfTTL)
            totalMassOfPacketsSent = totalMassOfPacketsSent + checksum1
            totalMassOfPacketsReceived = totalMassOfPacketsReceived + checksum2
            if addressOfHop == 0:
                print('unable to reach host')
                break
            try:
                ipOfHost= addressOfHop[0]
                nameOfTheHop = socket.gethostbyaddr(ip)
                self.printOneResult(nameOfTheHop, sizeOfReceivedPacket, timeSpent, numberOfTTL)
            except socket.herror:
                self.printOneResult(ip, sizeOfReceivedPacket, timeSpent, numberOfTTL)
            # Increase TTL
            numberOfTTL = numberOfTTL + 1
           
            # If the received response is echo response - stop!
            if(packetType == 0):
                break
        percentageOfLoss = (totalMassOfPacketsSent - totalMassOfPacketsReceived) / totalMassOfPacketsSent * 100
        self.printAdditionalDetails(percentageOfLoss)

class WebServer(NetworkApplication):
    
    def handleRequest(self, tcpSocket):
        # Receive request message from the client on the connection socket
        data = tcpSocket.recv(1024)
        data = data.decode('utf-8')
        # Extract the path of the requested object from the message
        firstLineOfTheHeader = data.split('\r', 1)[0]
        path = firstLineOfTheHeader.split(' ', 2)[1]
        requestType = firstLineOfTheHeader.split(' ', 1)[0]
        path.strip()
        newFile = path.split('/', 2)[1].strip()
        # Read the corresponding file from disk if it's a valid request
        if requestType == 'GET' and path != '':
            try:
                givenFile = open(newFile, 'r')
                temporaryBuffer = givenFile.read() 
                # Store in temporary buffer
                print(temporaryBuffer)
                # Send the content of the file to the socket
                headerSuccess = 'HTTP/1.1 200 OK\r\n\r\n'
                package = headerSuccess + temporaryBuffer
                tcpSocket.send(package.encode('UTF-8', 'strict'))
                # Send the correct HTTP response error if file isn't found
            except FileNotFoundError:
                headerFail = 'HTTP/1.1 404 Not Found\r\n\r\n 404 Not Found'
                tcpSocket.send(headerFail.encode('UTF-8', 'strict'))
                print('Path extracted, file not found')
        else:
            headerFail = 'HTTP/1.1 404 Not Found\r\n\r\n 404 Not Found'
            tcpSocket.send(headerFail.encode('UTF-8', 'strict'))
            print('Just an error')
        # Close the connection socket
        tcpSocket.close()
    

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # Create a server socket and bind the server socket to server address and server port
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('localhost', args.port))
        # Continuously listen for connections to server socket
        server.listen(1)
        # When a connection is accepted, call handleRequest function, passing new connection socket
        while True:
            try:
                print('Waiting for a connection')
                clientSocket, clientAddress = server.accept()
                print('Connection accepted from', clientAddress)
                # Handle request 
                self.handleRequest(clientSocket)
            # If there is a Keyboard Interrupt safely close the server socket
            except KeyboardInterrupt:
                break
        print('Server is closing')
        server.close()

class Proxy(NetworkApplication):

    def forwardRequest (self, tcpSocket):
        # Receive a request message from the client on the connection socket
        data = tcpSocket.recv(1024)
        # Save a data copy for forwarding
        datacopy = data
        data = data.decode('utf-8')
        # Extract the first line of the header from the message 
        firstLineOfTheHeader = data.split('\r', 1)[0]
        # Create a server client socket
        forwardingSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # If the header is valid extract the destination
        if firstLineOfTheHeader != '':
            path = firstLineOfTheHeader.split(' ', 2)[1]
            requestType = firstLineOfTheHeader.split(' ', 1)[0]
            path.strip()
            address = path.split(' ', 1)[0]
            if address[-1] == '/':
                address = address[:-1].strip()
            address = address.split('//', 1)[1]
            # Establish a TCP connection with the requested server
            print('connection established with ', address)
            try:
                forwardingSocket.connect((address, 80))
                # Forward the request
                forwardingSocket.sendall(datacopy)
                # Wait for the socket to get a response
                isPackageReceived = select.select([forwardingSocket], [], [], 5)
                # Give a timeout if the package is not received on time
                if isPackageReceived[0] == []:
                    print('Time out')
                    headerFail = 'HTTP/1.1 404 Not Found\r\n\r\n 404 Not Found'
                    tcpSocket.send(headerFail.encode('UTF-8', 'strict'))
                else:
                    response = forwardingSocket.recv(4096)
                    # Forward the response
                    tcpSocket.send(response)
            except socket.gaierror:
                headerFail = 'HTTP/1.1 400 Bad Request\r\n\r\n 404 Not Found'
                tcpSocket.send(headerFail.encode('UTF-8', 'strict'))

        # If the first line of the header was not valid send an error message
        else:
            headerFail = 'HTTP/1.1 404 Not Found\r\n\r\n 404 Not Found'
            tcpSocket.send(headerFail.encode('UTF-8', 'strict'))
            print('Just an error')
        # Close the server client and client sockets
        forwardingSocket.close()
        tcpSocket.close()

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        # Create a server socket and bind the server socket to server address and server port
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('localhost', args.port))

        # Continuously listen for connections to server socket
        server.listen(1)

        # When a connection is accepted, call handleRequest function, passing new connection socket
        while True:
            try:
                print('Waiting for a connection')
                clientSocket, clientAddress = server.accept()
                print('Connection received from', clientAddress)
                #  Forward the Request
                self.forwardRequest(clientSocket)
            #  In case of a Keyboard interrupt safely close the server socket
            except KeyboardInterrupt:
                break
        server.close()


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
