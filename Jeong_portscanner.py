#!/usr/bin/env python

import socket
import subprocess
import sys
from datetime import datetime
import argparse
from threading import Thread
from queue import Queue

class Scan(Thread):
    def __init__(self):
        super(Scan, self).__init__()
        # Thread.__init__(self)
        
    # override Thread.run(self)
    def run(self):
        while (not queue.empty()):
            host, port = queue.get()
            if port == -1:
                self.open(host, port, 1)
            else:
                self.open(host, port, 0)
    
    def open(self, host, port, default):

        # Using the range function to specify ports (here it will scans all ports between 1 and 1024)
        # We also put in some error handling for catching errors


        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as s:
                if default == 1:
                    for port in range(1,1025):  
                        s.settimeout(0.5)
                        result = s.connect_ex((host, port)) # returns error code
                        if result == 0:                     # successful connection
                            print("Port {}: \t Open".format(port))
                else:
                    s.settimeout(0.5)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        print("Port {}: \t Open".format(port))
                    
                # get IP TTL and TCP Window Buffer Size
                service = ''.join((socket.getservbyport(port)).split())
                ttl_size = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)                
                # send_buf = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)                
                # rcv_buf = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                # print("host: %s, port:%d" % (host,port))
                # print("service: %10s \t ttl: %d \t send_buf: %d [bytes] \t rcv_buf: %d [bytes]" % (service,ttl,send_buf,rcv_buf))
                print("host: %s, port:%d, service: %s, TTL size: %d [bytes]" % (host,port,service,ttl_size))
                s.close()

        except KeyboardInterrupt:
            print("ERROR: Ctrl+C. Exiting...")
            sys.exit()

        except socket.gaierror:
            print("ERROR: host %s:%s not found." % (host,port))
            sys.exit()

        except socket.error:
            # print("ERROR: server connection to host %s:%s fail." % (host,port))
            sys.exit()


if __name__=='__main__':
    # Clear the screen
    subprocess.call('clear', shell=True)

    # Argument parse
    parser = argparse.ArgumentParser(description='Function: Scanning ports of the entered host.')
    parser.add_argument("host", type=str, help='Enter a host name(address) to scan...')
    parser.add_argument("-p", "--port", default='0:1024', help='Enter ports (inclusive if range). Default is 0:1024.')
    args = vars(parser.parse_args())
    target = args['host']
    char_colon = args['port'].find(':')
    if (char_colon is not -1):
        a,b = args['port'].split(':')
    else:
        a = args['port']
        b = a
    
    startport, endport = int(a), int(b)
    if (startport > endport):
        print("ERROR: Starting port is higher than the ending port")
        sys.exit()
    ports = list(range(startport, endport+1))
    # print('Scanning ports: %s' % ports)
    
    # make a queue of (host, port) pair
    queue = Queue()
    for port in ports:
        queue.put((target, port))
    
    # Check what time the scan started
    t1 = datetime.now()

    # make threads
    threadlist = []
    numThreads = int(endport - startport) + 1
    for i in range(numThreads):
        thread = Scan()
        thread.start()
        threadlist.append(thread)

    # join all threads
    try:
        for thread in threadlist:
            thread.join()
    except KeyboardInterrupt:
        print("ERROR: Ctrl+C. Exiting...")
        sys.exit()

    
    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1

    # Printing the information to screen
    print('Scanning Completed in: ', total)


