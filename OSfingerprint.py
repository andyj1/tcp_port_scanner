#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import logging

# turn off scapy warnings

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

# import Scapy libs

from scapy.all import IP, TCP, sr1


def os_by_window_size(window_size, ttl):

    # return name for OS based on TCP window size and TTL

    return {
        '4128': lambda ttl: 'IOS 12.4 (Cisco Router)',
        '5720': lambda ttl: 'Google Linux',
        '5840': lambda ttl: 'Linux 2.4',
        '14600': lambda ttl: 'Linux 3.x',
        '8192': lambda ttl: 'Windows 7',
        '16384': lambda ttl: ('Windows Server 2003' if int(ttl)
                              > 64 else 'OpenBSD'),
        '65535': lambda ttl: ('Windows XP' if int(ttl)
                              > 64 else 'FreeBSD'),
    }.get(window_size, lambda ttl: 'Unknown')(ttl)


# make sure root privilege

if not os.geteuid() == 0:
    sys.exit('Must have root privileges')

# check for command line args

if len(sys.argv) < 2:
    sys.exit('Usage: %s [hostname|IP]' % sys.argv[0])

# get IP address or hostname

target_ip = sys.argv[1]

# check if localhost

if target_ip == "localhost" or target_ip == "127.0.0.1":
    sys.exit('OS: %s' % sys.platform)

# most commonly open ports

common_ports = [
    80,     # http
    22,     # ssh
    21,     # ftp
    135,    # dcom-smc
    139,    # netbios
    143,    # imap
    1723,   # pptp
    3389,   # rdp
    25,     # smtp
    23,     # telnet
    53,     # dns
    443,    # https
    110,    # pop3
    445,    # ms-ds
    8080,   # tomcat
    4567,   # filenail (commonly open port for backdoors)
]

# try each common port until one responds

for port in common_ports:

    # assemble IP packet with target IP

    ip = IP()
    ip.dst = target_ip

    # assemble TCP with dst port and SYN flag set

    tcp = TCP()
    tcp.dport = port
    tcp.flags = 'S'

    print('Trying port %d' % port)

    # send the packet and wait 2 seconds for an answer

    rcv_pkt = sr1(ip / tcp, timeout=2, verbose=0)

    # if answered no need to try more ports

    if rcv_pkt:
        break

# check to see if host responded, quit if otherwise

if not rcv_pkt:
    sys.exit('No response from host.')

# extract the TCP window size from the received packet

window_size = rcv_pkt.sprintf('%TCP.window%')

# extract the IP TTL from the received packet

ttl = rcv_pkt.sprintf('%IP.ttl%')

print("window size", window_size)

# get OS name
os_name = os_by_window_size(window_size, ttl)

# display the result

print('OS is probably', os_name)