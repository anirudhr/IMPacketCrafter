#!/usr/bin/python
from scapy.all import *

ip=IP(src="10..1.2.3", dst="10.2.3.4")
SYN=TCP(sport=1500, dport=80, flags="S", seq=100)
SYNACK=sr1(ip/SYN)

my_ack = SYNACK.seq + 1
ACK=TCP(sport=1050, dport=80, flags="A", seq=101, ack=my_ack)
send(ip/ACK)

payload="stuff"
PUSH=TCP(sport=1050, dport=80, flags="PA", seq=11, ack=my_ack)
send(ip/PUSH/payload)
