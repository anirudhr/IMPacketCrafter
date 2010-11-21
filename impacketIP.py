#!/usr/bin/python

from impacket import ImpactDecoder, ImpactPacket
import socket, sys

if len(sys.argv) < 3:
	print "Bad call to program."
	exit

src = sys.argv[1]
dst = sys.argv[2]

ip = ImpactPacket.IP()
ip.set_ip_src(src)
ip.set_ip_dst(dst)
ip.set_ip_v(4)
ip.set_ip_df(0)
ip.set_ip_ttl(240)
#ip

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

i = 0
while i < int(sys.argv[3]):
	s.sendto(ip.get_packet(), (dst, 0))
	i += 1
