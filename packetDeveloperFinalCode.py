#!/usr/bin/python

import httplib
from ftplib import FTP
from impacket import ImpactDecoder, ImpactPacket
import socket
import DNS

def inputIPv4():
	n = int(raw_input("Enter the number of packets: "))
	pSrc = raw_input("Input the source IP address ")
	pDst = raw_input("Input the destination IP address ")
	pID = int(raw_input("Input the packet ID "))
	pTTL = int(raw_input("Input the time to live "))
	pFlags = raw_input("Input the flags (R / DF / MF) ")
	sendIPv4(n, pID, pTTL, pSrc, pDst, pFlags)

def sendIPv4(n, pID, pTTL, pSrc, pDst, pFlags):
	try:
		ip = ImpactPacket.IP() #Creating IP packet
		ip.set_ip_src(pSrc)
		ip.set_ip_dst(pDst)
		ip.set_ip_v(4)
		ip.set_ip_df(0)
		ip.set_ip_ttl(pTTL)
		ip.set_ip_id(pID)

		if pFlags == "R": #'Reserved' flag
			ip.set_ip_rf(1)
		elif pFlags == "DF": #'Do not Fragment' flag
			ip.set_ip_df(1)
		elif pFlags == "MF": #'More Fragments' flag
			ip.set_ip_mf(1)

		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #Create a raw socket. ICMP is randomly chosen, though IP packet has no payload
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		for i in range(n):
			s.sendto(ip.get_packet(), (pDst, 0))
			
		print "Packets successfully sent."
		return 0
		
	except:
		print "IPv4 sending failed."
		return 1

def inputTCP():
	n = int(raw_input("Enter the number of packets: "))
	pSrcAddr = raw_input("Input the source IP address ")
	pDstAddr = raw_input("Input the destination IP address ")
	pSrcPort = int(raw_input("Input the source port " ))
	pDstPort = int(raw_input("Input the destination port "))
	pID = int(raw_input("Input the packet ID "))
	pSeq = int(raw_input("Input packet sequence number "))
	pFlags = raw_input("Input the flags (C = CWR / E = ECE / U = URG / A = ACK / P = PSH / R = RST / S = SYN / F = FIN) ")
	sendTCP(n, pFlags, pSeq, pSrcAddr, pSrcPort, pDstAddr, pDstPort)

def sendTCP(n, pFlags, pSeq, pSrcAddr, pSrcPort, pDstAddr, pDstPort):
	try:
		tcp = ImpactPacket.TCP() #Create a TCP packet
		chkACK = 0
		for i in pFlags:
			if i == "C":
				tcp.set_CWR() #'Congestion Window Reduce'
			if i == "E":
				tcp.set_ECE() #'Explicit Congestion Notification echo indicated'
			if i == "U":
				tcp.set_URG() #'Urgent'
			if i == "A":
				tcp.set_ACK() #'Acknowledgement'
				chkACK = 1
			if i == "P":
				tcp.set_PSH() #'Push'
			if i == "R":
				tcp.set_RST() #'Reset'
			if i == "S":
				tcp.set_SYN() #'Synchronize'
			if i == "F":
				tcp.set_FIN() #'Finished'

		tcp.set_th_sport(pSrcPort)
		tcp.set_th_dport(pDstPort)

		if chkACK == 1:
			tcp.set_th_ack(pSeq + 1)
		else:
			tcp.set_th_seq(pSeq)        

		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		for i in range(n):
			s.sendto(tcp.get_packet(), (pDstAddr, 0))
			
		print "Packets successfully sent."
		return 0
	except:
		print "TCP sending failed."
		return 1

def inputUDP():
	n = int(raw_input("Enter the number of packets: "))
	pSrcAddr = raw_input("Input the source IP address ")
	pDstAddr = raw_input("Input the destination IP address ")
	pSrcPort = int(raw_input("Input the source port " ))
	pDstPort = int(raw_input("Input the destination port "))
	sendUDP(n, pSrcAddr, pSrcPort, pDstAddr, pDstPort)

def sendUDP(n, pSrcAddr, pSrcPort, pDstAddr, pDstPort):
	try:
		udp = ImpactPacket.UDP() #Create a UDP packet

		udp.set_uh_sport(pSrcPort)
		udp.set_uh_dport(pDstPort)

		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		for i in range(n):
			s.sendto(udp.get_packet(), (pDstAddr, 0))

		print "Packets successfully sent."
		return 0

	except:
		print "UDP sending failed."
		return 1

def inputIGMP():
	n = int(raw_input("Enter the number of packets: "))
	pSrcAddr = raw_input("Input the source IP address ")
	pDstAddr = raw_input("Input the destination IP address ")
	sendIGMP(n, pSrcAddr, pDstAddr)

def sendIGMP(n, pSrcAddr, pDstAddr):
	try:
		ip = ImpactPacket.IP() #Create the IP packet upon which the IGMP packet will form a payload
		ip.set_ip_src(pSrcAddr)
		ip.set_ip_dst(pDstAddr)

		igmp = ImpactPacket.IGMP() #Create an IGMP packet
		igmp.set_igmp_type(1)
		igmp.set_igmp_code(0)
		igmp.set_igmp_group(0)

		ip.contains(igmp) #Place the IGMP payload packet into the IP packet

		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		for i in range(n):
			s.sendto(ip.get_packet(), (pDstAddr, 0))

		print "Packets successfully sent."
		return 0

	except:
		print "IGMP sending failed."
		return 1

def inputHTTP():
	n = int(raw_input("Enter the number of packets: "))
	pDst = raw_input("Enter the destination host: ")
	pPort= raw_input("Enter destination port: ")
	pTimeOut = int(raw_input("Enter the timeout: "))
	pMet = raw_input("""Enter the method:
Request:
GET
HEAD
POST
PUT
DELETE
TRACE
CONNECT
""")
	pUri = raw_input("Enter the destination URI: ")
	sendHTTP(n, pDst, pPort, pTimeOut, pMet, pUri)
	
def sendHTTP(n, pDst, pPort, pTimeOut, pMet, pUri):
	try:
		http = httplib.HTTPConnection(pDst, pPort, timeout=pTimeOut) #Initialise HTTP connection
		for i in range(n):
			http.request(pMet, pUri)
		http.close()

		print "Packets successfully sent."
		return 0

	except:
		print "HTTP sending failed."
		return 1
	
def inputFTP():
	n = int(raw_input("Enter the number of packets: "))
	pDst = raw_input("Enter the destination host: ")
	pPort= raw_input("Enter destination port: ")
	pTimeOut = int(raw_input("Enter the timeout: "))
	pCmd = raw_input("""Enter command to be sent: 
?  	 			to request help or information about the FTP commands
ascii 			to set the mode of file transfer to ASCII
binary 			to set the mode of file transfer to binary
bye 			to exit the FTP environment
cd 				to change directory on the remote machine
close 			to terminate a connection with another computer
close brubeck 	closes the current FTP connection with brubeck, but still leaves you within the FTP environment.
delete 			to delete (remove) a file in the current remote directory (same as rm in UNIX)
get 			to copy one file from the remote machine to the local machine
help 			to request a list of all available FTP commands
lcd 			to change directory on your local machine (same as UNIX cd)
ls 				to list the names of the files in the current remote directory
mkdir 			to make a new directory within the current remote directory
mget 			to copy multiple files from the remote machine to the local machine;
mput 			to copy multiple files from the local machine to the remote machine;
open 			to open a connection with another computer
open brubeck 	opens a new FTP connection with brubeck;
put 			to copy one file from the local machine to the remote machine
pwd 			to find out the pathname of the current directory on the remote machine
quit 			to exit the FTP environment (same as bye)
rmdir 			to to remove (delete) a directory in the current remote directory 
""")
	sendFTP(n, pDst, pPort, pTimeOut, pCmd)
	
def sendFTP(n, pDst, pPort, pTimeOut, pCmd):
	try:
		ftp = FTP(pDst, pPort, timeout=pTimeOut) #Initialise FTP connection	
		for i in range(n):
			ftp.sendcmd(pCmd)
		ftp.close()

		print "Packets successfully sent."
		return 0

	except:
		print "FTP sending failed."
		return 1
	

def inputDNS():
	n = int(raw_input("Enter the number of packets: "))
	ch = int(raw_input("""Enter DNS option:
0. Perform an address request (A)
1. Perform a request for all records (ANY)
2. Perform a mail exchange request (MX)
3. Perform a start-of-authority request (SOA)
4. Perform a request (SRV)
"""))
#5. Reverse look up an IP address
#"""))
	if ch in range(0, 2):
		hName = raw_input("Enter the name of the host to resolve: ")
		dName = ""
		ip = ""
	elif ch in range(3, 4):
		hName = ""
		dName = raw_input("Enter the domain name: ")
		ip = ""
#	elif ch == 5:
#		hName = ""
#		dName = ""
#		ip = raw_input("Enter the IP address: ")
	#
	pTimeout = int(raw_input("Enter the timeout: "))
	sendDNS(n, ch, hName, dName, ip, pTimeout)


def sendDNS(n, ch, hName, dName, ip, pTimeout):
	try:
		if ch == 0:
			DNS.ParseResolvConf() #Parse /etc/resolv.conf
			r = DNS.DnsRequest(name = hName, qtype = 'A', timeout = pTimeout)
			for i in range(n):
				a = r.req()
		elif ch == 1:
			DNS.ParseResolvConf()
			r = DNS.DnsRequest(name = hName, qtype = 'ANY', timeout = pTimeout)
			for i in range(n):
				a = r.req()
		elif ch == 2:
			DNS.ParseResolvConf()
			r = DNS.DnsRequest(qtype = 'mx', timeout = pTimeout)
			for i in range(n):
				a = r.req()
		elif ch == 3:
			r = DNS.Request(dName, qtype = 'SOA', timeout = pTimeout)
			for i in range(n):
				a = r.req()
		elif ch == 4:
			r = DNS.Request(qtype = 'srv', timeout = pTimeout).req(dName)
			for i in range(n):
				a = r.req()
	#	elif ch == 5:
	#		for i in range(n):
	#			name = dns.reversename.from_address(ip)

		print "Packets successfully sent."
		return 0

	except:
		print "DNS sending failed."
		return 1

def inputARP():
	n = int(raw_input("Enter the number of packets: "))
	pSrcAddr = raw_input("Enter the source IP address ")
	pDstAddr = raw_input("Enter the destination IP address ")
	#    pSrcHA = raw_input("Input the source hardware address " )
	#    pDstHA = raw_input("Input the destination hardware address ")
	pOpCode = int(raw_input("""Enter the opcode:
0	Reserved
1	Request
2	Reply
3	Request Reverse
4	Reply Reverse
5	DRARP Request
6	DRARP Reply
7	DRARP Error
8	InARP Request
9	InARP Reply
10	ARP NAK
11	MARS Request
12	MARS Multi 
13	MARS MServ	 
14	MARS Join	 
15	MARS Leave
16	MARS NAK
17	MARS Unserv
18	MARS SJoin
19	MARS SLeave
20	MARS Grouplist Request
21	MARS Grouplist Reply
22	MARS Redirect Map
23	MAPOS UNARP
24	OP_EXP1
25	OP_EXP2
"""))
	sendARP(n, pDstAddr, pSrcAddr, pOpCode)

def sendARP(n, pDstAddr, pSrcAddr, pOpCode):
	try:
		eth = ImpactPacket.Ethernet() #Create an ethernet packet
		arp = ImpactPacket.ARP()
		eth.set_ether_shost((0x0, 0x1c, 0xbf, 0xbe, 0x87, 0x98))
		eth.set_ether_dhost((0x0, 0x1c, 0xbf, 0xbe, 0x87, 0x98))

		arp.set_ar_op(pOpCode)
		arp.set_ar_hrd(1)
		arp.set_ar_spa((pSrcAddr))
		arp.set_ar_tpa((pDstAddr))
		#	arp.set_ar_sha((pDstHA))
		#	arp.set_ar_tha((pSrcHA))
		eth.contains(arp)
		s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
		s.bind(("eth0",0x0806))
		#	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		for i in range(n):
			s.sendto(eth.get_packet(), ("00:1E:68:14:EE:46", 0)) #Hard-coded MAC address to try; failed

		print "Packets successfully sent."
		return 0

	except:
		print "ARP sending failed."
		return 1


def inputICMP():
	n = int(raw_input("Enter the number of packets: "))
	typeICMP = int(raw_input("""Enter choice for type of ICMP packet:
0  Echo reply
3  Destination unreachable
4  Source Quench
5  Redirect
6  Alternate host address
8  Echo
9  Router advertisement
10 Router selection
11 Time exceeded
12 Parameter problem
13 Timestamp
14 Timestamp reply
15 Information request
16 Information reply
17 Address mask request
18 Address mask reply
"""))
	if typeICMP == 3:
		codeICMP = int(raw_input("""Enter choice for code of ICMP packet:
0  Net unreachable
1  Host unreachable
2  Protocol unreachable
3  Port unreachable
4  Frag required and DF set
5  Source route failed
6  Destination network unknown
7  Destination host unknown
8  Source host isolated
9  Network administratively prohibited
10 Host administratively prohibited
11 Network unreachable for ToS
12 Host unreachable for ToS
13 Filter prohibited
14 Host precedence
15 Precedence cutoff
"""))

	elif typeICMP == 5:
		codeICMP = int(raw_input("""Enter choice for code of ICMP packet:
0 Redirect datagram for the network
1 Redirect datagram for the host
2 Redirect datagram for the ToS and network
3 Redirect datagram for the ToS and host
"""))

	elif typeICMP == 11:
		codeICMP = int(raw_input("""Enter choice for code of ICMP packet:
0 TTL exceeded
1 Fragment reassembly time exceeded
"""))

	elif typeICMP == 12:
		codeICMP = int(raw_input("""Enter choice for code of ICMP packet:
0 Pointer problem
1 Missing a required operand
2 Bad length
"""))

	elif typeICMP in [0, 1, 2, 4, 6, 7, 8, 9, 10, 13, 14, 15]:
		codeICMP = -1

	else:
		print "ERROR!!!"
		return 1

	pSrcAddr = raw_input("Enter source address: ")
	pDstAddr = raw_input("Enter destination address: ")
	pPayload = raw_input("Enter ICMP payload: ")
	sendICMP(n, typeICMP, codeICMP, pSrcAddr, pDstAddr, pPayload)
	return 0

def sendICMP(n, typeICMP, codeICMP, pSrcAddr, pDstAddr, pPayload):
	try:
		ip = ImpactPacket.IP() #Create the IP packet upon which the ICMP packet will form a payload
		ip.set_ip_src(pSrcAddr)
		ip.set_ip_dst(pDstAddr)
		ip.set_ip_v(4)

		icmp = ImpactPacket.ICMP()

		t0 = typeICMP
		t1 = codeICMP

		if t0 == 0:
			icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)

		elif t0 == 3:
			icmp.set_icmp_type(icmp.ICMP_UNREACH)

			if t1 == 0:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_NET)

			elif t1 == 1:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_HOST)

			elif t1 == 2:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_PROTOCOL)

			elif t1 == 3:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_PORT)

			elif t1 == 4:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_NEEDFRAG)

			elif t1 == 5:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_SRCFAIL)

			elif t1 == 6:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_NET_UNKNOWN)

			elif t1 == 7:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_HOST_UNKNOWN)

			elif t1 == 8:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_ISOLATED)

			elif t1 == 9:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_NET_PROHIB)

			elif t1 == 10:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_HOST_PROHIB)

			elif t1 == 11:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_TOSNET)

			elif t1 == 12:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_TOSHOST)

			elif t1 == 13:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_FILTERPROHIB)

			elif t1 == 14:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_HOST_PRECEDENCE)

			elif t1 == 15:
				icmp.set_icmp_code(icmp.ICMP_UNREACH_PRECEDENCE_CUTOFF)

			else:
				print "ERROR!!!"
				return 1

		elif t0 == 4:
			icmp.set_icmp_type(icmp.ICMP_SOURCEQUENCH)

		elif t0 == 5:
			icmp.set_icmp_type(icmp.ICMP_REDIRECT)

			if t1 == 0:
				icmp.set_icmp_code(icmp.ICMP_REDIRECT_NET)

			elif t1 == 1:
				icmp.set_icmp_code(icmp.ICMP_REDIRECT_HOST)

			elif t1 == 2:
				icmp.set_icmp_code(icmp.ICMP_REDIRECT_TOSNET)

			elif t1 == 3:
				icmp.set_icmp_code(icmp.ICMP_REDIRECT_TOSHOST)

			else:
				print "ERROR!!!"
				return 1

		elif t0 == 6:
			icmp.set_icmp_type(icmp.ICMP_ALTHOSTADDR)

		elif t0 == 8:
			icmp.set_icmp_type(icmp.ICMP_ECHO)

		elif t0 == 9:
			icmp.set_icmp_type(icmp.ICMP_ROUTERADVERT)

		elif t0 == 10:
			icmp.set_icmp_type(icmp.ICMP_ROUTERSOLICIT)

		elif t0 == 11:
			icmp.set_icmp_type(icmp.ICMP_TIMXCEED)

			if t1 == 0:
				icmp.set_icmp_code(icmp.ICMP_TIMXCEED_INTRANS)

			elif t1 == 1:
				icmp.set_icmp_code(icmp.ICMP_TIMXCEED_REASS)

			else:
				print "ERROR!!!"
				return 1

		elif t0 == 12:
			icmp.set_icmp_type(icmp.ICMP_PARAMPROB)

			if t1 == 0:
				icmp.set_icmp_code(icmp.ICMP_PARAMPROB_ERRATPTR)

			elif t1 == 1:
				icmp.set_icmp_code(icmp.ICMP_PARAMPROB_OPTABSENT)

			elif t1 == 2:
				icmp.set_icmp_code(icmp.ICMP_LENGTH)

			else:
				print "ERROR!!!"
				return 1

		elif t0 == 13:
			icmp.set_icmp_type(icmp.ICMP_TSTAMP)

		elif t0 == 14:
			icmp.set_icmp_type(icmp.ICMP_TSTAMPREPLY)

		elif t0 == 15:
			icmp.set_icmp_type(icmp.ICMP_IREQ)

		elif t0 == 16:
			icmp.set_icmp_type(icmp.ICMP_IREQREPLY)

		elif t0 == 17:
			icmp.set_icmp_type(icmp.ICMP_MASKREQ)

		elif t0 == 18:
			icmp.set_icmp_type(icmp.ICMP_MASKREPLY)

		else:
			print "ERROR!!!"
			return 1

		icmp.contains(ImpactPacket.Data(str(pPayload))) #Place the ICMP payload packet into the IP packet

		ip.contains(icmp)

		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		for i in range(n):
			s.sendto(ip.get_packet(), (pDstAddr, 0))

		print "Packets successfully sent."
		return 0
		
	except:
		print "ICMP sending failed."
		return 1
#######################################################################################
ch = 1
while ch:
	print "\n\n**********PACKET DEVELOPER**********\n\n"
	proto = 0
	while proto not in range(1,9):
		print "Enter the protocol (0 to quit):\n"
		print "1. IPv4 \n2. TCP \n3. HTTP \n4. FTP \n5. DNS \n6. UDP \n7. ICMP \n8. IGMP \n9. ARP \n"
		proto  = int(raw_input())

		if proto == 0:
			print "Thank you for using Packet Developer. Packet Developer has terminated."
			exit()
		if proto == 1:
			inputIPv4()
		elif proto == 2:
			inputTCP()
		elif proto == 3:
			inputHTTP()
		elif proto == 4:
			inputFTP()
		elif proto == 5:
			inputDNS()
		elif proto == 6:
			inputUDP()
		elif proto == 7:
			inputICMP()
		elif proto == 8:
			inputIGMP()
		elif proto == 9:
			inputARP()
		else:
			print "Invalid input. Please try again."
	
	ch = int(raw_input("Continue? (1 / 0) "))
	
print "Thank you for using Packet Developer. Packet Developer has terminated."
exit()
