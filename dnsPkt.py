#!/usr/bin/python

import DNS #python-dns AKA pyDNS
#import dns.reversename

def inputDNS():
	n = int(raw_input("How many packets? "))
	ch = int(raw_input("""Choose DNS option:
0. Perform an address request (A)
1. Perform a request for all records (ANY)
2. Perform a mail exchange request (MX)
3. Perform a start-of-authority request (SOA)
4. Perform a request (SRV)
"""))
#5. Reverse look up an IP address
#"""))
	if ch in range(0, 2):
		hName = raw_input("Enter name of host to resolve: ")
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
	if ch == 0:
		DNS.ParseResolvConf()
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
#

inputDNS()
