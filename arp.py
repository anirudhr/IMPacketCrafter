def inputARP():
    pSrcAddr = raw_input("Input the source IP address ")
    pDstAddr = raw_input("Input the destination IP address ")
    pSrcHA = raw_input("Input the source hardware address " )
    pDstHA = raw_input("Input the destination hardware address ")
    pOpCode = int("Input the opcode ")
    sendARP(n, pDstAddr, pDstPort, pSrcHA, pSrcHA, pOpCode)

def sendARP(n, pDstAddr, pDstPort, pSrcHA, pSrcHA, pOpCode):
	ip = ImpactPacket.IP()
	arp = ImpactPacket.ARP()
    ip.set_ip_dst(pSrcAddr)
    ip.set_ip_src(pDstAddr)

    arp.set_ar_oppOpCode)
    arp.set_ar_hrd(1)
    arp.set_ar_spa((pSrcAddr))
    arp.set_ar_tpa((pDstAddr))
    arp.set_ar_sha((pDstHA))
    arp.set_ar_tha((pSrcHA))
    ip.contains(arp)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ARP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	while 1:
		s.sendto(ip.get_packet(), (dst, 0))
