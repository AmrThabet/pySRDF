from pySRDF import *

pcap = PcapFile("http.pcap")

traffic = pcap.traffic

conn = traffic.Sessions

i = 0
for session in conn:
    print "Session: %d" % i
    i += 1                                                                      # to print index only
    print "Number of Packets: %d" % session.nPackets
    
    print "Client MAC: %s Server MAC: %s" % (MACToString(session.ClientMAC), MACToString(session.ServerMAC))
    
    #Addressing Layer
    if session.AddressingType == CONN_ADDRESSING_IP:
        print "IP: from: %s to %s" % (IPToString(session.ClientIP), IPToString(session.ServerIP))

    elif session.AddressingType == CONN_ADDRESSING_ARP:
        print "ARP"
        print "Requester MAC: %s" % MACToString(session.RequesterMAC)
        print "Requested MAC: %s" % MACToString(session.RequestedMAC)
        print "Replier MAC: %s" % MACToString(session.ReplierMAC)
        print "Requester IP: %s" % PToString(session.RequesterIP)
        if session.GotReply:
            print "RequestedMAC IP: %s" % PToString(session.RequestedMACIP)
    
    #Transport Layer
    if session.TransportType == CONN_TRANSPORT_TCP:
        print "TCP: Client Port: %d to ServerPort: %d" % (session.ClientPort, session.ServerPort)
        
    elif session.TransportType == CONN_TRANSPORT_UDP:
         print "UDP: Client Port: %d to ServerPort: %d" % (session.ClientPort, session.ServerPort)
         
    elif session.TransportType == CONN_TRANSPORT_ICMP:
        print "ICMP: From: %s To %s" % (IPToString(session.PingRequester), IPToString(session.PingReceiver))
    
    #Application Layer
    if session.ApplicationType == CONN_APPLICATION_DNS:
        print "DNS"
        print "Requested Domain: %s" % session.DNS.RequestedDomain
        
        if session.DNS.DomainIsFound:
            for IP in session.DNS.ResolvedIPs:
                print IPToString(IP.IP)
    
    if session.ApplicationType == CONN_APPLICATION_HTTP:
        print "HTTP"
        print "Referer: %s" % session.HTTP.Referer
        print "UserAgent: %s" % session.HTTP.UserAgent
        print "ServerType: %s" % session.HTTP.ServerType
        print "Number of Downloaded Files: %d" % session.HTTP.nFiles
        
        for cookie in session.HTTP.Cookies:
            print "Cookie: %s" % cookie.Value
        
        for req in session.HTTP.Request:
            print "RequestType: %s" % req.RequestType
            print "Address: %s" % req.Address
            print "ReplyNumber: %d" % req.ReplyNumber
            
            for arg in req.Arguments:
                print "%s: %s" % (arg.Key, arg.Value)

    print "-----------------------------\n"
