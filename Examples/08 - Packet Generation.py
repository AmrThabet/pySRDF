from pySRDF import *

tcp = PacketGenerator(GENERATE_TCP)                              #you have UDP,ARP and ICMP

tcp.SetMACAddress("50:50:50:50:50:50","50:50:50:50:50:50")       #src, dest
tcp.SetIPAddress("192.168.1.100","192.168.1.1")                  #source, dest
tcp.SetPorts(1000,80)                                            #src, dest
tcp.CustomizeTCP("AAAA",4,TCP_ACK + TCP_PSH)                     #tcpdata, tcpdata_size, tcpflags
print tcp.DumpPacket()

#CustomizeUDP("AAAA",4)
#CustomizeICMP(icmp_type,icmp_code,icmp_data,icmp_data_size)