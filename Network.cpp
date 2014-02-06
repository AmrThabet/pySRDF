// Network.cpp : includes all packetyzer wrapper classes
//

#include "stdafx.h"
#include "pySRDF.h"

PcapFile::PcapFile(char* Filename)
{

	Pcap = new cPcapFile(Filename,CPCAP_OPTIONS_MALFORM_CHECK);
	if (Pcap->IsFound() == FALSE)
	{
		set_err("filename not found or access denied");
		return;
	}
	nPackets = Pcap->nPackets;
	traffic = new Traffic(Pcap->Traffic);

}

PcapFile::~PcapFile()
{
	delete traffic;
	delete Pcap;
};

//------------------------------------------------------------------------------

Traffic::Traffic(cTraffic* t)
{
	traffic = t;
	Sessions.init(sizeof(Session));
	for (int i = 0;i < t->nConnections;i++)
	{
		Session* session = new Session(t->Connections[i]);
		Sessions.additem(session);
	}
};

//------------------------------------------------------------------------------
#define ADD_DWORD_ARG(vName,sType)			\
	c.Name = #vName;						\
	c.nValue = ((sType*)conn)->##vName##;	\
	c.Type = PARAMTYPE_DWORD;				\
	__params__.additem(&c);

#define ADD_MAC_ARG(vName,sType)				\
	c.Name = #vName;							\
	memcpy(&c.MAC,&((sType*)conn)->##vName##,6);\
	c.Type = PARAMTYPE_MAC;						\
	__params__.additem(&c);


Session::Session(cConnection* connection)
{
	__params__.init(sizeof(CONN_PARAM));
	
	conn = connection;
	//Adding Basic Info
	CONN_PARAM c = {0};
	ADD_DWORD_ARG(TransportType,cConnection)
	ADD_DWORD_ARG(NetworkType,cConnection)
	ADD_DWORD_ARG(AddressingType,cConnection)
	ADD_DWORD_ARG(ApplicationType,cConnection)
	ADD_DWORD_ARG(Protocol,cConnection)
	ADD_DWORD_ARG(nPackets,cConnection)
	
	//Adding MAC Addresses
	ADD_MAC_ARG(ClientMAC,cConnection)
	ADD_MAC_ARG(ServerMAC,cConnection)

	//IPs
	if (conn->AddressingType == CONN_ADDRESSING_IP)
	{

		ADD_DWORD_ARG(ClientIP,cConStream)
		ADD_DWORD_ARG(ServerIP,cConStream)
	}
	else if (conn->AddressingType == CONN_ADDRESSING_ARP)
	{
		ADD_MAC_ARG(RequesterMAC,cARPStream)
		ADD_MAC_ARG(RequestedMAC,cARPStream)
		ADD_MAC_ARG(ReplierMAC,cARPStream)
		ADD_DWORD_ARG(RequesterIP,cARPStream)
		ADD_DWORD_ARG(RequestedMACIP,cARPStream)
		ADD_DWORD_ARG(GotReply,cARPStream)
	}

	//Transport Layer
	if (conn->TransportType == CONN_TRANSPORT_TCP)
	{
		ADD_DWORD_ARG(ClientPort,cTCPStream)
		ADD_DWORD_ARG(ServerPort,cTCPStream)
	}
	else if (conn->TransportType == CONN_TRANSPORT_UDP)
	{
		ADD_DWORD_ARG(ClientPort,cUDPStream)
		ADD_DWORD_ARG(ServerPort,cUDPStream)
	}
	else if (conn->TransportType == CONN_TRANSPORT_ICMP)
	{
		ADD_DWORD_ARG(PingRequester,cICMPStream)
		ADD_DWORD_ARG(PingReceiver,cICMPStream)
	}

	//Application Layer
	if (conn->ApplicationType == CONN_APPLICATION_DNS)
	{
		cDNSStream* DNSObj = (cDNSStream*)conn;
		DNS = new DNS_STRUCT();
		DNS->DomainIsFound = DNSObj->DomainIsFound;
		DNS->RequestedDomain = (char*)DNSObj->RequestedDomain;
		DNS->ResolvedIPs.init(sizeof(IP_INT));
		for (int i = 0;i < DNSObj->nResolvedIPs;i++)
		{
			DNS->ResolvedIPs.additem((IP_INT*)&DNSObj->ResolvedIPs[i]);
		}
	}
	else if (conn->ApplicationType == CONN_APPLICATION_HTTP)
	{
		cHTTPStream* HTTPObj = (cHTTPStream*)conn;
		HTTP = new HTTP_STRUCT();
		HTTP->Referer = (HTTPObj->Referer == NULL)? "" : HTTPObj->Referer->GetChar();
		HTTP->ServerType = (HTTPObj->ServerType == NULL)? "" : HTTPObj->ServerType->GetChar();
		HTTP->UserAgent = (HTTPObj->UserAgent == NULL)? "" : HTTPObj->UserAgent->GetChar();
		HTTP->nFiles = HTTPObj->nFiles;
		HTTP->Files = HTTPObj->Files;
		HTTP->Cookies.init(sizeof(STRING_STRUCT));
		for (int i = 0;i < HTTPObj->nCookies; i++)
		{
			STRING_STRUCT c;
			c.Value = HTTPObj->Cookies[i]->GetChar();
			HTTP->Cookies.additem(&c);
		}
		HTTP->Request.init(sizeof(REQUESTS));
		//cout << "nFiles: " << HTTPObj->nFiles << "\n";
		//cout << "Requests: " << HTTPObj->nRequests << "\n";
		for (int i = 0;i < HTTPObj->nRequests; i++)
		{
			REQUESTS* req = new REQUESTS();
			req->Address = (HTTPObj->Requests[i].Address == NULL)? "" : HTTPObj->Requests[i].Address->GetChar(); 
			req->ReplyNumber = HTTPObj->Requests[i].ReplyNumber;
			req->RequestType = (char*)HTTPObj->Requests[i].RequestType;
			req->Arguments.init(sizeof(HASH_STRUCT));
			for (int l = 0;l < HTTPObj->Requests[i].Arguments->GetNumberOfItems(); l++)
			{
				HASH_STRUCT* hash = new HASH_STRUCT();
				hash->Key = (char*)malloc( HTTPObj->Requests[i].Arguments->GetKey(l).GetLength()+1);
				memset(hash->Key,0,HTTPObj->Requests[i].Arguments->GetKey(l).GetLength()+1);
				memcpy(hash->Key, HTTPObj->Requests[i].Arguments->GetKey(l).GetChar(), HTTPObj->Requests[i].Arguments->GetKey(l).GetLength());
				
				hash->Value = (char*)malloc( HTTPObj->Requests[i].Arguments->GetValue(l).GetLength()+1);
				memset(hash->Value,0,HTTPObj->Requests[i].Arguments->GetValue(l).GetLength()+1);
				memcpy(hash->Value, HTTPObj->Requests[i].Arguments->GetValue(l).GetChar(), HTTPObj->Requests[i].Arguments->GetValue(l).GetLength());

				req->Arguments.additem(hash);
			}
			HTTP->Request.additem(req);
		}
	}
}


Session::~Session()
{
	__params__.clear();
};

char* IPToString(DWORD IP)
{
	char* buff = (char*)malloc(4*4);
	memset(buff,0,4*4);
	unsigned char* cIP = (unsigned char*)&IP;
	sprintf(buff,"%d.%d.%d.%d",cIP[0],cIP[1],cIP[2],cIP[3]);
	return buff;
}

char* MACToString(char MAC[6])
{
	char* buff = (char*)malloc(6*4);
	memset(buff,0,6*4);
	unsigned char* cMAC = (unsigned char*)&MAC;
	sprintf(buff,"%02x:%02x:%02x:%02x:%02x",cMAC[0],cMAC[1],cMAC[2],cMAC[3],cMAC[4],cMAC[5]);
	return buff;
};

void Session::ReadPacket(DWORD index,char **s, int *slen)
{
	if (index >= conn->nPackets)
	{
		set_err("index out of range");
		*s = "";
		*slen = 0;
	}
	else
	{
		*s = (char*)malloc(conn->Packets[index]->Size);
		memcpy(*s,(const void*)conn->Packets[index]->BaseAddress,conn->Packets[index]->Size);
		*slen = conn->Packets[index]->Size;
	}
}

//========================================================================================
//Packet Generator

PacketGenerator::PacketGenerator(DWORD type)
{
	pGen = new cPacketGen(type);
}

bool PacketGenerator::SetMACAddress(char* src_mac, char* dest_mac)
{
	return (BOOL)pGen->SetMACAddress(src_mac,dest_mac);
}

bool PacketGenerator::SetIPAddress(char* src_ip, char* dest_ip)
{
	return pGen->SetIPAddress(src_ip, dest_ip);
}

bool PacketGenerator::SetPorts(short src_port, short dest_port)
{
	return pGen->SetPorts(src_port,dest_port);
}


bool PacketGenerator::CustomizeTCP(char* tcp_data, DWORD tcp_data_size, short tcp_flags)
{
	return pGen->CustomizeTCP((UCHAR*)"",0,(UCHAR*)tcp_data,tcp_data_size,tcp_flags);
}

bool PacketGenerator::CustomizeUDP(char* udp_data, DWORD udp_data_size)
{
	return pGen->CustomizeUDP((UCHAR*)udp_data,udp_data_size);
}

bool PacketGenerator::CustomizeICMP(char icmp_type, char icmp_code, char* icmp_data, DWORD icmp_data_size)
{
	return pGen->CustomizeICMP(icmp_type,icmp_code,(UCHAR*)icmp_data,icmp_data_size);
}

void PacketGenerator::DumpPacket(char **s, int *slen)
{
	*s = (char*)malloc(pGen->Packet->PacketSize);
	memcpy(*s,(const void*)pGen->Packet->BaseAddress,pGen->Packet->PacketSize);
	*slen = pGen->Packet->PacketSize;
}