#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")
#include <IPHlpApi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <winsock.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#define ETH_len 14
#define IP_len 20
#define TCP_len 20
#define TCP_payload ETH_len+IP_len+TCP_len

#define ETH_type 12
#define IP_prot 9

#define IP_chksum ETH_len+10
#define TCP_chksum ETH_len+IP_len+16

#define TCP_windowsize ETH_len+IP_len+14  // 2 byte (14-16)

int TYPE_IPv4(const u_char* packet) {
	/******************************
	if type is IPv4: return 1
	else:			 return 0
	*******************************/
	return ((packet[ETH_type] == 0x08) && (packet[ETH_type + 1] == 0x00));
}
int PROT_TCP(const u_char* packet) {
	/******************************
	if protocol is TCP: return 1
	else:				return 0
	*******************************/
	return (packet[ETH_len + IP_prot] == 0x06);
}

typedef struct tcp_hdr
{
	UINT16 SrcPort;
	UINT16 DstPort;
	UINT32 SeqNum;
	UINT32 AckNum;
	UINT8 res1 : 4;
	UINT8 doff : 4;
	UINT8 fin : 1;
	UINT8 syn : 1;
	UINT8 rst : 1;
	UINT8 psh : 1;
	UINT8 ack : 1;
	UINT8 urg : 1;
	UINT8 res2 : 2;
	UINT16 Window;
	UINT16 ChkSum;
	UINT16 UrgentPtr;

}TCP_HDR;

typedef struct ether_hdr
{
	UINT8  ether_dhost[6];        /* destination eth addr */
	UINT8  ether_shost[6];        /* source ether addr    */
	UINT16 ether_type;
}Ether_HDR;

typedef struct _Pseudohdr {
	UINT32   saddr;
	UINT32   daddr;
	UINT8		useless;
	UINT8		protocol;
	UINT16   tcplength;
}Pseudohdr;

typedef struct ip_hdr
{
	UINT8  ihl : 4;
	UINT8  ip_version : 4;
	UINT8  ip_tos;          /* IP type of service */
	UINT16 ip_totallength;  /* Total length */
	UINT16 ip_id;           /* Unique identifier */
	UINT16 ip_offset;       /* Fragment offset field */
	UINT8  ip_ttl;          /* Time to live */
	UINT8  ip_protocol;     /* Protocol */
	UINT16 ip_checksum;     /* IP checksum */
	UINT32   ip_srcaddr;      /* Source address */
	UINT32   ip_destaddr;
}IP_HDR;

UINT16 GetCheckSum(UINT16 *buffer, int size)
{
	unsigned long cksum = 0;

	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size) {
		cksum += *(unsigned char *)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}

int my_MAC(unsigned char* mac) {
	PIP_ADAPTER_INFO info, pinfo = NULL;
	DWORD size = sizeof(info);
	int success = 0;

	info = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (info == NULL) {
		printf("Error in allocating info\n");
	}

	if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW) {
		info = (IP_ADAPTER_INFO *)malloc(size);
		if (info == NULL) {
			printf("Error in allocating info\n");
		}
	}
	if (GetAdaptersInfo(info, &size) == NO_ERROR) {
		pinfo = info;
		if (pinfo) {
			success = 1;
		}
	}
	if (success) {
		memcpy(mac, pinfo->Address, 6);
	}

	free(info);
	return success;	// success 1 , fail 0
}

int my_IP(unsigned char* ipadd) {
	PIP_ADAPTER_INFO info, pinfo = NULL;
	DWORD size = sizeof(info);
	int success = 0;
	int chk, cnt;

	info = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (info == NULL) {
		printf("Error in allocating info\n");
	}

	if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW) {
		info = (IP_ADAPTER_INFO *)malloc(size);
		if (info == NULL) {
			printf("Error in allocating info\n");
		}
	}
	if (GetAdaptersInfo(info, &size) == NO_ERROR) {
		pinfo = info;
		if (pinfo) {
			success = 1;
		}
	}
	if (success) {
		chk = 0;
		cnt = 0;
		for (int i = 0; i<strlen(pinfo->IpAddressList.IpAddress.String); i++) {
			if (pinfo->IpAddressList.IpAddress.String[i] == '.') {
				ipadd[cnt] = chk;
				chk = 0;
				cnt++;
			}
			else {
				chk = chk * 10 + pinfo->IpAddressList.IpAddress.String[i] - 0x30;
			}
		}
		ipadd[cnt] = chk;
	}

	free(info);
	return success;	// success 1 , fail 0
}

int gateway_IP(unsigned char* gip) {
	PIP_ADAPTER_INFO info, pinfo = NULL;
	DWORD size = sizeof(info);
	int success = 0;
	int chk, cnt;

	info = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (info == NULL) {
		printf("Error in allocating info\n");
	}

	if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW) {
		info = (IP_ADAPTER_INFO *)malloc(size);
		if (info == NULL) {
			printf("Error in allocating info\n");
		}
	}
	if (GetAdaptersInfo(info, &size) == NO_ERROR) {
		pinfo = info;
		if (pinfo) {
			success = 1;
		}
	}
	if (success) {
		cnt = 0;
		chk = 0;
		for (int i = 0; i<strlen(pinfo->GatewayList.IpAddress.String); i++) {
			if (pinfo->GatewayList.IpAddress.String[i] == '.') {
				gip[cnt] = chk;
				chk = 0;
				cnt++;
			}
			else {
				chk = chk * 10 + pinfo->GatewayList.IpAddress.String[i] - 0x30;
			}
		}
		gip[cnt] = chk;
	}

	free(info);
	return success;	// success 1 , fail 0
}

int get_MAC(pcap_t* adhandle, u_char* gip, u_char* gmac) {
	int res, i;
	struct pcap_pkthdr *header;
	const u_char* pkt_data;
	u_char req_data[42];

	make_request(req_data, gip);

	if (pcap_sendpacket(adhandle, req_data, 42) != 0) {
		printf("Error : Sending request packet!\n");
	}

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* Timeout elapsed */
			continue;

		// type check
		if (ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0806) {
			// it's not ARP
			continue;
		}
		else { // It's ARP !
			if (ntohs(*((unsigned short*)(&pkt_data[20]))) == 0x0002) {
				if (((unsigned int*)(&pkt_data[28]))[0] == ((unsigned int*)(&req_data[38]))[0]) {
					for (i = 0; i<6; i++) {
						gmac[i] = pkt_data[6 + i];
					}
					break;
				}
			}
		}
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 1;
}

// copied from my arp_poison
int make_request(u_char* pdata, u_char* tip) {
	int i;
	// broadcast
	for (i = 0; i<6; i++)
		pdata[i] = 0xFF;
	if (my_MAC(&pdata[6]) == 0) {
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	pdata[12] = 0x08;
	pdata[13] = 0x06;
	pdata[14] = 0x00;
	pdata[15] = 0x01;
	pdata[16] = 0x08;
	pdata[17] = 0x00;
	pdata[18] = 0x06;
	pdata[19] = 0x04;
	pdata[20] = 0x00;
	pdata[21] = 0x01; // request

	if (my_MAC(&pdata[22]) == 0) {
		printf("Error : Writing my MAC! \n");
		return 0;
	}
	if (my_IP(&pdata[28]) == 0) {
		printf("Error : Writing my IP! \n");
		return 0;
	}
	for (i = 0; i<6; i++)
		pdata[32 + i] = 0x00;
	for (i = 0; i<4; i++)
		pdata[38 + i] = tip[i];

	return 1;

}



int calc_checksum_IP(u_char* packet) {
	unsigned short *c_packet = (unsigned short*)packet;
	unsigned checksum = 0;
	unsigned short finalchk;
	int i = 0;

	packet[IP_chksum] = 0x00;
	packet[IP_chksum + 1] = 0x00;

	for (i = 0; i < 10; i++) {
		checksum += c_packet[ETH_len / 2 + i];
	}
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	finalchk = (~checksum & 0xffff);

	packet[IP_chksum] = ((u_char*)&finalchk)[0];
	packet[IP_chksum + 1] = ((u_char*)&finalchk)[1];

	return 1;
}

int calc_checksum_TCP(u_char* packet, unsigned int len) {
	unsigned short *c_packet = (unsigned short*)packet;
	unsigned checksum = 0;
	unsigned short finalchk;
	int i = 0;

	packet[TCP_chksum] = 0x00;
	packet[TCP_chksum + 1] = 0x00;

	for (i = 0; i < (len - ETH_len - IP_len)/2; i++) {
		checksum += c_packet[(ETH_len + IP_len) / 2 + i];
	}
	for (i = 0; i < 4; i++) {
		checksum += c_packet[(ETH_len + 12) / 2 + i];
	}
	checksum += htons(0x0006);
	checksum += htons(len - ETH_len - IP_len);

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	finalchk = (~checksum & 0xffff);
	packet[TCP_chksum] = ((u_char*)&finalchk)[0];
	packet[TCP_chksum + 1] = ((u_char*)&finalchk)[1];

	return 1;
}


int bg_request(u_char* pdata, u_char* tip, u_char* gatewayMAC, int port){
	int i;

	// ethernet header
	memcpy(pdata, gatewayMAC, 6);
	my_MAC(&pdata[6]);
	pdata[12] = 0x08;
	pdata[13] = 0x00;

	// ip header
	pdata[14] = 0x45;
	pdata[15] = 0x00;
	pdata[16] = 0x00;
	pdata[17] = 0x34;
	pdata[18] = 0x16;
	pdata[19] = 0x26;
	pdata[20] = 0x40;
	pdata[21] = 0x00;
	pdata[22] = 0x80;
	pdata[23] = 0x06;
	// 24, 25 chksum
	my_IP(&pdata[26]);
	for (i = 0; i < 4; i++) {
		pdata[30 + i] = tip[i];
	}
	calc_checksum_IP(pdata);

	srand(time(0));

	*(unsigned short*)(&pdata[34]) = htons(rand() % 65536);
	*(unsigned short*)(&pdata[36]) = htons(port);
	*(unsigned long*)(&pdata[38]) = htonl(rand() % 200000);
	*(unsigned long*)(&pdata[42]) = 0x0000; // ACK 0
	pdata[46] = 0x80;
	pdata[47] = 0x02;
	*(unsigned short*)(&pdata[48]) = htons(0x2000);
	*(unsigned short*)(&pdata[50]) = 0x00; // checksum
	*(unsigned short*)(&pdata[52]) = 0x00; 
	pdata[54] = 0x02;
	pdata[55] = 0x04;
	*(unsigned short*)(&pdata[56]) = htons(0x05b4);
	pdata[58] = 0x01;
	pdata[59] = 0x03;
	pdata[60] = 0x03;
	pdata[61] = 0x08;
	pdata[62] = 0x01;
	pdata[63] = 0x01;
	pdata[64] = 0x04;
	pdata[65] = 0x02;
	calc_checksum_TCP(pdata,66);
	return 1;
}

int bg_handshake(u_char* pdata, u_char* req_data, const u_char* recv_data, int port) {
	memcpy(pdata, req_data, 54);
	pdata[0x11] = 0x28;
	pdata[0x13]++;
	calc_checksum_IP(pdata);
	*(unsigned long*)(&pdata[38]) = *(unsigned long*)(&recv_data[42]);
	*(unsigned long*)(&pdata[42]) = htonl(ntohl(*(unsigned long*)(&recv_data[38])) + 1);
	pdata[46] = 0x50;
	pdata[47] = 0x10;
	*(unsigned short*)(&pdata[48]) = htons(0x1000);
	*(unsigned long*)(&pdata[50]) = htonl(0xa0230000);
	calc_checksum_TCP(pdata, 54);
	return 1;
}

int telnet_bg(pcap_t* adhandle, u_char* srcIP, u_char* srcMac, u_char* dstIP, u_char* dstMac, int port) {
	struct pcap_pkthdr *header;
	const u_char* pkt_data;
	
	int res, i;
	u_char req_data[100];
	u_char send_data[100];

	u_char* req_http = "GET * HTTP/1.1\x0d\x0a\x0d\x0a";

	bg_request(req_data, dstIP, dstMac, port);
	pcap_sendpacket(adhandle, req_data, 66);
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* Timeout elapsed */
			continue;

		// type check
		if (!TYPE_IPv4(pkt_data))
			continue;
		if (!PROT_TCP(pkt_data))
			continue;
		if (((unsigned int*)(&pkt_data[26]))[0] == ((unsigned int*)(dstIP))[0]) {
			if (((unsigned int*)(&pkt_data[30]))[0] == ((unsigned int*)(srcIP))[0]) {
				if (*(unsigned short*)(&pkt_data[0x22]) == htons(port)) {
					bg_handshake(send_data, req_data, pkt_data, port);
					break;
				}
			}
		}
		continue;
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	pcap_sendpacket(adhandle, send_data, 54);
	
	send_data[0x11] = 0x3a;
	*(unsigned short*)(&send_data[0x12]) = htons(ntohs(*(unsigned short*)(&send_data[0x12])) + 1);
	calc_checksum_IP(send_data);
	for (i = 0; i < 18; i++) {
		send_data[54 + i] = req_http[i];
	}
	calc_checksum_TCP(send_data, 72);

	pcap_sendpacket(adhandle, send_data, 72);

	
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* Timeout elapsed */
			continue;

		// type check
		if (!TYPE_IPv4(pkt_data))
			continue;
		if (!PROT_TCP(pkt_data))
			continue;
		if (((unsigned int*)(&pkt_data[26]))[0] == ((unsigned int*)(dstIP))[0]) {
			if (((unsigned int*)(&pkt_data[30]))[0] == ((unsigned int*)(srcIP))[0]) {
				if ((*(unsigned short*)(&pkt_data[0x22]) == htons(port)) && (*(unsigned short*)(&pkt_data[0x24]) == *(unsigned short*)(&send_data[0x22]))) {
					if(strstr(&pkt_data[54], "HTTP")){
						for (i = 0x36; i < header->caplen; i++) {
							printf("%c", pkt_data[i]);
						}
						printf("\n");
						break;
					}
				}
				for (i = 0x36; i < header->caplen; i++) {
					printf("%c", pkt_data[i]);
				}
				printf("\n");
			}
		}
		continue;
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	send_data[47] += 0x4;
	calc_checksum_TCP(send_data, 72);
	pcap_sendpacket(adhandle, send_data, 72);

}

int main(void) {
	int i, inum, res;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char* pkt_data;

	u_char req_data[66];
	u_char myIP[4];
	u_char myMAC[6];
	u_char gatewayIP[4];
	u_char gatewayMAC[6];

	Ether_HDR* ethHdr;
	TCP_HDR* tcpHdr = NULL;
	IP_HDR* ipHdr = NULL;
	Pseudohdr* pseudoHdr;
	unsigned char packet[60];
	UINT16 port = 80;
	u_char dstMac[6] = { 0, };
	u_char srcMac[6] = { 0, };
	u_char dstIP[4] = {24, 143, 251, 118};//{ 115, 68, 74, 145 };//
	u_char srcIP[4] = { 0, };
	u_char send_data[66];


	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	inum = 1;	// first device select

				/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture. 
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	gateway_IP(gatewayIP);
	my_IP(srcIP);
	my_MAC(srcMac);
	get_MAC(adhandle, gatewayIP, dstMac);
	

	ethHdr = (Ether_HDR*)packet;
	ZeroMemory(ethHdr, sizeof(Ether_HDR));

	ipHdr = (IP_HDR*)(packet + sizeof(Ether_HDR));
	ZeroMemory(ipHdr, sizeof(IP_HDR));

	tcpHdr = (TCP_HDR*)(packet + sizeof(Ether_HDR) + sizeof(IP_HDR));
	ZeroMemory(tcpHdr, sizeof(TCP_HDR));

	pseudoHdr = (Pseudohdr *)((char*)tcpHdr - sizeof(Pseudohdr));

	memcpy(ethHdr->ether_dhost, dstMac, 6);
	memcpy(ethHdr->ether_shost, srcMac, 6);
	ethHdr->ether_type = htons(0x0800);

	pseudoHdr->saddr = *(UINT32*)srcIP;
	pseudoHdr->daddr = *(UINT32*)dstIP;
	pseudoHdr->protocol = IPPROTO_TCP;
	pseudoHdr->tcplength = htons(sizeof(TCP_HDR));

	srand(time(0));
	tcpHdr->SrcPort = rand() % 65536;//htons(10000);
	tcpHdr->DstPort = htons(port);
	tcpHdr->SeqNum = rand()%200000;//htonl(100);
	tcpHdr->AckNum = 0;
	tcpHdr->doff = 0x05;
	tcpHdr->syn = 0x01;
	//tcpHdr->fin = 0x01;
	/*tcpHdr->rst = 0x01;
	tcpHdr->psh = 0x01;
	tcpHdr->ack = 0x01;
	tcpHdr->urg = 0x01;
	tcpHdr->res2 = 0x03;*/
	tcpHdr->Window = htons(512);
	tcpHdr->ChkSum = GetCheckSum((UINT16*)pseudoHdr, sizeof(Pseudohdr) + sizeof(TCP_HDR));

	ipHdr->ip_version = 4;
	ipHdr->ihl = 5;
	ipHdr->ip_protocol = IPPROTO_TCP;
	ipHdr->ip_totallength = htons(sizeof(IP_HDR) + sizeof(TCP_HDR));
	ipHdr->ip_id = htons(rand() % 0xffff);
	ipHdr->ip_offset = 0;
	ipHdr->ip_ttl = 255;
	ipHdr->ip_srcaddr = *(UINT32*)srcIP;
	ipHdr->ip_destaddr = *(UINT32*)dstIP;
	ipHdr->ip_checksum = 0;
	ipHdr->ip_checksum = GetCheckSum((UINT16*)ipHdr, sizeof(IP_HDR));

	int sendLen = sizeof(Ether_HDR) + sizeof(IP_HDR) + sizeof(TCP_HDR);
/*
	if (pcap_sendpacket(adhandle, (u_char*)packet, sendLen) != 0)
	{
		fprintf(stderr, "\n1Error sending the packet: %s\n", pcap_geterr(adhandle));
	}
	
	
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			// Timeout elapsed
			continue;

		// type check
		if (!TYPE_IPv4(pkt_data))
			continue;
		if (!PROT_TCP(pkt_data))
			continue;
		if (((unsigned int*)(&pkt_data[26]))[0] == ((unsigned int*)(dstIP))[0]) {
			if (((unsigned int*)(&pkt_data[30]))[0] == ((unsigned int*)(srcIP))[0]) {
				printf("TTL: %d\n", (unsigned short*)(&pkt_data[ETH_len + 8])[0]);
				printf("Seq: %d\n", (unsigned int*)(&pkt_data[ETH_len + IP_len + 4])[0]);
				printf("window: %d\n", (unsigned short*)(&pkt_data[ETH_len + IP_len + 14])[0]);
				break;
			}
		}
		continue;
	}
	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
*/
	printf("\n\n");

	telnet_bg(adhandle, srcIP, srcMac, dstIP, dstMac, 8888);
	
	pcap_close(adhandle);

	/*
	printf("My IP  : %d.%d.%d.%d\n", myIP[0], myIP[1], myIP[2], myIP[3]);
	printf("My MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", myMAC[0], myMAC[1], myMAC[2], myMAC[3], myMAC[4], myMAC[5]);
	printf("Gateway IP  : %d.%d.%d.%d\n", gatewayIP[0], gatewayIP[1], gatewayIP[2], gatewayIP[3]);
	printf("Gateway MAC : %02x-%02x-%02x-%02x-%02x-%02x\n", gatewayMAC[0], gatewayMAC[1], gatewayMAC[2], gatewayMAC[3], gatewayMAC[4], gatewayMAC[5]);
	*/

	return 0;
}